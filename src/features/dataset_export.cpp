#include "ciphertracedroid/features/dataset_export.hpp"

#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/features/feature_extractor.hpp"
#include "ciphertracedroid/traffic/windowing.hpp"
#include "ciphertracedroid/util/sha256.hpp"
#include "ciphertracedroid/util/logging.hpp"

#include <cmath>
#include <fstream>
#include <stdexcept>
#include <unordered_map>

namespace ciphertracedroid::features {

std::size_t export_features(const std::filesystem::path& manifest_path,
                            const std::filesystem::path& output_path,
                            const FeatureExportOptions& options)
{
    if (!std::isfinite(options.window_seconds) || options.window_seconds <= 0.0) throw std::invalid_argument("window duration must be finite and positive");
    const auto rows = experiments::read_session_manifest(manifest_path);
    experiments::validate_session_manifest_integrity(rows);
    util::debug_log("features", "manifest validated; beginning export");
    const auto temporary = output_path.string() + ".tmp";
    std::ofstream output(temporary, std::ios::trunc);
    if (!output) throw std::runtime_error("could not create feature output: " + temporary);
    output << csv_header() << '\n';
    std::unordered_map<std::string, capture::CaptureData> captures;
    std::size_t rows_written = 0;
    for (const auto& row : rows) {
        if (!row.include) continue;
        const auto key = row.capture_file.string();
        if (!row.capture_sha256.empty() && util::sha256_file(row.capture_file) != row.capture_sha256) {
            throw std::runtime_error("capture SHA-256 does not match manifest for session " + row.session_id);
        }
        util::debug_log("features", "capture provenance verified");
        auto [capture_it, inserted] = captures.try_emplace(key);
        if (inserted) capture_it->second = capture::read_pcap(key, options.device_ip);
        auto packets = capture_it->second.packets;
        const double origin = capture_it->second.summary.first_timestamp_seconds;
        for (auto& packet : packets) packet.timestamp_seconds -= origin;
        const std::vector<traffic::StateInterval> intervals{{experiments::to_string(row.state), row.start_offset_seconds, row.end_offset_seconds, true}};
        for (const auto& window : traffic::make_windows(packets, row.session_id, intervals, options.window_seconds)) {
            if (window.packets.empty()) continue;
            SampleMetadata metadata;
            metadata.app_id = row.app_id;
            metadata.run_id = row.run_id;
            metadata.capture_source = row.capture_source;
            metadata.capture_reference = row.capture_sha256;
            metadata.synthetic_test_only = row.synthetic_test_only;
            metadata.pilot = row.pilot;
            output << to_csv_row(extract_features(window, std::move(metadata))) << '\n';
            ++rows_written;
        }
    }
    output.close();
    if (!output) throw std::runtime_error("could not write feature output: " + temporary);
    std::filesystem::rename(temporary, output_path);
    util::debug_log("features", "feature CSV written successfully");
    return rows_written;
}

}  // namespace ciphertracedroid::features
