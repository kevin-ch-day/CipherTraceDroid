#include "ciphertracedroid/analysis/condition_analysis.hpp"

#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/traffic/windowing.hpp"
#include "ciphertracedroid/util/sha256.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::analysis {
namespace {

double fraction(double numerator, double denominator)
{
    return denominator == 0.0 ? 0.0 : numerator / denominator;
}

std::string csv_escape(const std::string& value)
{
    if (value.find_first_of(",\"\n") == std::string::npos) return value;
    std::string result{"\""};
    for (const char character : value) result += character == '\"' ? "\"\"" : std::string(1, character);
    return result + '\"';
}

void optional_csv(std::ostream& output, const std::optional<double>& value)
{
    if (value) output << *value;
}

std::uint64_t total_bytes(const std::vector<traffic::PacketRecord>& packets)
{
    return std::accumulate(packets.begin(), packets.end(), std::uint64_t{},
                           [](std::uint64_t sum, const auto& packet) {
                               return sum + packet.ip_packet_length;
                           });
}

std::vector<traffic::PacketRecord> packets_in_interval(
    const std::vector<traffic::PacketRecord>& packets, double start, double end)
{
    std::vector<traffic::PacketRecord> selected;
    std::copy_if(packets.begin(), packets.end(), std::back_inserter(selected),
                 [&](const auto& packet) {
                     return packet.timestamp_seconds >= start && packet.timestamp_seconds < end;
                 });
    return selected;
}

void write_file(const std::filesystem::path& path, const std::string& contents)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("could not create analysis artifact: " + path.string());
    output << contents;
    if (!output) throw std::runtime_error("could not write analysis artifact: " + path.string());
}

std::string status_name(WindowObservationStatus status)
{
    return status == WindowObservationStatus::observed_nonempty ? "observed_nonempty"
                                                                : "observed_empty";
}

}  // namespace

std::vector<double> ConditionProfilePredictors::required_values() const
{
    std::vector<double> values{condition_duration_seconds, total_ip_packets, total_ip_bytes,
                               packets_per_second, ip_bytes_per_second,
                               scheduled_window_count, active_window_count,
                               active_window_fraction, longest_quiet_duration_seconds};
    if (time_to_first_packet_seconds) values.push_back(*time_to_first_packet_seconds);
    if (aggregate_packet_features) {
        const auto traffic_values = aggregate_packet_features->values();
        values.insert(values.end(), traffic_values.begin(), traffic_values.end());
    }
    return values;
}

std::vector<std::string> condition_profile_predictor_names()
{
    return {"condition_duration_seconds", "total_ip_packets", "total_ip_bytes",
            "packets_per_second", "ip_bytes_per_second", "scheduled_window_count",
            "active_window_count", "active_window_fraction",
            "longest_quiet_duration_seconds", "time_to_first_packet_seconds",
            "aggregate_packet_statistics"};
}

ConditionAnalysis analyze_condition(
    const experiments::SessionManifestRow& row,
    const std::vector<traffic::PacketRecord>& capture_relative_packets,
    double window_seconds)
{
    if (!std::isfinite(window_seconds) || window_seconds <= 0.0) {
        throw std::invalid_argument("analysis window duration must be finite and positive");
    }
    const double duration = row.end_offset_seconds - row.start_offset_seconds;
    const auto selected = packets_in_interval(capture_relative_packets,
                                              row.start_offset_seconds,
                                              row.end_offset_seconds);
    const std::vector<traffic::StateInterval> intervals{{experiments::to_string(row.state),
        row.start_offset_seconds, row.end_offset_seconds, true}};
    const auto traffic_windows = traffic::make_windows(capture_relative_packets, row.session_id,
                                                       intervals, window_seconds);
    ConditionAnalysis result;
    std::size_t current_empty = 0;
    for (const auto& window : traffic_windows) {
        const auto bytes = total_bytes(window.packets);
        WindowObservation observation{.window_id = window.window_id,
                                      .session_id = row.session_id,
                                      .run_id = row.run_id,
                                      .app_id = row.app_id,
                                      .condition = experiments::to_string(row.state),
                                      .capture_source = row.capture_source,
                                      .start_seconds = window.start_time,
                                      .end_seconds = window.end_time,
                                      .status = window.packets.empty()
                                          ? WindowObservationStatus::observed_empty
                                          : WindowObservationStatus::observed_nonempty,
                                      .packet_count = window.packets.size(),
                                      .total_ip_bytes = bytes,
                                      .packets_per_second = window.packets.size() / window_seconds,
                                      .ip_bytes_per_second = bytes / window_seconds,
                                      .schema_v1_features = std::nullopt,
                                      .packet_timestamps = {}};
        for (const auto& packet : window.packets) observation.packet_timestamps.push_back(packet.timestamp_seconds);
        if (!window.packets.empty()) {
            features::SampleMetadata metadata;
            metadata.app_id = row.app_id;
            metadata.run_id = row.run_id;
            metadata.capture_source = row.capture_source;
            metadata.capture_reference = row.capture_sha256;
            metadata.synthetic_test_only = row.synthetic_test_only;
            metadata.pilot = row.pilot;
            observation.schema_v1_features = features::extract_features(window, std::move(metadata)).predictors;
            ++result.occupancy.nonempty_window_count;
            current_empty = 0;
        } else {
            ++result.occupancy.empty_window_count;
            ++current_empty;
            result.occupancy.longest_consecutive_empty_windows = std::max(
                result.occupancy.longest_consecutive_empty_windows, current_empty);
        }
        result.windows.push_back(std::move(observation));
    }
    result.occupancy.scheduled_window_count = result.windows.size();
    result.occupancy.active_window_fraction = fraction(result.occupancy.nonempty_window_count,
                                                       result.windows.size());
    result.occupancy.quiet_window_fraction = fraction(result.occupancy.empty_window_count,
                                                      result.windows.size());
    result.occupancy.longest_quiet_duration_seconds =
        result.occupancy.longest_consecutive_empty_windows * window_seconds;
    result.occupancy.discarded_tail_seconds = std::max(
        0.0, duration - result.windows.size() * window_seconds);
    if (!selected.empty()) {
        result.occupancy.time_to_first_packet_seconds =
            selected.front().timestamp_seconds - row.start_offset_seconds;
        result.occupancy.time_from_last_packet_to_interval_end_seconds =
            row.end_offset_seconds - selected.back().timestamp_seconds;
    }
    ConditionProfilePredictors predictors;
    predictors.condition_duration_seconds = duration;
    predictors.total_ip_packets = static_cast<double>(selected.size());
    predictors.total_ip_bytes = static_cast<double>(total_bytes(selected));
    predictors.packets_per_second = predictors.total_ip_packets / duration;
    predictors.ip_bytes_per_second = predictors.total_ip_bytes / duration;
    predictors.scheduled_window_count = static_cast<double>(result.windows.size());
    predictors.active_window_count = static_cast<double>(result.occupancy.nonempty_window_count);
    predictors.active_window_fraction = result.occupancy.active_window_fraction;
    predictors.longest_quiet_duration_seconds = result.occupancy.longest_quiet_duration_seconds;
    predictors.time_to_first_packet_seconds = result.occupancy.time_to_first_packet_seconds;
    if (!selected.empty()) {
        traffic::TrafficWindow entire{.window_id = row.session_id + "_condition",
                                      .session_id = row.session_id,
                                      .activity_state = experiments::to_string(row.state),
                                      .start_time = row.start_offset_seconds,
                                      .end_time = row.end_offset_seconds,
                                      .packets = selected};
        features::SampleMetadata metadata;
        metadata.app_id = row.app_id;
        metadata.run_id = row.run_id;
        predictors.aggregate_packet_features = features::extract_features(entire, metadata).predictors;
    }
    for (const double value : predictors.required_values()) {
        if (!std::isfinite(value)) throw std::runtime_error("condition profile contains non-finite value");
    }
    result.profile = {{kConditionProfileSchemaVersion, row.session_id, row.run_id, row.app_id,
                       experiments::to_string(row.state), row.capture_source}, std::move(predictors)};
    return result;
}

std::filesystem::path write_condition_analysis_bundle(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& output_directory,
    const std::string& device_ip,
    const std::vector<double>& sweep_durations)
{
    if (std::filesystem::exists(output_directory)) {
        throw std::runtime_error("analysis output already exists: " + output_directory.string());
    }
    const auto rows = experiments::read_session_manifest(manifest_path);
    experiments::validate_session_manifest_integrity(rows);
    std::filesystem::create_directories(output_directory);
    std::map<std::string, capture::CaptureData> captures;
    auto load_packets = [&](const experiments::SessionManifestRow& row) -> const std::vector<traffic::PacketRecord>& {
        const auto key = row.capture_file.string();
        if (util::sha256_file(row.capture_file) != row.capture_sha256) {
            throw std::runtime_error("capture hash mismatch for " + row.session_id);
        }
        auto [iterator, inserted] = captures.try_emplace(key);
        if (inserted) {
            iterator->second = capture::read_pcap(key, device_ip);
            const double origin = iterator->second.summary.first_timestamp_seconds;
            for (auto& packet : iterator->second.packets) packet.timestamp_seconds -= origin;
        }
        return iterator->second.packets;
    };

    std::ostringstream ledger;
    ledger << "window_id,session_id,run_id,app_id,condition,capture_source,start_s,end_s,duration_s,status,has_packets,packet_count,total_ip_bytes,packets_per_second,ip_bytes_per_second,schema_v1_features_available,ip_size_mean,outbound_packet_fraction,iat_mean,tcp_packet_fraction,udp_packet_fraction\n";
    std::ostringstream occupancy;
    occupancy << "session_id,run_id,app_id,condition,capture_source,window_seconds,scheduled_window_count,nonempty_window_count,empty_window_count,active_window_fraction,quiet_window_fraction,longest_consecutive_empty_windows,longest_quiet_duration_seconds,time_to_first_packet_seconds,time_from_last_packet_to_interval_end_seconds,discarded_tail_seconds\n";
    std::ostringstream profiles;
    profiles << "condition_profile_schema_version,session_id,run_id,app_id,condition,capture_source,condition_duration_seconds,total_ip_packets,total_ip_bytes,packets_per_second,ip_bytes_per_second,scheduled_window_count,active_window_count,active_window_fraction,longest_quiet_duration_seconds,time_to_first_packet_seconds,packet_statistics_available,ip_size_mean,ip_size_stddev,ip_size_min,ip_size_max,ip_size_median,ip_size_q1,ip_size_q3,outbound_packet_count,inbound_packet_count,unknown_packet_count,outbound_packet_fraction,inbound_packet_fraction,unknown_packet_fraction,iat_mean,iat_stddev,iat_median,iat_min,iat_max,tcp_packet_fraction,udp_packet_fraction,other_transport_fraction\n";
    std::ostringstream sweep;
    sweep << "session_id,run_id,app_id,condition,capture_source,window_seconds,scheduled_complete_windows,nonempty_windows,empty_windows,occupancy_fraction,discarded_tail_seconds,longest_quiet_seconds\n";
    ledger << std::setprecision(17); occupancy << std::setprecision(17);
    profiles << std::setprecision(17); sweep << std::setprecision(17);

    for (const auto& row : rows) {
        if (!row.include) continue;
        const auto& packets = load_packets(row);
        const auto primary = analyze_condition(row, packets, 5.0);
        for (const auto& window : primary.windows) {
            ledger << csv_escape(window.window_id) << ',' << csv_escape(window.session_id) << ','
                   << csv_escape(window.run_id) << ',' << csv_escape(window.app_id) << ','
                   << csv_escape(window.condition) << ',' << experiments::to_string(window.capture_source)
                   << ',' << window.start_seconds << ',' << window.end_seconds << ','
                   << window.end_seconds - window.start_seconds << ',' << status_name(window.status)
                   << ',' << (window.packet_count ? "true" : "false") << ',' << window.packet_count
                   << ',' << window.total_ip_bytes << ',' << window.packets_per_second << ','
                   << window.ip_bytes_per_second << ','
                   << (window.schema_v1_features ? "true" : "false");
            if (window.schema_v1_features) {
                const auto& feature = *window.schema_v1_features;
                ledger << ',' << feature.ip_size_mean << ',' << feature.outbound_packet_fraction
                       << ',' << feature.iat_mean << ',' << feature.tcp_packet_fraction << ','
                       << feature.udp_packet_fraction;
            } else ledger << ",,,,,";
            ledger << '\n';
        }
        const auto& metric = primary.occupancy;
        occupancy << row.session_id << ',' << row.run_id << ',' << row.app_id << ','
                  << experiments::to_string(row.state) << ',' << experiments::to_string(row.capture_source)
                  << ",5," << metric.scheduled_window_count << ',' << metric.nonempty_window_count
                  << ',' << metric.empty_window_count << ',' << metric.active_window_fraction << ','
                  << metric.quiet_window_fraction << ',' << metric.longest_consecutive_empty_windows
                  << ',' << metric.longest_quiet_duration_seconds << ',';
        optional_csv(occupancy, metric.time_to_first_packet_seconds); occupancy << ',';
        optional_csv(occupancy, metric.time_from_last_packet_to_interval_end_seconds);
        occupancy << ',' << metric.discarded_tail_seconds << '\n';

        const auto& profile = primary.profile;
        const auto& predictor = profile.predictors;
        profiles << profile.metadata.schema_version << ',' << profile.metadata.session_id << ','
                 << profile.metadata.run_id << ',' << profile.metadata.app_id << ','
                 << profile.metadata.condition << ',' << experiments::to_string(profile.metadata.capture_source)
                 << ',' << predictor.condition_duration_seconds << ',' << predictor.total_ip_packets
                 << ',' << predictor.total_ip_bytes << ',' << predictor.packets_per_second << ','
                 << predictor.ip_bytes_per_second << ',' << predictor.scheduled_window_count << ','
                 << predictor.active_window_count << ',' << predictor.active_window_fraction << ','
                 << predictor.longest_quiet_duration_seconds << ',';
        optional_csv(profiles, predictor.time_to_first_packet_seconds);
        profiles << ',' << (predictor.aggregate_packet_features ? "true" : "false");
        if (predictor.aggregate_packet_features) {
            const auto& feature = *predictor.aggregate_packet_features;
            profiles << ',' << feature.ip_size_mean << ',' << feature.ip_size_stddev << ','
                     << feature.ip_size_min << ',' << feature.ip_size_max << ','
                     << feature.ip_size_median << ',' << feature.ip_size_q1 << ',' << feature.ip_size_q3
                     << ',' << feature.outbound_packet_count << ',' << feature.inbound_packet_count
                     << ',' << feature.unknown_packet_count << ',' << feature.outbound_packet_fraction
                     << ',' << feature.inbound_packet_fraction << ',' << feature.unknown_packet_fraction
                     << ',' << feature.iat_mean << ',' << feature.iat_stddev << ',' << feature.iat_median
                     << ',' << feature.iat_min << ',' << feature.iat_max << ','
                     << feature.tcp_packet_fraction << ',' << feature.udp_packet_fraction << ','
                     << feature.other_transport_fraction;
        } else {
            for (int field = 0; field < 21; ++field) profiles << ',';
        }
        profiles << '\n';

        for (const double window_seconds : sweep_durations) {
            const auto item = analyze_condition(row, packets, window_seconds).occupancy;
            sweep << row.session_id << ',' << row.run_id << ',' << row.app_id << ','
                  << experiments::to_string(row.state) << ',' << experiments::to_string(row.capture_source)
                  << ',' << window_seconds << ',' << item.scheduled_window_count << ','
                  << item.nonempty_window_count << ',' << item.empty_window_count << ','
                  << item.active_window_fraction << ',' << item.discarded_tail_seconds << ','
                  << item.longest_quiet_duration_seconds << '\n';
        }
    }
    write_file(output_directory / "complete-window-ledger.csv", ledger.str());
    write_file(output_directory / "occupancy-summary.csv", occupancy.str());
    write_file(output_directory / "condition-profiles.csv", profiles.str());
    write_file(output_directory / "duration-sweep.csv", sweep.str());
    std::ostringstream checksums;
    for (const std::string file : {"complete-window-ledger.csv", "condition-profiles.csv",
                                   "duration-sweep.csv", "occupancy-summary.csv"}) {
        checksums << util::sha256_file(output_directory / file) << "  " << file << '\n';
    }
    write_file(output_directory / "checksums.sha256", checksums.str());
    return output_directory;
}

}  // namespace ciphertracedroid::analysis
