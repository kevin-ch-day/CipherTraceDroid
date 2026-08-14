#pragma once

#include "ciphertracedroid/experiments/capture_source.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ciphertracedroid::experiments {

// device_control is an experimental baseline, not an Android lifecycle state.
enum class ActivityState { foreground, background, transition, device_control };

struct SessionManifestRow {
    std::string session_id;
    std::string app_id;
    std::string run_id;
    ActivityState state{};
    std::filesystem::path capture_file;
    std::string capture_sha256;
    CaptureSourceKind capture_source{CaptureSourceKind::routed_primary};
    double start_offset_seconds{};
    double end_offset_seconds{};
    bool include{};
    bool synthetic_test_only{};
    bool pilot{};
    std::size_t source_row{};
};

[[nodiscard]] std::vector<SessionManifestRow> read_session_manifest(const std::filesystem::path& path);
void validate_session_manifest_integrity(const std::vector<SessionManifestRow>& rows);
[[nodiscard]] std::string to_string(ActivityState state);

}  // namespace ciphertracedroid::experiments
