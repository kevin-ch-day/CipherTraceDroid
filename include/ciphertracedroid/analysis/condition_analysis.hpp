#pragma once

#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/features/feature_extractor.hpp"
#include "ciphertracedroid/traffic/packet_record.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ciphertracedroid::analysis {

inline constexpr int kConditionProfileSchemaVersion = 1;

enum class WindowObservationStatus { observed_nonempty, observed_empty };

struct WindowObservation {
    std::string window_id;
    std::string session_id;
    std::string run_id;
    std::string app_id;
    std::string condition;
    experiments::CaptureSourceKind capture_source{};
    double start_seconds{};
    double end_seconds{};
    WindowObservationStatus status{WindowObservationStatus::observed_empty};
    std::size_t packet_count{};
    std::uint64_t total_ip_bytes{};
    double packets_per_second{};
    double ip_bytes_per_second{};
    std::optional<features::FeatureVector> schema_v1_features;
    std::vector<double> packet_timestamps;
};

struct OccupancyMetrics {
    std::size_t scheduled_window_count{};
    std::size_t nonempty_window_count{};
    std::size_t empty_window_count{};
    double active_window_fraction{};
    double quiet_window_fraction{};
    std::size_t longest_consecutive_empty_windows{};
    double longest_quiet_duration_seconds{};
    std::optional<double> time_to_first_packet_seconds;
    std::optional<double> time_from_last_packet_to_interval_end_seconds;
    double discarded_tail_seconds{};
};

struct ConditionProfileMetadata {
    int schema_version{kConditionProfileSchemaVersion};
    std::string session_id;
    std::string run_id;
    std::string app_id;
    std::string condition;
    experiments::CaptureSourceKind capture_source{};
};

struct ConditionProfilePredictors {
    double condition_duration_seconds{};
    double total_ip_packets{};
    double total_ip_bytes{};
    double packets_per_second{};
    double ip_bytes_per_second{};
    std::optional<features::FeatureVector> aggregate_packet_features;
    double scheduled_window_count{};
    double active_window_count{};
    double active_window_fraction{};
    double longest_quiet_duration_seconds{};
    std::optional<double> time_to_first_packet_seconds;

    [[nodiscard]] std::vector<double> required_values() const;
};

struct RunConditionProfile {
    ConditionProfileMetadata metadata;
    ConditionProfilePredictors predictors;
};

struct ConditionAnalysis {
    std::vector<WindowObservation> windows;
    OccupancyMetrics occupancy;
    RunConditionProfile profile;
};

[[nodiscard]] ConditionAnalysis analyze_condition(
    const experiments::SessionManifestRow& row,
    const std::vector<traffic::PacketRecord>& capture_relative_packets,
    double window_seconds);
[[nodiscard]] std::vector<std::string> condition_profile_predictor_names();
[[nodiscard]] std::filesystem::path write_condition_analysis_bundle(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& output_directory,
    const std::string& device_ip,
    const std::vector<double>& sweep_durations = {5.0, 10.0, 15.0, 30.0, 60.0});

}  // namespace ciphertracedroid::analysis
