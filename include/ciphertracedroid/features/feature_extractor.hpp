#pragma once

#include "ciphertracedroid/traffic/windowing.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ciphertracedroid::features {

inline constexpr int kFeatureSchemaVersion = 1;

struct FeatureRow {
    int schema_version{kFeatureSchemaVersion};
    std::string sample_id;
    std::string session_id;
    std::string app_id;
    std::string run_id;
    std::string activity_state;
    double window_start{};
    double window_end{};
    std::size_t packet_count{};
    double total_bytes{};
    double packets_per_second{};
    double bytes_per_second{};
    double size_mean{};
    double size_stddev{};
    double size_min{};
    double size_max{};
    double size_median{};
    double size_q1{};
    double size_q3{};
    std::size_t outbound_packet_count{};
    std::size_t inbound_packet_count{};
    double outbound_bytes{};
    double inbound_bytes{};
    double outbound_inbound_packet_ratio{};
    double outbound_inbound_byte_ratio{};
    std::size_t unknown_direction_count{};
    double iat_mean{};
    double iat_stddev{};
    double iat_median{};
    double iat_min{};
    double iat_max{};
    std::size_t idle_gap_count{};
    std::size_t burst_count{};
    double burst_mean_packets{};
    double burst_max_packets{};
    double burst_mean_bytes{};
    double burst_max_bytes{};
};

[[nodiscard]] FeatureRow extract_features(const traffic::TrafficWindow& window,
                                          const std::string& app_id,
                                          const std::string& run_id,
                                          double idle_gap_seconds = 1.0);
[[nodiscard]] bool has_finite_values(const FeatureRow& row);
[[nodiscard]] std::string csv_header();
[[nodiscard]] std::string to_csv_row(const FeatureRow& row);

}  // namespace ciphertracedroid::features
