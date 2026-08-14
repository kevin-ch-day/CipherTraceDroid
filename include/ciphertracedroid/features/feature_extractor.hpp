#pragma once

#include "ciphertracedroid/experiments/capture_source.hpp"
#include "ciphertracedroid/traffic/windowing.hpp"

#include <string>
#include <vector>

namespace ciphertracedroid::features {

inline constexpr int kFeatureSchemaVersion = 1;

struct SampleMetadata {
    int schema_version{kFeatureSchemaVersion};
    std::string sample_id;
    std::string session_id;
    std::string app_id;
    std::string run_id;
    std::string activity_state;
    experiments::CaptureSourceKind capture_source{experiments::CaptureSourceKind::synthetic_fixture};
    std::string capture_reference;
    double window_start{};
    double window_end{};
    bool synthetic_test_only{};
    bool pilot{};
};

struct FeatureVector {
    double packet_count{};
    double total_ip_bytes{};
    double packets_per_second{};
    double ip_bytes_per_second{};
    double ip_size_mean{};
    double ip_size_stddev{};
    double ip_size_min{};
    double ip_size_max{};
    double ip_size_median{};
    double ip_size_q1{};
    double ip_size_q3{};
    double outbound_packet_count{};
    double inbound_packet_count{};
    double unknown_packet_count{};
    double outbound_ip_bytes{};
    double inbound_ip_bytes{};
    double unknown_ip_bytes{};
    double outbound_packet_fraction{};
    double inbound_packet_fraction{};
    double unknown_packet_fraction{};
    double outbound_byte_fraction{};
    double inbound_byte_fraction{};
    double unknown_byte_fraction{};
    double iat_mean{};
    double iat_stddev{};
    double iat_median{};
    double iat_min{};
    double iat_max{};
    double tcp_packet_fraction{};
    double udp_packet_fraction{};
    double other_transport_fraction{};

    [[nodiscard]] std::vector<double> values() const;
};

struct DatasetSample {
    SampleMetadata metadata;
    FeatureVector predictors;
};

[[nodiscard]] DatasetSample extract_features(const traffic::TrafficWindow& window,
                                             SampleMetadata metadata);
[[nodiscard]] bool has_finite_values(const FeatureVector& vector);
[[nodiscard]] std::vector<std::string> predictor_names();
[[nodiscard]] std::string csv_header();
[[nodiscard]] std::string to_csv_row(const DatasetSample& sample);

}  // namespace ciphertracedroid::features
