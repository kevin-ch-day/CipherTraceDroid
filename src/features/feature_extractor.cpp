#include "ciphertracedroid/features/feature_extractor.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::features {
namespace {

double average(const std::vector<double>& values)
{
    if (values.empty()) return 0.0;
    return std::accumulate(values.begin(), values.end(), 0.0) /
           static_cast<double>(values.size());
}

double standard_deviation(const std::vector<double>& values, double mean)
{
    if (values.size() < 2) return 0.0;
    double squared_sum = 0.0;
    for (const double value : values) squared_sum += (value - mean) * (value - mean);
    return std::sqrt(squared_sum / static_cast<double>(values.size()));
}

double quantile(const std::vector<double>& sorted, double fraction)
{
    if (sorted.empty()) return 0.0;
    const double location = fraction * static_cast<double>(sorted.size() - 1);
    const auto lower = static_cast<std::size_t>(std::floor(location));
    const auto upper = static_cast<std::size_t>(std::ceil(location));
    return sorted[lower] + (sorted[upper] - sorted[lower]) *
                               (location - static_cast<double>(lower));
}

double fraction(double numerator, double denominator)
{
    return denominator == 0.0 ? 0.0 : numerator / denominator;
}

std::string csv_escape(const std::string& value)
{
    if (value.find_first_of(",\"\n") == std::string::npos) return value;
    std::string result{"\""};
    for (char character : value) result += character == '\"' ? "\"\"" : std::string(1, character);
    return result + '\"';
}

}  // namespace

std::vector<double> FeatureVector::values() const
{
    return {packet_count, total_ip_bytes, packets_per_second, ip_bytes_per_second,
            ip_size_mean, ip_size_stddev, ip_size_min, ip_size_max, ip_size_median,
            ip_size_q1, ip_size_q3, outbound_packet_count, inbound_packet_count,
            unknown_packet_count, outbound_ip_bytes, inbound_ip_bytes, unknown_ip_bytes,
            outbound_packet_fraction, inbound_packet_fraction, unknown_packet_fraction,
            outbound_byte_fraction, inbound_byte_fraction, unknown_byte_fraction,
            iat_mean, iat_stddev, iat_median, iat_min, iat_max, tcp_packet_fraction,
            udp_packet_fraction, other_transport_fraction};
}

std::vector<std::string> predictor_names()
{
    return {"packet_count", "total_ip_bytes", "packets_per_second", "ip_bytes_per_second",
            "ip_size_mean", "ip_size_stddev", "ip_size_min", "ip_size_max",
            "ip_size_median", "ip_size_q1", "ip_size_q3", "outbound_packet_count",
            "inbound_packet_count", "unknown_packet_count", "outbound_ip_bytes",
            "inbound_ip_bytes", "unknown_ip_bytes", "outbound_packet_fraction",
            "inbound_packet_fraction", "unknown_packet_fraction", "outbound_byte_fraction",
            "inbound_byte_fraction", "unknown_byte_fraction", "iat_mean", "iat_stddev",
            "iat_median", "iat_min", "iat_max", "tcp_packet_fraction",
            "udp_packet_fraction", "other_transport_fraction"};
}

DatasetSample extract_features(const traffic::TrafficWindow& window, SampleMetadata metadata)
{
    const double duration = window.end_time - window.start_time;
    if (duration <= 0.0 || !std::isfinite(duration)) {
        throw std::invalid_argument("window duration must be finite and positive");
    }
    metadata.sample_id = window.window_id;
    metadata.session_id = window.session_id;
    metadata.activity_state = window.activity_state;
    metadata.window_start = window.start_time;
    metadata.window_end = window.end_time;
    FeatureVector result;
    std::vector<double> sizes;
    std::vector<double> iats;
    sizes.reserve(window.packets.size());
    double tcp_count = 0.0;
    double udp_count = 0.0;
    double other_count = 0.0;
    for (std::size_t index = 0; index < window.packets.size(); ++index) {
        const auto& packet = window.packets[index];
        if (packet.network_layer == traffic::NetworkLayer::unknown || packet.ip_packet_length == 0) {
            throw std::invalid_argument("feature window contains a non-IP or lengthless packet");
        }
        const double bytes = static_cast<double>(packet.ip_packet_length);
        sizes.push_back(bytes);
        result.total_ip_bytes += bytes;
        if (packet.direction == traffic::Direction::outbound) {
            ++result.outbound_packet_count;
            result.outbound_ip_bytes += bytes;
        } else if (packet.direction == traffic::Direction::inbound) {
            ++result.inbound_packet_count;
            result.inbound_ip_bytes += bytes;
        } else {
            ++result.unknown_packet_count;
            result.unknown_ip_bytes += bytes;
        }
        if (packet.transport_protocol == traffic::TransportProtocol::tcp) ++tcp_count;
        else if (packet.transport_protocol == traffic::TransportProtocol::udp) ++udp_count;
        else ++other_count;
        if (index > 0) {
            const double gap = packet.timestamp_seconds - window.packets[index - 1].timestamp_seconds;
            if (gap < 0.0 || !std::isfinite(gap)) {
                throw std::invalid_argument("packets must be in nondecreasing timestamp order");
            }
            iats.push_back(gap);
        }
    }
    result.packet_count = static_cast<double>(window.packets.size());
    result.packets_per_second = result.packet_count / duration;
    result.ip_bytes_per_second = result.total_ip_bytes / duration;
    std::sort(sizes.begin(), sizes.end());
    result.ip_size_mean = average(sizes);
    result.ip_size_stddev = standard_deviation(sizes, result.ip_size_mean);
    if (!sizes.empty()) {
        result.ip_size_min = sizes.front();
        result.ip_size_max = sizes.back();
    }
    result.ip_size_q1 = quantile(sizes, 0.25);
    result.ip_size_median = quantile(sizes, 0.5);
    result.ip_size_q3 = quantile(sizes, 0.75);
    result.outbound_packet_fraction = fraction(result.outbound_packet_count, result.packet_count);
    result.inbound_packet_fraction = fraction(result.inbound_packet_count, result.packet_count);
    result.unknown_packet_fraction = fraction(result.unknown_packet_count, result.packet_count);
    result.outbound_byte_fraction = fraction(result.outbound_ip_bytes, result.total_ip_bytes);
    result.inbound_byte_fraction = fraction(result.inbound_ip_bytes, result.total_ip_bytes);
    result.unknown_byte_fraction = fraction(result.unknown_ip_bytes, result.total_ip_bytes);
    std::sort(iats.begin(), iats.end());
    result.iat_mean = average(iats);
    result.iat_stddev = standard_deviation(iats, result.iat_mean);
    if (!iats.empty()) {
        result.iat_min = iats.front();
        result.iat_max = iats.back();
    }
    result.iat_median = quantile(iats, 0.5);
    result.tcp_packet_fraction = fraction(tcp_count, result.packet_count);
    result.udp_packet_fraction = fraction(udp_count, result.packet_count);
    result.other_transport_fraction = fraction(other_count, result.packet_count);
    if (!has_finite_values(result)) throw std::runtime_error("feature extraction produced a non-finite predictor");
    return {std::move(metadata), result};
}

bool has_finite_values(const FeatureVector& vector)
{
    const auto values = vector.values();
    return std::all_of(values.begin(), values.end(), [](double value) { return std::isfinite(value); });
}

std::string csv_header()
{
    std::ostringstream output;
    output << "feature_schema_version,sample_id,session_id,app_id,run_id,activity_state,"
              "capture_source,capture_reference,window_start_s,window_end_s,synthetic_test_only,pilot";
    for (const auto& name : predictor_names()) output << ',' << name;
    return output.str();
}

std::string to_csv_row(const DatasetSample& sample)
{
    if (!has_finite_values(sample.predictors)) throw std::invalid_argument("refusing to serialize non-finite predictors");
    std::ostringstream output;
    output << std::setprecision(17) << sample.metadata.schema_version << ','
           << csv_escape(sample.metadata.sample_id) << ',' << csv_escape(sample.metadata.session_id)
           << ',' << csv_escape(sample.metadata.app_id) << ',' << csv_escape(sample.metadata.run_id)
           << ',' << csv_escape(sample.metadata.activity_state) << ','
           << experiments::to_string(sample.metadata.capture_source) << ','
           << csv_escape(sample.metadata.capture_reference) << ',' << sample.metadata.window_start
           << ',' << sample.metadata.window_end << ','
           << (sample.metadata.synthetic_test_only ? "true" : "false") << ','
           << (sample.metadata.pilot ? "true" : "false");
    for (double value : sample.predictors.values()) output << ',' << value;
    return output.str();
}

}  // namespace ciphertracedroid::features
