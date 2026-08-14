#include "ciphertracedroid/features/feature_extractor.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::features {
namespace {

double average(const std::vector<double>& values)
{
    if (values.empty()) return 0.0;
    double total = 0.0;
    for (const double value : values) total += value;
    return total / static_cast<double>(values.size());
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
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (location - static_cast<double>(lower));
}

double safe_ratio(double numerator, double denominator)
{
    // The schema defines a zero denominator as 0.0; no undefined value is exported.
    return denominator == 0.0 ? 0.0 : numerator / denominator;
}

bool finite(double value) { return std::isfinite(value); }

}  // namespace

FeatureRow extract_features(const traffic::TrafficWindow& window, const std::string& app_id,
                            const std::string& run_id, double idle_gap_seconds)
{
    if (idle_gap_seconds < 0.0 || !finite(idle_gap_seconds)) {
        throw std::invalid_argument("idle-gap threshold must be finite and non-negative");
    }
    const double duration = window.end_time - window.start_time;
    if (duration <= 0.0 || !finite(duration)) {
        throw std::invalid_argument("window duration must be finite and positive");
    }
    FeatureRow row{.sample_id = window.window_id, .session_id = window.session_id,
                   .app_id = app_id, .run_id = run_id, .activity_state = window.activity_state,
                   .window_start = window.start_time, .window_end = window.end_time,
                   .packet_count = window.packets.size()};
    std::vector<double> sizes;
    std::vector<double> iats;
    sizes.reserve(window.packets.size());
    for (std::size_t i = 0; i < window.packets.size(); ++i) {
        const auto& packet = window.packets[i];
        const double bytes = static_cast<double>(packet.original_length);
        sizes.push_back(bytes);
        row.total_bytes += bytes;
        if (packet.direction == traffic::Direction::outbound) {
            ++row.outbound_packet_count; row.outbound_bytes += bytes;
        } else if (packet.direction == traffic::Direction::inbound) {
            ++row.inbound_packet_count; row.inbound_bytes += bytes;
        } else {
            ++row.unknown_direction_count;
        }
        if (i > 0) {
            const double gap = packet.timestamp_seconds - window.packets[i - 1].timestamp_seconds;
            if (gap < 0.0 || !finite(gap)) throw std::invalid_argument("packets must be timestamp ordered");
            iats.push_back(gap);
            if (gap > idle_gap_seconds) ++row.idle_gap_count;
        }
    }
    row.packets_per_second = static_cast<double>(row.packet_count) / duration;
    row.bytes_per_second = row.total_bytes / duration;
    std::sort(sizes.begin(), sizes.end());
    row.size_mean = average(sizes); row.size_stddev = standard_deviation(sizes, row.size_mean);
    if (!sizes.empty()) { row.size_min = sizes.front(); row.size_max = sizes.back(); }
    row.size_q1 = quantile(sizes, .25); row.size_median = quantile(sizes, .5); row.size_q3 = quantile(sizes, .75);
    row.outbound_inbound_packet_ratio = safe_ratio(static_cast<double>(row.outbound_packet_count), static_cast<double>(row.inbound_packet_count));
    row.outbound_inbound_byte_ratio = safe_ratio(row.outbound_bytes, row.inbound_bytes);
    std::sort(iats.begin(), iats.end());
    row.iat_mean = average(iats); row.iat_stddev = standard_deviation(iats, row.iat_mean);
    if (!iats.empty()) { row.iat_min = iats.front(); row.iat_max = iats.back(); }
    row.iat_median = quantile(iats, .5);
    // A burst is a maximal packet sequence separated by gaps no greater than the configured idle threshold.
    if (!window.packets.empty()) {
        std::vector<double> burst_packets{1.0}; std::vector<double> burst_bytes{static_cast<double>(window.packets.front().original_length)};
        for (std::size_t i = 1; i < window.packets.size(); ++i) {
            const double gap = window.packets[i].timestamp_seconds - window.packets[i - 1].timestamp_seconds;
            if (gap > idle_gap_seconds) { burst_packets.push_back(0.0); burst_bytes.push_back(0.0); }
            burst_packets.back() += 1.0; burst_bytes.back() += static_cast<double>(window.packets[i].original_length);
        }
        row.burst_count = burst_packets.size(); row.burst_mean_packets = average(burst_packets);
        row.burst_max_packets = *std::max_element(burst_packets.begin(), burst_packets.end());
        row.burst_mean_bytes = average(burst_bytes); row.burst_max_bytes = *std::max_element(burst_bytes.begin(), burst_bytes.end());
    }
    if (!has_finite_values(row)) throw std::runtime_error("feature extraction produced a non-finite value");
    return row;
}

bool has_finite_values(const FeatureRow& row)
{
    const double numeric[] = {row.window_start, row.window_end, row.total_bytes, row.packets_per_second, row.bytes_per_second, row.size_mean, row.size_stddev, row.size_min, row.size_max, row.size_median, row.size_q1, row.size_q3, row.outbound_bytes, row.inbound_bytes, row.outbound_inbound_packet_ratio, row.outbound_inbound_byte_ratio, row.iat_mean, row.iat_stddev, row.iat_median, row.iat_min, row.iat_max, row.burst_mean_packets, row.burst_max_packets, row.burst_mean_bytes, row.burst_max_bytes};
    return std::all_of(std::begin(numeric), std::end(numeric), finite);
}

std::string csv_header()
{
    return "feature_schema_version,sample_id,session_id,app_id,run_id,activity_state,window_start_s,window_end_s,packet_count,total_bytes,packets_per_second,bytes_per_second,size_mean,size_stddev,size_min,size_max,size_median,size_q1,size_q3,outbound_packet_count,inbound_packet_count,outbound_bytes,inbound_bytes,outbound_inbound_packet_ratio,outbound_inbound_byte_ratio,unknown_direction_count,iat_mean,iat_stddev,iat_median,iat_min,iat_max,idle_gap_count,burst_count,burst_mean_packets,burst_max_packets,burst_mean_bytes,burst_max_bytes";
}

std::string to_csv_row(const FeatureRow& row)
{
    if (!has_finite_values(row)) throw std::invalid_argument("refusing to serialize non-finite feature values");
    std::ostringstream out; out << std::setprecision(17);
    out << row.schema_version << ',' << row.sample_id << ',' << row.session_id << ',' << row.app_id << ',' << row.run_id << ',' << row.activity_state;
    const double numeric[] = {row.window_start,row.window_end,static_cast<double>(row.packet_count),row.total_bytes,row.packets_per_second,row.bytes_per_second,row.size_mean,row.size_stddev,row.size_min,row.size_max,row.size_median,row.size_q1,row.size_q3,static_cast<double>(row.outbound_packet_count),static_cast<double>(row.inbound_packet_count),row.outbound_bytes,row.inbound_bytes,row.outbound_inbound_packet_ratio,row.outbound_inbound_byte_ratio,static_cast<double>(row.unknown_direction_count),row.iat_mean,row.iat_stddev,row.iat_median,row.iat_min,row.iat_max,static_cast<double>(row.idle_gap_count),static_cast<double>(row.burst_count),row.burst_mean_packets,row.burst_max_packets,row.burst_mean_bytes,row.burst_max_bytes};
    for (const double value : numeric) out << ',' << value;
    return out.str();
}

}  // namespace ciphertracedroid::features
