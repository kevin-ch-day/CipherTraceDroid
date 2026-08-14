#include "ciphertracedroid/traffic/windowing.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace ciphertracedroid::traffic {

Direction assign_direction(const PacketRecord& packet, const std::string& device_ip)
{
    if (device_ip.empty()) {
        return Direction::unknown;
    }
    if (packet.source_address == device_ip) {
        return Direction::outbound;
    }
    if (packet.destination_address == device_ip) {
        return Direction::inbound;
    }
    return Direction::unknown;
}

std::vector<TrafficWindow> make_windows(const std::vector<PacketRecord>& packets,
                                        const std::string& session_id,
                                        const std::vector<StateInterval>& intervals,
                                        double window_seconds)
{
    if (window_seconds <= 0.0 || !std::isfinite(window_seconds)) {
        throw std::invalid_argument("window duration must be finite and positive");
    }
    for (std::size_t index = 0; index < packets.size(); ++index) {
        if (!std::isfinite(packets[index].timestamp_seconds)) {
            throw std::invalid_argument("packet timestamp must be finite");
        }
        if (index > 0 && packets[index].timestamp_seconds < packets[index - 1].timestamp_seconds) {
            throw std::invalid_argument("packets must be in nondecreasing timestamp order");
        }
    }
    for (std::size_t left = 0; left < intervals.size(); ++left) {
        if (!std::isfinite(intervals[left].start_time) || !std::isfinite(intervals[left].end_time)) {
            throw std::invalid_argument("state interval boundaries must be finite");
        }
        for (std::size_t right = left + 1; right < intervals.size(); ++right) {
            if (std::max(intervals[left].start_time, intervals[right].start_time) <
                std::min(intervals[left].end_time, intervals[right].end_time)) {
                throw std::invalid_argument("state intervals must not overlap");
            }
        }
    }
    std::vector<TrafficWindow> windows;
    for (const auto& interval : intervals) {
        if (interval.end_time <= interval.start_time) {
            throw std::invalid_argument("state interval end must be after its start");
        }
        if (!interval.include) {
            continue;
        }
        for (double start = interval.start_time;
             start + window_seconds <= interval.end_time + 1e-12;
             start += window_seconds) {
            const double end = start + window_seconds;
            TrafficWindow window{.window_id = session_id + "_" + std::to_string(windows.size()),
                                 .session_id = session_id,
                                 .activity_state = interval.state,
                                 .start_time = start,
                                 .end_time = end,
                                 .packets = {},
                                 .known_direction_packet_count = 0,
                                 .unknown_direction_packet_count = 0};
            for (const auto& packet : packets) {
                if (packet.timestamp_seconds >= start && packet.timestamp_seconds < end) {
                    window.packets.push_back(packet);
                    if (packet.direction == Direction::unknown) {
                        ++window.unknown_direction_packet_count;
                    } else {
                        ++window.known_direction_packet_count;
                    }
                }
            }
            windows.push_back(std::move(window));
        }
    }
    return windows;
}

}  // namespace ciphertracedroid::traffic
