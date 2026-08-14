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
    std::vector<TrafficWindow> windows;
    for (const auto& interval : intervals) {
        if (interval.end_time <= interval.start_time) {
            throw std::invalid_argument("state interval end must be after its start");
        }
        if (!interval.include) {
            continue;
        }
        for (double start = interval.start_time; start < interval.end_time; start += window_seconds) {
            const double end = std::min(start + window_seconds, interval.end_time);
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
