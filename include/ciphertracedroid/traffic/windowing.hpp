#pragma once

#include "ciphertracedroid/traffic/packet_record.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ciphertracedroid::traffic {

struct TrafficWindow {
    std::string window_id;
    std::string session_id;
    std::string activity_state;
    double start_time{};
    double end_time{};
    std::vector<PacketRecord> packets;
    std::size_t known_direction_packet_count{};
    std::size_t unknown_direction_packet_count{};
};

struct StateInterval {
    std::string state;
    double start_time{};
    double end_time{};
    bool include{};
};

[[nodiscard]] std::vector<TrafficWindow> make_windows(
    const std::vector<PacketRecord>& packets, const std::string& session_id,
    const std::vector<StateInterval>& intervals, double window_seconds);

}  // namespace ciphertracedroid::traffic
