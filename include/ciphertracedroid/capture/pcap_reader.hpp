#pragma once

#include "ciphertracedroid/traffic/packet_record.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ciphertracedroid::capture {

struct CaptureSummary {
    std::string capture_path;
    int link_layer_type{};
    std::string link_layer_name;
    std::size_t packet_count{};
    double first_timestamp_seconds{};
    double last_timestamp_seconds{};
    double duration_seconds{};
    std::uint64_t captured_bytes{};
    std::uint64_t original_bytes{};
    std::string timestamp_precision;
    std::size_t ipv4_count{};
    std::size_t ipv6_count{};
    std::size_t non_ip_frame_count{};
    std::size_t unsupported_frame_count{};
    std::size_t tcp_count{};
    std::size_t udp_count{};
    std::size_t other_protocol_count{};
    std::size_t malformed_packet_count{};
};

struct CaptureData {
    CaptureSummary summary;
    std::vector<traffic::PacketRecord> packets;
};

[[nodiscard]] CaptureData read_pcap(const std::string& path,
                                    const std::string& device_ip = "");
[[nodiscard]] std::string summary_to_json(const CaptureSummary& summary);
[[nodiscard]] std::string summary_to_text(const CaptureSummary& summary);

}  // namespace ciphertracedroid::capture
