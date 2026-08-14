#pragma once

#include <cstdint>
#include <string>

namespace ciphertracedroid::traffic {

enum class NetworkLayer { unknown, ipv4, ipv6 };
enum class TransportProtocol { other, tcp, udp };
enum class Direction { unknown, outbound, inbound };

struct PacketRecord {
    std::uint64_t index{};
    double timestamp_seconds{};
    std::uint32_t captured_length{};
    std::uint32_t original_length{};
    NetworkLayer network_layer{NetworkLayer::unknown};
    TransportProtocol transport_protocol{TransportProtocol::other};
    std::string source_address;
    std::string destination_address;
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    Direction direction{Direction::unknown};
};

[[nodiscard]] Direction assign_direction(const PacketRecord& packet,
                                         const std::string& device_ip);

}  // namespace ciphertracedroid::traffic
