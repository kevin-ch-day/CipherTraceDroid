#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/util/logging.hpp"

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::capture {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;
constexpr std::uint8_t kIpProtocolTcp = 6;
constexpr std::uint8_t kIpProtocolUdp = 17;

std::uint16_t read_u16(const std::uint8_t* bytes)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) | bytes[1]);
}

std::string address_text(int family, const std::uint8_t* bytes)
{
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (inet_ntop(family, bytes, text.data(), text.size()) == nullptr) {
        throw std::runtime_error("could not format parsed IP address");
    }
    return text.data();
}

bool parse_transport(traffic::PacketRecord& record, const std::uint8_t* bytes,
                     std::size_t available, std::uint8_t protocol)
{
    if (protocol == kIpProtocolTcp || protocol == kIpProtocolUdp) {
        if (available < 4) return false;
        record.transport_protocol = protocol == kIpProtocolTcp
                                        ? traffic::TransportProtocol::tcp
                                        : traffic::TransportProtocol::udp;
        record.source_port = read_u16(bytes);
        record.destination_port = read_u16(bytes + 2);
    }
    return true;
}

bool parse_ethernet(const std::uint8_t* bytes, std::size_t available,
                    traffic::PacketRecord& record)
{
    if (available < 14) return false;
    std::size_t offset = 14;
    std::uint16_t ether_type = read_u16(bytes + 12);
    while (ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) {
        if (available < offset + 4) return false;
        ether_type = read_u16(bytes + offset + 2);
        offset += 4;
    }
    if (ether_type == kEtherTypeIpv4) {
        if (available < offset + 20) return false;
        const auto version_and_ihl = bytes[offset];
        const auto header_length = static_cast<std::size_t>(version_and_ihl & 0x0FU) * 4U;
        if ((version_and_ihl >> 4U) != 4 || header_length < 20 || available < offset + header_length) return false;
        record.network_layer = traffic::NetworkLayer::ipv4;
        record.source_address = address_text(AF_INET, bytes + offset + 12);
        record.destination_address = address_text(AF_INET, bytes + offset + 16);
        return parse_transport(record, bytes + offset + header_length,
                               available - offset - header_length, bytes[offset + 9]);
    }
    if (ether_type == kEtherTypeIpv6) {
        if (available < offset + 40 || (bytes[offset] >> 4U) != 6) return false;
        record.network_layer = traffic::NetworkLayer::ipv6;
        record.source_address = address_text(AF_INET6, bytes + offset + 8);
        record.destination_address = address_text(AF_INET6, bytes + offset + 24);
        // Extension headers are deliberately recorded as other until explicitly implemented.
        return parse_transport(record, bytes + offset + 40, available - offset - 40, bytes[offset + 6]);
    }
    return true;
}

void update_protocol_counts(CaptureSummary& summary, const traffic::PacketRecord& record)
{
    if (record.network_layer == traffic::NetworkLayer::ipv4) ++summary.ipv4_count;
    if (record.network_layer == traffic::NetworkLayer::ipv6) ++summary.ipv6_count;
    if (record.transport_protocol == traffic::TransportProtocol::tcp) ++summary.tcp_count;
    else if (record.transport_protocol == traffic::TransportProtocol::udp) ++summary.udp_count;
    else ++summary.other_protocol_count;
}

std::string json_string(const std::string& value)
{
    std::ostringstream out;
    out << '"';
    for (const char character : value) {
        if (character == '"' || character == '\\') {
            out << '\\' << character;
        } else if (character == '\n') {
            out << "\\n";
        } else {
            out << character;
        }
    }
    out << '"';
    return out.str();
}

}  // namespace

CaptureData read_pcap(const std::string& path, const std::string& device_ip)
{
    util::debug_log("capture", "opening offline PCAP");
    std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
    const std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_open_offline(path.c_str(), error_buffer.data()), &pcap_close);
    if (!handle) throw std::runtime_error("could not open capture '" + path + "': " + error_buffer.data());
    const int link_type = pcap_datalink(handle.get());
    if (link_type != DLT_EN10MB) {
        throw std::runtime_error("unsupported link-layer type " + std::to_string(link_type) +
                                 " (currently supports Ethernet/DLT_EN10MB)");
    }
    util::debug_log("capture", "using Ethernet decoder");
    CaptureData result;
    result.summary.capture_path = path;
    result.summary.link_layer_type = link_type;
    result.summary.link_layer_name = pcap_datalink_val_to_name(link_type);
    pcap_pkthdr* header = nullptr;
    const u_char* bytes = nullptr;
    int status = 0;
    while ((status = pcap_next_ex(handle.get(), &header, &bytes)) >= 0) {
        if (status == 0) continue;
        const double timestamp = static_cast<double>(header->ts.tv_sec) +
                                 static_cast<double>(header->ts.tv_usec) / 1'000'000.0;
        if (result.summary.packet_count == 0) result.summary.first_timestamp_seconds = timestamp;
        result.summary.last_timestamp_seconds = timestamp;
        ++result.summary.packet_count;
        result.summary.captured_bytes += header->caplen;
        result.summary.original_bytes += header->len;
        traffic::PacketRecord record{.index = result.summary.packet_count - 1,
                                     .timestamp_seconds = timestamp,
                                     .captured_length = header->caplen,
                                     .original_length = header->len,
                                     .source_address = {},
                                     .destination_address = {}};
        if (!parse_ethernet(bytes, header->caplen, record)) {
            ++result.summary.malformed_packet_count;
            continue;
        }
        record.direction = traffic::assign_direction(record, device_ip);
        update_protocol_counts(result.summary, record);
        result.packets.push_back(std::move(record));
    }
    if (status == -1) throw std::runtime_error("error while reading capture '" + path + "': " + pcap_geterr(handle.get()));
    if (result.summary.packet_count > 0) result.summary.duration_seconds = result.summary.last_timestamp_seconds - result.summary.first_timestamp_seconds;
    util::debug_log("capture", "completed PCAP decode");
    return result;
}

std::string summary_to_json(const CaptureSummary& summary)
{
    std::ostringstream out;
    out << std::setprecision(17) << "{\"capture_path\":" << json_string(summary.capture_path)
        << ",\"link_layer_type\":" << summary.link_layer_type
        << ",\"link_layer_name\":" << json_string(summary.link_layer_name)
        << ",\"packet_count\":" << summary.packet_count
        << ",\"first_timestamp_seconds\":" << summary.first_timestamp_seconds
        << ",\"last_timestamp_seconds\":" << summary.last_timestamp_seconds
        << ",\"duration_seconds\":" << summary.duration_seconds
        << ",\"captured_bytes\":" << summary.captured_bytes
        << ",\"original_bytes\":" << summary.original_bytes
        << ",\"ipv4_count\":" << summary.ipv4_count
        << ",\"ipv6_count\":" << summary.ipv6_count
        << ",\"tcp_count\":" << summary.tcp_count
        << ",\"udp_count\":" << summary.udp_count
        << ",\"other_protocol_count\":" << summary.other_protocol_count
        << ",\"malformed_packet_count\":" << summary.malformed_packet_count << "}\n";
    return out.str();
}

std::string summary_to_text(const CaptureSummary& summary)
{
    std::ostringstream out;
    out << std::setprecision(17) << "Capture: " << summary.capture_path << '\n'
        << "Link layer: " << summary.link_layer_name << " (" << summary.link_layer_type << ")\n"
        << "Packets: " << summary.packet_count << '\n'
        << "First timestamp: " << summary.first_timestamp_seconds << '\n'
        << "Last timestamp: " << summary.last_timestamp_seconds << '\n'
        << "Duration: " << summary.duration_seconds << '\n'
        << "Captured bytes: " << summary.captured_bytes << '\n'
        << "Original bytes: " << summary.original_bytes << '\n'
        << "IPv4/IPv6: " << summary.ipv4_count << '/' << summary.ipv6_count << '\n'
        << "TCP/UDP/other: " << summary.tcp_count << '/' << summary.udp_count << '/' << summary.other_protocol_count << '\n'
        << "Malformed: " << summary.malformed_packet_count << '\n';
    return out.str();
}

}  // namespace ciphertracedroid::capture
