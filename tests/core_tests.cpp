#include "ciphertracedroid/app.hpp"
#include "ciphertracedroid/features/feature_extractor.hpp"
#include "ciphertracedroid/features/dataset_export.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/experiments/grouped_partitioner.hpp"
#include "ciphertracedroid/util/sha256.hpp"
#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/traffic/windowing.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

ciphertracedroid::traffic::PacketRecord packet(double timestamp, std::uint32_t length,
                                                ciphertracedroid::traffic::Direction direction)
{
    return {.timestamp_seconds = timestamp,
            .captured_length = length,
            .original_length = length,
            .source_address = {},
            .destination_address = {},
            .direction = direction};
}

void test_direction_assignment()
{
    auto record = packet(0.0, 10, ciphertracedroid::traffic::Direction::unknown);
    record.source_address = "192.168.1.42"; record.destination_address = "8.8.8.8";
    require(ciphertracedroid::traffic::assign_direction(record, "192.168.1.42") == ciphertracedroid::traffic::Direction::outbound, "outbound direction");
    record.source_address = "8.8.8.8"; record.destination_address = "192.168.1.42";
    require(ciphertracedroid::traffic::assign_direction(record, "192.168.1.42") == ciphertracedroid::traffic::Direction::inbound, "inbound direction");
    require(ciphertracedroid::traffic::assign_direction(record, "") == ciphertracedroid::traffic::Direction::unknown, "empty identity stays unknown");
}

void test_state_boundaries()
{
    using namespace ciphertracedroid::traffic;
    const std::vector<PacketRecord> packets{packet(0.5, 10, Direction::outbound), packet(5.5, 20, Direction::inbound), packet(10.5, 30, Direction::unknown)};
    const std::vector<StateInterval> intervals{{"foreground", 0.0, 10.0, true}, {"transition", 10.0, 12.0, false}, {"background", 12.0, 20.0, true}};
    const auto windows = make_windows(packets, "session", intervals, 5.0);
    require(windows.size() == 4, "included state intervals are windowed without crossing state boundaries");
    require(windows[0].packets.size() == 1 && windows[1].packets.size() == 1, "packets stay in their state window");
    require(windows[2].packets.empty() && windows[3].packets.empty(), "transition packet is excluded");
    require(windows[0].activity_state == "foreground" && windows[2].activity_state == "background", "state labels preserved");
}

void test_features()
{
    using namespace ciphertracedroid;
    traffic::TrafficWindow window{.window_id = "s_0", .session_id = "s", .activity_state = "foreground", .start_time = 0.0, .end_time = 5.0,
                                  .packets = {packet(0.0, 100, traffic::Direction::outbound), packet(0.2, 50, traffic::Direction::inbound), packet(2.0, 25, traffic::Direction::unknown)}};
    const auto row = features::extract_features(window, "app", "run", 1.0);
    require(row.packet_count == 3 && row.total_bytes == 175.0, "volume features");
    require(row.outbound_inbound_packet_ratio == 1.0 && row.outbound_inbound_byte_ratio == 2.0, "direction ratios");
    require(row.burst_count == 2, "burst threshold");
    require(features::has_finite_values(row), "finite feature values");
    require(features::csv_header().find("feature_schema_version") == 0, "versioned CSV header");
    require(features::to_csv_row(row).find("nan") == std::string::npos, "CSV does not contain NaN");
    traffic::TrafficWindow empty{.window_id = "empty", .session_id = "s", .activity_state = "background", .start_time = 0.0, .end_time = 5.0, .packets = {}};
    const auto empty_row = features::extract_features(empty, "app", "run");
    require(empty_row.packet_count == 0 && empty_row.outbound_inbound_packet_ratio == 0.0 && features::has_finite_values(empty_row), "zero-packet values are explicit and finite");
}

void write_u16(std::ofstream& out, std::uint16_t value) { out.write(reinterpret_cast<const char*>(&value), sizeof(value)); }
void write_u32(std::ofstream& out, std::uint32_t value) { out.write(reinterpret_cast<const char*>(&value), sizeof(value)); }

void write_packet(std::ofstream& out, std::uint32_t seconds, const std::vector<std::uint8_t>& bytes)
{
    write_u32(out, seconds); write_u32(out, 0); write_u32(out, bytes.size()); write_u32(out, bytes.size());
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::vector<std::uint8_t> ethernet(std::uint16_t type)
{
    std::vector<std::uint8_t> bytes(14); bytes[12] = static_cast<std::uint8_t>(type >> 8U); bytes[13] = static_cast<std::uint8_t>(type);
    return bytes;
}

void test_pcap_reader()
{
    const auto path = std::filesystem::temp_directory_path() / "ciphertracedroid_synthetic.pcap";
    {
        std::ofstream out(path, std::ios::binary); require(out.good(), "create synthetic PCAP");
        write_u32(out, 0xa1b2c3d4U); write_u16(out, 2); write_u16(out, 4); write_u32(out, 0); write_u32(out, 0); write_u32(out, 65535); write_u32(out, 1);
        auto ipv4_tcp = ethernet(0x0800); ipv4_tcp.resize(54); ipv4_tcp[14] = 0x45; ipv4_tcp[23] = 6; ipv4_tcp[26] = 192; ipv4_tcp[27] = 168; ipv4_tcp[28] = 1; ipv4_tcp[29] = 42; ipv4_tcp[30] = 8; ipv4_tcp[31] = 8; ipv4_tcp[32] = 8; ipv4_tcp[33] = 8; ipv4_tcp[34] = 0x01; ipv4_tcp[35] = 0xbb; ipv4_tcp[36] = 0x01; ipv4_tcp[37] = 0xbb;
        auto ipv4_udp = ethernet(0x0800); ipv4_udp.resize(42); ipv4_udp[14] = 0x45; ipv4_udp[23] = 17; ipv4_udp[26] = 8; ipv4_udp[27] = 8; ipv4_udp[28] = 4; ipv4_udp[29] = 4; ipv4_udp[30] = 192; ipv4_udp[31] = 168; ipv4_udp[32] = 1; ipv4_udp[33] = 42; ipv4_udp[34] = 0; ipv4_udp[35] = 53; ipv4_udp[36] = 0x13; ipv4_udp[37] = 0x88;
        auto ipv6_udp = ethernet(0x86dd); ipv6_udp.resize(62); ipv6_udp[14] = 0x60; ipv6_udp[20] = 17; ipv6_udp[22] = 0x20; ipv6_udp[23] = 0x01; ipv6_udp[38] = 0x20; ipv6_udp[39] = 0x01; ipv6_udp[54] = 0x13; ipv6_udp[55] = 0x88; ipv6_udp[56] = 0x01; ipv6_udp[57] = 0xbb;
        write_packet(out, 10, ipv4_tcp); write_packet(out, 11, ipv4_udp); write_packet(out, 12, ipv6_udp); write_packet(out, 13, std::vector<std::uint8_t>(10));
    }
    const auto capture = ciphertracedroid::capture::read_pcap(path.string(), "192.168.1.42");
    require(capture.summary.packet_count == 4 && capture.packets.size() == 3, "PCAP packet and malformed counts");
    require(capture.summary.ipv4_count == 2 && capture.summary.ipv6_count == 1, "IP version parsing");
    require(capture.summary.tcp_count == 1 && capture.summary.udp_count == 2, "transport parsing");
    require(capture.summary.malformed_packet_count == 1 && capture.summary.duration_seconds == 3.0, "capture timing and malformed parsing");
    require(capture.packets.front().direction == ciphertracedroid::traffic::Direction::outbound, "explicit device direction");
    require(ciphertracedroid::capture::summary_to_json(capture.summary).find("\"packet_count\":4") != std::string::npos, "deterministic JSON summary");
    std::string path_text = path.string();
    char program[] = "ciphertracedroid";
    char inspect[] = "inspect";
    char format[] = "--format";
    char json[] = "json";
    char* arguments[] = {program, inspect, path_text.data(), format, json};
    require(ciphertracedroid::run(5, arguments) == 0, "inspect CLI accepts valid synthetic PCAP");
    const auto manifest = path.parent_path() / "ciphertracedroid_synthetic_manifest.csv";
    const auto csv = path.parent_path() / "ciphertracedroid_synthetic_features.csv";
    { std::ofstream out(manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,start_offset_s,end_offset_s,include\n" << "s1,app,r1,foreground," << path.filename().string() << ',' << ciphertracedroid::util::sha256_file(path) << ",0,10,true\n"; }
    const auto written = ciphertracedroid::features::export_features(manifest, csv, {.window_seconds = 5.0, .idle_gap_seconds = 1.0, .device_ip = "192.168.1.42"});
    require(written == 2, "manifest-driven state windows export");
    { std::ifstream input(csv); std::string header; std::string first_row; std::getline(input, header); std::getline(input, first_row); require(header == ciphertracedroid::features::csv_header() && first_row.find(",s1,app,r1,foreground,") != std::string::npos, "feature CSV provenance"); }
    std::filesystem::remove(manifest); std::filesystem::remove(csv);
    std::filesystem::remove(path);
}

void test_manifest_and_hash()
{
    const auto directory = std::filesystem::temp_directory_path() / "ciphertracedroid_manifest_test";
    std::filesystem::create_directories(directory);
    const auto capture = directory / "capture.pcap";
    { std::ofstream out(capture, std::ios::binary); out << "synthetic"; }
    const auto hash = ciphertracedroid::util::sha256_file(capture);
    require(ciphertracedroid::util::is_sha256_hex(hash), "SHA-256 output format");
    const auto manifest = directory / "sessions.csv";
    { std::ofstream out(manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,start_offset_s,end_offset_s,include\n" << "s1,app,r1,foreground,capture.pcap," << hash << ",0,10,true\n"; }
    const auto rows = ciphertracedroid::experiments::read_session_manifest(manifest);
    require(rows.size() == 1 && rows[0].capture_file == capture && rows[0].include, "strict manifest parsing");
    std::string manifest_text = manifest.string();
    char program[] = "ciphertracedroid";
    char validate[] = "validate-manifest";
    char* arguments[] = {program, validate, manifest_text.data()};
    require(ciphertracedroid::run(3, arguments) == 0, "manifest validation CLI");
    std::filesystem::remove_all(directory);
}

void test_grouped_partitioning()
{
    using ciphertracedroid::experiments::SampleMetadata;
    const std::vector<SampleMetadata> samples{{"w1", "s1", "r1", "a", "foreground"}, {"w2", "s1", "r1", "a", "background"}, {"w3", "s2", "r2", "a", "foreground"}};
    const auto partition = ciphertracedroid::experiments::partition_by_run(samples, {"r2"});
    require(partition.training_indices == std::vector<std::size_t>{0, 1} && partition.test_indices == std::vector<std::size_t>{2}, "all windows from a run stay together");
}

}  // namespace

int main()
{
    try { test_direction_assignment(); test_state_boundaries(); test_features(); test_pcap_reader(); test_manifest_and_hash(); test_grouped_partitioning(); }
    catch (const std::exception& error) { std::cerr << "test failure: " << error.what() << '\n'; return EXIT_FAILURE; }
    return EXIT_SUCCESS;
}
