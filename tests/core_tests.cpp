#include "ciphertracedroid/app.hpp"
#include "ciphertracedroid/analysis/condition_analysis.hpp"
#include "ciphertracedroid/features/feature_extractor.hpp"
#include "ciphertracedroid/features/dataset_export.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/experiments/grouped_partitioner.hpp"
#include "ciphertracedroid/experiments/session_plan.hpp"
#include "ciphertracedroid/experiments/capture_source.hpp"
#include "ciphertracedroid/experiments/integration_experiment.hpp"
#include "ciphertracedroid/util/sha256.hpp"
#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/device/adb_client.hpp"
#include "ciphertracedroid/device/android_state.hpp"
#include "ciphertracedroid/device/input_diagnostics.hpp"
#include "ciphertracedroid/device/pcapdroid_controller.hpp"
#include "ciphertracedroid/experiments/manifest_builder.hpp"
#include "ciphertracedroid/traffic/windowing.hpp"

#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
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
            .ip_packet_length = length,
            .network_layer = ciphertracedroid::traffic::NetworkLayer::ipv4,
            .source_address = {},
            .destination_address = {},
            .source_port = std::nullopt,
            .destination_port = std::nullopt,
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
    require(windows.size() == 3, "only complete windows are emitted without crossing state boundaries");
    require(windows[0].packets.size() == 1 && windows[1].packets.size() == 1, "packets stay in their state window");
    require(windows[2].packets.empty(), "transition packet and incomplete background tail are excluded");
    require(windows[0].activity_state == "foreground" && windows[2].activity_state == "background", "state labels preserved");
    bool overlap_rejected = false;
    try { (void)make_windows(packets, "session", {{"foreground", 0.0, 6.0, true}, {"background", 5.0, 10.0, true}}, 5.0); }
    catch (const std::invalid_argument&) { overlap_rejected = true; }
    require(overlap_rejected, "overlapping state intervals are rejected");
}

void test_features()
{
    using namespace ciphertracedroid;
    traffic::TrafficWindow window{.window_id = "s_0", .session_id = "s", .activity_state = "foreground", .start_time = 0.0, .end_time = 5.0,
                                  .packets = {packet(0.0, 100, traffic::Direction::outbound), packet(0.2, 50, traffic::Direction::inbound), packet(2.0, 25, traffic::Direction::unknown)}};
    features::SampleMetadata metadata;
    metadata.app_id = "app";
    metadata.run_id = "run";
    const auto sample = features::extract_features(window, metadata);
    const auto& row = sample.predictors;
    require(row.packet_count == 3 && row.total_ip_bytes == 175.0, "IP volume features");
    require(row.outbound_packet_fraction == 1.0 / 3.0 && row.inbound_packet_fraction == 1.0 / 3.0 && row.unknown_packet_fraction == 1.0 / 3.0, "bounded direction fractions");
    require(row.outbound_byte_fraction == 100.0 / 175.0 && row.unknown_ip_bytes == 25.0, "directional IP-byte features");
    require(features::has_finite_values(row), "finite predictor values");
    require(features::csv_header().find("feature_schema_version") == 0, "versioned CSV header");
    require(features::to_csv_row(sample).find("nan") == std::string::npos, "CSV does not contain NaN");
    traffic::TrafficWindow empty{.window_id = "empty", .session_id = "s", .activity_state = "background", .start_time = 0.0, .end_time = 5.0, .packets = {}};
    const auto empty_sample = features::extract_features(empty, metadata);
    require(empty_sample.predictors.packet_count == 0 && empty_sample.predictors.outbound_packet_fraction == 0.0 && features::has_finite_values(empty_sample.predictors), "zero-packet values are explicit and finite");
    auto non_finite = sample;
    non_finite.predictors.iat_mean = std::numeric_limits<double>::quiet_NaN();
    require(!features::has_finite_values(non_finite.predictors), "non-finite predictor is detected");
    bool non_finite_rejected = false;
    try { (void)features::to_csv_row(non_finite); }
    catch (const std::invalid_argument&) { non_finite_rejected = true; }
    require(non_finite_rejected, "non-finite predictor cannot be serialized");
    auto reversed = window;
    reversed.packets[1].timestamp_seconds = -1.0;
    bool reversed_rejected = false;
    try { (void)features::extract_features(reversed, metadata); }
    catch (const std::invalid_argument&) { reversed_rejected = true; }
    require(reversed_rejected, "timestamp reversal is rejected");
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
        auto ipv4_tcp = ethernet(0x0800); ipv4_tcp.resize(54); ipv4_tcp[14] = 0x45; ipv4_tcp[16] = 0; ipv4_tcp[17] = 40; ipv4_tcp[23] = 6; ipv4_tcp[26] = 192; ipv4_tcp[27] = 168; ipv4_tcp[28] = 1; ipv4_tcp[29] = 42; ipv4_tcp[30] = 8; ipv4_tcp[31] = 8; ipv4_tcp[32] = 8; ipv4_tcp[33] = 8; ipv4_tcp[34] = 0x01; ipv4_tcp[35] = 0xbb; ipv4_tcp[36] = 0x01; ipv4_tcp[37] = 0xbb;
        auto ipv4_udp = ethernet(0x0800); ipv4_udp.resize(42); ipv4_udp[14] = 0x45; ipv4_udp[16] = 0; ipv4_udp[17] = 28; ipv4_udp[23] = 17; ipv4_udp[26] = 8; ipv4_udp[27] = 8; ipv4_udp[28] = 4; ipv4_udp[29] = 4; ipv4_udp[30] = 192; ipv4_udp[31] = 168; ipv4_udp[32] = 1; ipv4_udp[33] = 42; ipv4_udp[34] = 0; ipv4_udp[35] = 53; ipv4_udp[36] = 0x13; ipv4_udp[37] = 0x88;
        auto ipv6_udp = ethernet(0x86dd); ipv6_udp.resize(62); ipv6_udp[14] = 0x60; ipv6_udp[18] = 0; ipv6_udp[19] = 8; ipv6_udp[20] = 17; ipv6_udp[22] = 0x20; ipv6_udp[23] = 0x01; ipv6_udp[38] = 0x20; ipv6_udp[39] = 0x01; ipv6_udp[54] = 0x13; ipv6_udp[55] = 0x88; ipv6_udp[56] = 0x01; ipv6_udp[57] = 0xbb;
        auto arp = ethernet(0x0806); arp.resize(42);
        write_packet(out, 10, ipv4_tcp); write_packet(out, 11, ipv4_udp); write_packet(out, 12, ipv6_udp); write_packet(out, 13, arp); write_packet(out, 14, std::vector<std::uint8_t>(10)); write_packet(out, 20, arp);
    }
    const auto capture = ciphertracedroid::capture::read_pcap(path.string(), "192.168.1.42");
    require(capture.summary.packet_count == 6 && capture.packets.size() == 3, "PCAP frame and valid-IP counts");
    require(capture.summary.ipv4_count == 2 && capture.summary.ipv6_count == 1, "IP version parsing");
    require(capture.packets[0].ip_packet_length == 40 && capture.packets[1].ip_packet_length == 28 && capture.packets[2].ip_packet_length == 48, "IP length excludes Ethernet framing");
    require(capture.summary.tcp_count == 1 && capture.summary.udp_count == 2, "transport parsing");
    require(capture.summary.non_ip_frame_count == 2 && capture.summary.malformed_packet_count == 1 && capture.summary.duration_seconds == 10.0, "non-IP and malformed frames remain in capture accounting");
    require(capture.packets.front().direction == ciphertracedroid::traffic::Direction::outbound, "explicit device direction");
    require(ciphertracedroid::capture::summary_to_json(capture.summary).find("\"packet_count\":6") != std::string::npos, "deterministic JSON summary");
    std::string path_text = path.string();
    char program[] = "ciphertracedroid";
    char inspect[] = "inspect";
    char format[] = "--format";
    char json[] = "json";
    char* arguments[] = {program, inspect, path_text.data(), format, json};
    require(ciphertracedroid::run(5, arguments) == 0, "inspect CLI accepts valid synthetic PCAP");
    const auto raw_path = std::filesystem::temp_directory_path() / "ciphertracedroid_synthetic_raw.pcap";
    {
        std::ofstream out(raw_path, std::ios::binary); require(out.good(), "create synthetic raw-IP PCAP");
        write_u32(out, 0xa1b2c3d4U); write_u16(out, 2); write_u16(out, 4); write_u32(out, 0); write_u32(out, 0); write_u32(out, 65535); write_u32(out, 12);
        std::vector<std::uint8_t> raw_ipv4(40); raw_ipv4[0] = 0x45; raw_ipv4[2] = 0; raw_ipv4[3] = 40; raw_ipv4[9] = 6; raw_ipv4[12] = 192; raw_ipv4[13] = 168; raw_ipv4[14] = 1; raw_ipv4[15] = 42; raw_ipv4[16] = 1; raw_ipv4[17] = 1; raw_ipv4[18] = 1; raw_ipv4[19] = 1; raw_ipv4[20] = 0x01; raw_ipv4[21] = 0xbb; raw_ipv4[22] = 0x01; raw_ipv4[23] = 0xbb;
        std::vector<std::uint8_t> later_fragment(28); later_fragment[0] = 0x45; later_fragment[2] = 0; later_fragment[3] = 28; later_fragment[6] = 0; later_fragment[7] = 1; later_fragment[9] = 17;
        std::vector<std::uint8_t> unknown_version(20); unknown_version[0] = 0x70;
        write_packet(out, 20, raw_ipv4); write_packet(out, 21, later_fragment); write_packet(out, 22, unknown_version);
    }
    const auto raw_capture = ciphertracedroid::capture::read_pcap(raw_path.string(), "192.168.1.42");
    require(raw_capture.summary.link_layer_type == 12 && raw_capture.summary.ipv4_count == 2 && raw_capture.summary.tcp_count == 1 && raw_capture.summary.udp_count == 1, "raw IP PCAP parsing");
    require(!raw_capture.packets[1].source_port.has_value() && !raw_capture.packets[1].destination_port.has_value(), "later IPv4 fragments do not expose transport ports");
    require(raw_capture.summary.unsupported_frame_count == 1, "unknown raw-IP version is accounted as unsupported");
    const auto manifest = path.parent_path() / "ciphertracedroid_synthetic_manifest.csv";
    const auto csv = path.parent_path() / "ciphertracedroid_synthetic_features.csv";
    { std::ofstream out(manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot\n" << "s1,app,r1,foreground," << path.filename().string() << ',' << ciphertracedroid::util::sha256_file(path) << ",routed_primary,0,10,true,false,false\n"; }
    const auto written = ciphertracedroid::features::export_features(manifest, csv, {.window_seconds = 5.0, .device_ip = "192.168.1.42"});
    require(written == 1, "manifest export omits an empty complete window");
    { std::ifstream input(csv); std::string header; std::string first_row; std::getline(input, header); std::getline(input, first_row); require(header == ciphertracedroid::features::csv_header() && first_row.find(",s1,app,r1,foreground,") != std::string::npos, "feature CSV provenance"); }
    const auto analysis_directory = path.parent_path() / "ciphertracedroid_condition_analysis_test";
    std::filesystem::remove_all(analysis_directory);
    const auto bundle = ciphertracedroid::analysis::write_condition_analysis_bundle(
        manifest, analysis_directory, "192.168.1.42");
    require(std::filesystem::is_regular_file(bundle / "complete-window-ledger.csv") &&
                std::filesystem::is_regular_file(bundle / "condition-profiles.csv") &&
                std::filesystem::is_regular_file(bundle / "checksums.sha256"),
            "condition analysis writes deterministic evidence artifacts");
    std::string validate_manifest_text = manifest.string();
    char validate_program[] = "ciphertracedroid";
    char validate_command[] = "validate-manifest";
    char* validate_arguments[] = {validate_program, validate_command, validate_manifest_text.data()};
    require(ciphertracedroid::run(3, validate_arguments) == 0, "manifest validation recomputes capture evidence");
    const auto out_of_range_manifest = path.parent_path() / "ciphertracedroid_out_of_range_manifest.csv";
    { std::ofstream out(out_of_range_manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot\n" << "s1,app,r1,foreground," << path.filename().string() << ',' << ciphertracedroid::util::sha256_file(path) << ",routed_primary,0,11,true,false,false\n"; }
    std::string out_of_range_manifest_text = out_of_range_manifest.string();
    char* out_of_range_arguments[] = {validate_program, validate_command, out_of_range_manifest_text.data()};
    require(ciphertracedroid::run(3, out_of_range_arguments) != 0, "manifest validation rejects intervals beyond capture coverage");
    bool analysis_overwrite_rejected = false;
    try {
        (void)ciphertracedroid::analysis::write_condition_analysis_bundle(
            manifest, analysis_directory, "192.168.1.42");
    } catch (const std::runtime_error&) { analysis_overwrite_rejected = true; }
    require(analysis_overwrite_rejected, "condition analysis refuses overwrite");
    std::filesystem::remove_all(analysis_directory);
    std::filesystem::remove(manifest); std::filesystem::remove(out_of_range_manifest); std::filesystem::remove(csv);
    std::filesystem::remove(path);
    std::filesystem::remove(raw_path);
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
    { std::ofstream out(manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot\n" << "s1,app,r1,foreground,capture.pcap," << hash << ",routed_primary,0,10,true,false,false\n"; }
    const auto rows = ciphertracedroid::experiments::read_session_manifest(manifest);
    require(rows.size() == 1 && rows[0].capture_file == capture && rows[0].include, "strict manifest parsing");
    const auto overlap_manifest = directory / "overlap.csv";
    { std::ofstream out(overlap_manifest); out << "session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot\n" << "s1,app,r1,foreground,capture.pcap," << hash << ",routed_primary,0,10,true,false,false\n" << "s2,app,r1,background,capture.pcap," << hash << ",routed_primary,5,11,true,false,false\n"; }
    bool overlap_rejected = false;
    try { ciphertracedroid::experiments::validate_session_manifest_integrity(ciphertracedroid::experiments::read_session_manifest(overlap_manifest)); }
    catch (const std::runtime_error&) { overlap_rejected = true; }
    require(overlap_rejected, "manifest integrity rejects overlapping capture intervals");
    bool stale_hash_rejected = false;
    std::ofstream mutate(capture, std::ios::app | std::ios::binary); mutate << "changed"; mutate.close();
    try { ciphertracedroid::experiments::validate_session_manifest_integrity(rows); }
    catch (const std::runtime_error&) { stale_hash_rejected = true; }
    require(stale_hash_rejected, "manifest integrity rejects a changed capture");
    std::filesystem::remove_all(directory);
}

void test_grouped_partitioning()
{
    using ciphertracedroid::experiments::SampleMetadata;
    const std::vector<SampleMetadata> samples{{"w1", "s1", "r1", "a", "foreground"}, {"w2", "s1", "r1", "a", "background"}, {"w3", "s2", "r2", "a", "foreground"}};
    const auto partition = ciphertracedroid::experiments::partition_by_run(samples, {"r2"});
    require(partition.training_indices == std::vector<std::size_t>{0, 1} && partition.test_indices == std::vector<std::size_t>{2}, "all windows from a run stay together");
}

void test_capture_source_and_experiment_pipeline()
{
    using namespace ciphertracedroid;
    experiments::require_source_for_primary_experiment(experiments::CaptureSourceKind::routed_primary);
    bool auxiliary_rejected = false;
    try { experiments::require_source_for_primary_experiment(experiments::CaptureSourceKind::pcapdroid_auxiliary); }
    catch (const std::invalid_argument&) { auxiliary_rejected = true; }
    require(auxiliary_rejected, "PCAPdroid auxiliary source is rejected for primary experiments");
    features::DatasetSample synthetic;
    synthetic.metadata.capture_source = experiments::CaptureSourceKind::synthetic_fixture;
    synthetic.metadata.synthetic_test_only = true;
    bool publication_rejected = false;
    try { experiments::validate_capture_sources({synthetic}, false, true, false); }
    catch (const std::invalid_argument&) { publication_rejected = true; }
    require(publication_rejected, "synthetic source is rejected for publication-primary use");
    bool leaked = false;
    try { experiments::validate_no_run_leakage({"run1", "run2"}, {"run2"}); }
    catch (const std::invalid_argument&) { leaked = true; }
    require(leaked, "run leakage fails explicitly");
    const auto report = experiments::calculate_metrics({"a", "a", "b", "b"}, {"a", "b", "b", "b"});
    require(report.accuracy == 0.75 && report.confusion_matrix.size() == 2, "multiclass metrics match hand calculation");
    const auto result = experiments::run_synthetic_six_condition_experiment();
    require(result.conditions.size() == 6, "all six synthetic conditions execute");
    const std::vector<std::string> expected_conditions{"FG_to_FG", "FG_to_BG", "BG_to_BG", "BG_to_FG", "Mixed_to_FG", "Mixed_to_BG"};
    for (std::size_t index = 0; index < expected_conditions.size(); ++index) {
        require(experiments::to_string(result.conditions[index].specification.condition) == expected_conditions[index], "six-condition order is deterministic");
    }
    const auto predictor_columns = features::predictor_names();
    for (const std::string prohibited : {"app_id", "run_id", "activity_state", "capture_source", "package", "uid"}) {
        require(std::find(predictor_columns.begin(), predictor_columns.end(), prohibited) == predictor_columns.end(), "metadata is absent from predictor schema");
    }
    for (const auto& condition : result.conditions) {
        require(!condition.predictions.empty(), "each condition emits predictions");
        experiments::validate_no_run_leakage(condition.training_run_ids, condition.test_run_ids);
        require(condition.predictions.front().capture_source == experiments::CaptureSourceKind::synthetic_fixture, "capture source survives into predictions");
    }
    const auto root = std::filesystem::temp_directory_path() / "ciphertracedroid_evidence_test";
    std::filesystem::remove_all(root);
    const auto bundle = experiments::write_synthetic_evidence_bundle(result, root, "synthetic-contract-test");
    require(std::filesystem::is_regular_file(bundle / "checksums.sha256"), "evidence bundle is finalized with checksums");
    bool overwrite_rejected = false;
    try { (void)experiments::write_synthetic_evidence_bundle(result, root, "synthetic-contract-test"); }
    catch (const std::runtime_error&) { overwrite_rejected = true; }
    require(overwrite_rejected, "evidence bundle refuses overwrite");
    std::filesystem::remove_all(root);
}

void test_adb_device_parser()
{
    const auto devices = ciphertracedroid::device::AdbClient::parse_devices(
        "List of devices attached\n"
        "ABC123\tdevice product:fogo model:moto_g device:fogo transport_id:1\n"
        "DEF456\tunauthorized usb:1-1\n"
        "\n");
    require(devices.size() == 2, "ADB parser reads device records");
    require(devices[0].serial == "ABC123" && devices[0].state == "device", "ADB parser reads authorized device state");
    require(devices[1].serial == "DEF456" && devices[1].state == "unauthorized", "ADB parser reads unauthorized device state");
}

void test_activity_event_parser()
{
    const auto events = ciphertracedroid::device::AdbClient::parse_activity_events(
        "time=\"2026-08-13 10:00:00\" type=ACTIVITY_RESUMED package=com.example.app class=com.example.app.MainActivity flags=0x0\n"
        "time=\"2026-08-13 10:00:01\" type=ACTIVITY_PAUSED package=com.example.app class=com.example.app.MainActivity flags=0x0\n"
        "time=\"2026-08-13 10:00:02\" type=STANDBY_BUCKET_CHANGED package=com.example.app flags=0x0\n"
        "time=\"2026-08-13 10:00:03\" type=ACTIVITY_STOPPED package=com.other.app class=com.other.app.Main flags=0x0\n",
        "com.example.app");
    require(events.size() == 2, "usage-event parser keeps only requested activity events");
    require(events[0].timestamp == "2026-08-13 10:00:00" && events[0].type == "ACTIVITY_RESUMED" && events[0].activity_class == "com.example.app.MainActivity", "usage-event parser extracts lifecycle evidence");
}

void test_pcapdroid_request_contract()
{
    using namespace ciphertracedroid::device;
    const std::string fake_secret = "FAKE_TEST_SECRET_7f21";
    Secret secret(fake_secret);
    const PcapdroidPilotConfig config{"SERIAL123", "com.android.chrome", "unique-pilot-001.pcap"};
    const auto start = PcapdroidController::start_arguments(config, secret);
    require(std::find(start.begin(), start.end(), fake_secret) != start.end(), "API key reaches the required Intent argument boundary");
    const auto redacted = PcapdroidController::redacted_arguments(start);
    require(std::find(redacted.begin(), redacted.end(), fake_secret) == redacted.end(), "redacted command never contains the fake API key");
    require(std::find(redacted.begin(), redacted.end(), "[REDACTED]") != redacted.end(), "API key location is visibly redacted");
    const auto pull = PcapdroidController::pull_arguments(config, "/tmp/pilot-copy.pcap");
    require(pull.back() == "/tmp/pilot-copy.pcap", "artifact pull uses a structured destination argument");
    bool unsafe_name_rejected = false;
    try { (void)PcapdroidController::start_arguments({"SERIAL123", "com.android.chrome", "../replace.pcap"}, secret); }
    catch (const std::invalid_argument&) { unsafe_name_rejected = true; }
    require(unsafe_name_rejected, "unsafe or non-unique-looking artifact path is rejected");
}

void test_session_plan_guards()
{
    bool rejected_package = false;
    try { ciphertracedroid::experiments::write_session_plan({"not a package", "unused.json"}); }
    catch (const std::invalid_argument&) { rejected_package = true; }
    require(rejected_package, "session plan rejects invalid package names before ADB access");

    const auto path = std::filesystem::temp_directory_path() / "ciphertracedroid_existing_plan.json";
    { std::ofstream output(path); output << "preserve"; }
    bool rejected_overwrite = false;
    try { ciphertracedroid::experiments::write_session_plan({"com.android.chrome", path}); }
    catch (const std::runtime_error&) { rejected_overwrite = true; }
    std::filesystem::remove(path);
    require(rejected_overwrite, "session plan refuses an existing output file before ADB access");
}

ciphertracedroid::device::PackageStateObservation state_observation(
    const std::string& resumed, bool shade = false, bool interactive = true,
    bool locked = false)
{
    return {.package_name = "com.android.chrome",
            .top_activity = resumed,
            .focused_app = resumed,
            .current_focus = shade ? "NotificationShade" : resumed,
            .process_running = true,
            .top_activity_matches_package = resumed.find("com.android.chrome") != std::string::npos,
            .notification_shade_active = shade,
            .screen_interactive = interactive,
            .device_locked = locked};
}

void test_android_state_stabilizer_and_manifest_gate()
{
    using namespace ciphertracedroid;
    const device::AndroidStatePolicy policy{
        "com.android.chrome", "com.motorola.launcher3",
        {"CustomizationPanelLauncher", "QuickstepLauncher"}};
    const auto chrome = state_observation("ResumedActivity: com.android.chrome/.Main");
    const auto launcher = state_observation(
        "ResumedActivity: com.motorola.launcher3/com.android.launcher3.CustomizationPanelLauncher");
    const auto transient = state_observation(
        "ResumedActivity: com.motorola.launcher3/.LauncherTransition");
    require(device::classify_android_state(chrome, policy) == device::AndroidUiState::target_app_resumed,
            "target resumed classification");
    require(device::classify_android_state(launcher, policy) == device::AndroidUiState::launcher_environment,
            "normal launcher classification");
    require(device::classify_android_state(transient, policy) == device::AndroidUiState::launcher_owned_transient,
            "launcher transient classification");

    device::BackgroundStabilizer passing(policy);
    for (int second = 0; second <= 15; ++second) {
        const auto& observation = second == 4 ? transient : launcher;
        (void)passing.observe(static_cast<double>(second), observation);
    }
    const auto pass = passing.finish();
    require(pass.passed && pass.observations.size() == 16 &&
                pass.final_state == device::AndroidUiState::launcher_environment,
            "launcher and permitted transient pass after full duration");

    device::BackgroundStabilizer resumed(policy);
    (void)resumed.observe(0.0, launcher);
    const auto resumed_result = resumed.observe(1.0, chrome);
    require(resumed_result && !resumed_result->passed, "target resumption fails immediately");

    for (const auto& unsafe : {
             state_observation("ResumedActivity: com.android.systemui/.Shade", true),
             state_observation("ResumedActivity: com.motorola.launcher3/.Launcher", false, false, true),
             state_observation("unknown"),
             state_observation("ResumedActivity: com.android.settings/.Settings")}) {
        device::BackgroundStabilizer stabilizer(policy);
        const auto result = stabilizer.observe(0.0, unsafe);
        require(result && !result->passed, "unsafe or uncertain state fails immediately");
    }

    experiments::SessionManifestRow background;
    background.state = experiments::ActivityState::background;
    experiments::ManifestBuilder builder;
    bool missing_gate_rejected = false;
    try { builder.add_interval(background); }
    catch (const std::invalid_argument&) { missing_gate_rejected = true; }
    require(missing_gate_rejected, "coordinator cannot add background without a gate");
    builder.add_interval(background, pass);
    require(builder.rows().size() == 1, "passing gate authorizes one background interval");
}

void test_input_diagnostics()
{
    using namespace ciphertracedroid::device;
    const auto quiet = summarize_getevent("");
    require(quiet.kind == InputEvidenceKind::unavailable, "unavailable input stream remains explicit");
    const auto touch = summarize_getevent("[ 1.0] /dev/input/event8: EV_KEY BTN_TOUCH DOWN\n");
    require(touch.kind == InputEvidenceKind::touch_contact, "touch contact is classified");
    const auto key = summarize_getevent("[ 1.0] /dev/input/event11: EV_KEY KEY_HOME DOWN\n");
    require(key.kind == InputEvidenceKind::key_event, "key event is classified");
    require(classify_state_gate_failure(true, touch, true, true) == StateGateFailureCause::launcher_shortcut_activation,
            "aligned touch has a distinct failure cause");
    require(classify_state_gate_failure(true, quiet, false, true) == StateGateFailureCause::task_transition_unattributed,
            "unattributed task return remains explicit");
}

void test_complete_window_analysis()
{
    using namespace ciphertracedroid;
    experiments::SessionManifestRow row;
    row.session_id = "session";
    row.run_id = "run";
    row.app_id = "app";
    row.state = experiments::ActivityState::background;
    row.capture_source = experiments::CaptureSourceKind::pcapdroid_auxiliary;
    row.start_offset_seconds = 0.0;
    row.end_offset_seconds = 15.0;
    const std::vector<traffic::PacketRecord> packets{
        packet(1.0, 100, traffic::Direction::outbound),
        packet(11.0, 200, traffic::Direction::inbound)};
    const auto result = analysis::analyze_condition(row, packets, 5.0);
    require(result.windows.size() == 3, "ledger retains every complete window");
    require(result.windows[1].status == analysis::WindowObservationStatus::observed_empty &&
                !result.windows[1].schema_v1_features.has_value(),
            "empty window is explicit and packet statistics are unavailable");
    require(result.occupancy.nonempty_window_count == 2 &&
                result.occupancy.empty_window_count == 1 &&
                result.occupancy.longest_quiet_duration_seconds == 5.0,
            "occupancy metrics include quiet windows");
    require(result.profile.predictors.total_ip_packets == 2.0 &&
                result.profile.predictors.total_ip_bytes == 300.0 &&
                result.profile.predictors.aggregate_packet_features.has_value(),
            "condition profile summarizes the full independent condition");
    for (const auto& prohibited : {"app_id", "condition", "run_id", "capture_source", "package"}) {
        const auto names = analysis::condition_profile_predictor_names();
        require(std::find(names.begin(), names.end(), prohibited) == names.end(),
                "profile predictors exclude metadata and labels");
    }

    auto empty_row = row;
    empty_row.end_offset_seconds = 10.0;
    const auto empty = analysis::analyze_condition(empty_row, {}, 5.0);
    require(empty.windows.size() == 2 && empty.occupancy.empty_window_count == 2,
            "fully quiet condition preserves scheduled windows");
    require(!empty.profile.predictors.aggregate_packet_features.has_value() &&
                empty.profile.predictors.total_ip_packets == 0.0,
            "undefined empty-condition packet statistics remain unavailable");
}

}  // namespace

int main()
{
    try { test_direction_assignment(); test_state_boundaries(); test_features(); test_pcap_reader(); test_manifest_and_hash(); test_grouped_partitioning(); test_capture_source_and_experiment_pipeline(); test_adb_device_parser(); test_activity_event_parser(); test_pcapdroid_request_contract(); test_session_plan_guards(); test_android_state_stabilizer_and_manifest_gate(); test_input_diagnostics(); test_complete_window_analysis(); }
    catch (const std::exception& error) { std::cerr << "test failure: " << error.what() << '\n'; return EXIT_FAILURE; }
    return EXIT_SUCCESS;
}
