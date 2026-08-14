#include "ciphertracedroid/experiments/session_plan.hpp"

#include "ciphertracedroid/device/adb_client.hpp"
#include "ciphertracedroid/util/logging.hpp"

#include <chrono>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace ciphertracedroid::experiments {
namespace {

bool valid_package_name(const std::string& value)
{
    if (value.empty() || value.size() > 255 || value.front() == '.' || value.back() == '.') return false;
    bool has_dot = false;
    for (const unsigned char character : value) {
        if (character == '.') { has_dot = true; continue; }
        if (!std::isalnum(character) && character != '_') return false;
    }
    return has_dot;
}

std::string json_escape(const std::string& value)
{
    std::ostringstream escaped;
    for (const unsigned char character : value) {
        switch (character) {
        case '\\': escaped << "\\\\"; break;
        case '"': escaped << "\\\""; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (character < 0x20) escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(character) << std::dec << std::setfill(' ');
            else escaped << static_cast<char>(character);
        }
    }
    return escaped.str();
}

std::string utc_now()
{
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

void field(std::ostream& out, const char* name, const std::string& value, bool trailing_comma = true)
{
    out << "    \"" << name << "\": \"" << json_escape(value) << "\"" << (trailing_comma ? "," : "") << "\n";
}

}  // namespace

void write_session_plan(const SessionPlanOptions& options)
{
    if (!valid_package_name(options.package_name)) throw std::invalid_argument("package name must contain dot-separated Android package segments");
    if (options.output_file.empty()) throw std::invalid_argument("session-plan output path is required");
    if (std::filesystem::exists(options.output_file)) throw std::runtime_error("refusing to overwrite existing session-plan file: " + options.output_file.string());
    if (!options.output_file.parent_path().empty() && !std::filesystem::exists(options.output_file.parent_path())) {
        throw std::runtime_error("session-plan parent directory does not exist: " + options.output_file.parent_path().string());
    }

    device::AdbClient adb;
    const auto readiness = adb.inspect_single_device();
    const auto package = adb.inspect_package(readiness.device.serial, options.package_name);
    const auto top_activity = adb.current_top_activity(readiness.device.serial);
    util::debug_log("session-plan", "writing a read-only collection plan");

    std::ofstream out(options.output_file, std::ios::binary | std::ios::out);
    if (!out.good()) throw std::runtime_error("could not create session-plan file: " + options.output_file.string());
    out << "{\n";
    field(out, "schema_version", "1");
    field(out, "created_at_utc", utc_now());
    field(out, "package_name", package.name);
    field(out, "package_version_name", package.version_name);
    field(out, "package_version_code", package.version_code);
    field(out, "device_manufacturer", readiness.manufacturer);
    field(out, "device_model", readiness.model);
    field(out, "android_release", readiness.android_release);
    field(out, "android_api_level", readiness.api_level);
    field(out, "device_clock_offset_seconds", std::to_string(readiness.clock_offset_seconds));
    field(out, "adb_shell_uid", readiness.shell_uid);
    field(out, "on_device_tcpdump", readiness.tcpdump_available ? "available" : "not_available");
    field(out, "pcapdroid", readiness.pcapdroid_available ? readiness.pcapdroid_version : "not_installed");
    field(out, "vpn_active", readiness.vpn_active ? "true" : "false");
    field(out, "network_route", readiness.network_route);
    field(out, "top_activity_before_run", top_activity);
    field(out, "capture_vantage", "unvalidated");
    out << "    \"collection_gates\": [\n"
        << "      \"Validate that the chosen capture interface observes the controlled device traffic.\",\n"
        << "      \"Record host UTC boundaries and state verification for foreground and background intervals.\",\n"
        << "      \"Hash the finalized PCAP and add it to the strict session manifest.\"\n"
        << "    ],\n"
        << "    \"device_actions_performed\": []\n"
        << "}\n";
    if (!out.good()) throw std::runtime_error("could not finish session-plan file: " + options.output_file.string());
}

}  // namespace ciphertracedroid::experiments
