#include "ciphertracedroid/device/pcapdroid_controller.hpp"

#include <algorithm>
#include <cstdlib>
#include <regex>
#include <stdexcept>
#include <utility>

namespace ciphertracedroid::device {
namespace {

constexpr const char* kComponent =
    "com.emanuelef.remote_capture/.activities.CaptureCtrl";

void validate_serial(const std::string& serial)
{
    if (serial.empty() || serial.find_first_of(" \t\r\n") != std::string::npos) {
        throw std::invalid_argument("ADB serial is empty or contains whitespace");
    }
}

void validate_config(const PcapdroidPilotConfig& config)
{
    validate_serial(config.serial);
    static const std::regex package_pattern{R"(^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$)"};
    static const std::regex name_pattern{R"(^[A-Za-z0-9][A-Za-z0-9_.-]*\.pcap$)"};
    if (!std::regex_match(config.package_name, package_pattern)) {
        throw std::invalid_argument("invalid Android package name for PCAPdroid filter");
    }
    if (!std::regex_match(config.pcap_name, name_pattern) || config.pcap_name.find("..") != std::string::npos) {
        throw std::invalid_argument("PCAPdroid artifact name must be a simple unique .pcap filename");
    }
}

std::vector<std::string> base(const std::string& serial)
{
    validate_serial(serial);
    return {"adb", "-s", serial, "shell", "am", "start", "-W", "-a",
            "android.intent.action.VIEW"};
}

void add_string(std::vector<std::string>& arguments, const std::string& key,
                const std::string& value)
{
    arguments.insert(arguments.end(), {"--es", key, value});
}

void add_boolean(std::vector<std::string>& arguments, const std::string& key, bool value)
{
    arguments.insert(arguments.end(), {"--ez", key, value ? "true" : "false"});
}

}  // namespace

Secret::Secret(std::string value) : value_(std::move(value))
{
    if (value_.empty()) throw std::invalid_argument("PCAPdroid API key is empty");
}

Secret::~Secret() { clear(); }

Secret::Secret(Secret&& other) noexcept : value_(std::move(other.value_)) { other.clear(); }

Secret& Secret::operator=(Secret&& other) noexcept
{
    if (this != &other) {
        clear();
        value_ = std::move(other.value_);
        other.clear();
    }
    return *this;
}

void Secret::clear() noexcept
{
    volatile char* bytes = value_.empty() ? nullptr : value_.data();
    for (std::size_t index = 0; index < value_.size(); ++index) bytes[index] = '\0';
    value_.clear();
}

Secret Secret::from_environment()
{
    const char* value = std::getenv("CIPHERTRACEDROID_PCAPDROID_API_KEY");
    if (value == nullptr || *value == '\0') {
        throw std::runtime_error("PCAPdroid API key is unavailable in the runtime environment");
    }
    return Secret(value);
}

std::vector<std::string> PcapdroidController::status_arguments(const std::string& serial)
{
    auto arguments = base(serial);
    add_string(arguments, "action", "get_status");
    arguments.insert(arguments.end(), {"-n", kComponent});
    return arguments;
}

std::vector<std::string> PcapdroidController::start_arguments(
    const PcapdroidPilotConfig& config, const Secret& api_key)
{
    validate_config(config);
    auto arguments = base(config.serial);
    add_string(arguments, "action", "start");
    add_string(arguments, "api_key", api_key.value());
    add_string(arguments, "pcap_dump_mode", "pcap_file");
    add_string(arguments, "pcap_name", config.pcap_name);
    add_string(arguments, "app_filter", config.package_name);
    add_boolean(arguments, "tls_decryption", false);
    add_boolean(arguments, "full_payload", false);
    add_boolean(arguments, "pcapng_format", false);
    add_string(arguments, "block_quic", "never");
    arguments.insert(arguments.end(), {"-n", kComponent});
    return arguments;
}

std::vector<std::string> PcapdroidController::stop_arguments(const std::string& serial,
                                                             const Secret& api_key)
{
    auto arguments = base(serial);
    add_string(arguments, "action", "stop");
    add_string(arguments, "api_key", api_key.value());
    arguments.insert(arguments.end(), {"-n", kComponent});
    return arguments;
}

std::vector<std::string> PcapdroidController::pull_arguments(
    const PcapdroidPilotConfig& config, const std::filesystem::path& local_path)
{
    validate_config(config);
    if (local_path.empty()) throw std::invalid_argument("local PCAP path is empty");
    return {"adb", "-s", config.serial, "pull",
            "/sdcard/Download/PCAPdroid/" + config.pcap_name, local_path.string()};
}

std::vector<std::string> PcapdroidController::redacted_arguments(
    const std::vector<std::string>& arguments)
{
    auto redacted = arguments;
    for (std::size_t index = 0; index + 2 < redacted.size(); ++index) {
        if ((redacted[index] == "--es" || redacted[index] == "-e") &&
            redacted[index + 1] == "api_key") {
            redacted[index + 2] = "[REDACTED]";
        }
    }
    return redacted;
}

}  // namespace ciphertracedroid::device
