#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace ciphertracedroid::device {

class Secret {
public:
    explicit Secret(std::string value);
    ~Secret();
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept;
    Secret& operator=(Secret&& other) noexcept;

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] static Secret from_environment();

private:
    void clear() noexcept;
    std::string value_;
};

struct PcapdroidPilotConfig {
    std::string serial;
    std::string package_name;
    std::string pcap_name;
};

class PcapdroidController {
public:
    [[nodiscard]] static std::vector<std::string> status_arguments(const std::string& serial);
    [[nodiscard]] static std::vector<std::string> start_arguments(
        const PcapdroidPilotConfig& config, const Secret& api_key);
    [[nodiscard]] static std::vector<std::string> stop_arguments(
        const std::string& serial, const Secret& api_key);
    [[nodiscard]] static std::vector<std::string> pull_arguments(
        const PcapdroidPilotConfig& config, const std::filesystem::path& local_path);
    [[nodiscard]] static std::vector<std::string> redacted_arguments(
        const std::vector<std::string>& arguments);
};

}  // namespace ciphertracedroid::device
