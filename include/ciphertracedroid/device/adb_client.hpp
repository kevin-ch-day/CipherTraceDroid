#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ciphertracedroid::device {

struct AndroidDevice {
    std::string serial;
    std::string state;
    std::string description;
};

struct DeviceReadiness {
    AndroidDevice device;
    std::string manufacturer;
    std::string model;
    std::string android_release;
    std::string api_level;
    std::string network_route;
    std::string shell_uid;
    bool tcpdump_available{};
    bool screen_interactive{};
    bool device_locked{};
    long long clock_offset_seconds{};
    bool pcapdroid_available{};
    std::string pcapdroid_version;
    bool vpn_active{};
};

struct AndroidPackage {
    std::string name;
    std::string version_name;
    std::string version_code;
};

struct PackageStateObservation {
    std::string package_name;
    std::string top_activity;
    std::string focused_app;
    std::string current_focus;
    bool process_running{};
    bool top_activity_matches_package{};
    bool notification_shade_active{};
    bool screen_interactive{};
    bool device_locked{};
};

struct ActivityLifecycleEvent {
    std::string timestamp;
    std::string type;
    std::string activity_class;
};

class AdbClient {
public:
    [[nodiscard]] std::vector<AndroidDevice> list_devices() const;
    [[nodiscard]] DeviceReadiness inspect_single_device() const;
    [[nodiscard]] AndroidPackage inspect_package(const std::string& serial, const std::string& package_name) const;
    [[nodiscard]] std::string current_top_activity(const std::string& serial) const;
    [[nodiscard]] std::string resolved_home_activity(const std::string& serial) const;
    [[nodiscard]] PackageStateObservation observe_package_state(const std::string& serial, const std::string& package_name) const;
    [[nodiscard]] long long measure_clock_offset_seconds(const std::string& serial) const;
    [[nodiscard]] std::vector<ActivityLifecycleEvent> recent_activity_events(const std::string& serial, const std::string& package_name, std::size_t limit = 12) const;
    void launch_package(const std::string& serial, const std::string& package_name) const;
    void send_home(const std::string& serial) const;
    void collapse_system_ui(const std::string& serial) const;
    [[nodiscard]] static std::vector<AndroidDevice> parse_devices(const std::string& output);
    [[nodiscard]] static std::vector<ActivityLifecycleEvent> parse_activity_events(const std::string& output, const std::string& package_name);
};

}  // namespace ciphertracedroid::device
