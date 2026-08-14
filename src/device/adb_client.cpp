#include "ciphertracedroid/device/adb_client.hpp"
#include "ciphertracedroid/util/logging.hpp"

#include <array>
#include <chrono>
#include <stdexcept>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

namespace ciphertracedroid::device {
namespace {

std::string trim(std::string value)
{
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ')) value.pop_back();
    const auto first = value.find_first_not_of(" \t\r\n");
    return first == std::string::npos ? "" : value.substr(first);
}

std::string one_line(std::string value)
{
    for (auto& character : value) {
        if (character == '\n' || character == '\r' || character == '\t') character = ' ';
    }
    return trim(value);
}

bool contains(const std::string& text, std::string_view value)
{
    return text.find(value) != std::string::npos;
}

std::string run_process(const std::vector<std::string>& arguments)
{
    int pipe_fds[2]{};
    if (pipe(pipe_fds) != 0) throw std::runtime_error("could not create ADB output pipe");
    const pid_t process = fork();
    if (process < 0) {
        close(pipe_fds[0]); close(pipe_fds[1]);
        throw std::runtime_error("could not start ADB process");
    }
    if (process == 0) {
        dup2(pipe_fds[1], STDOUT_FILENO); dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[0]); close(pipe_fds[1]);
        std::vector<char*> raw; raw.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) raw.push_back(const_cast<char*>(argument.c_str()));
        raw.push_back(nullptr); execvp(raw.front(), raw.data()); _exit(127);
    }
    close(pipe_fds[1]); std::string output; std::array<char, 4096> buffer{}; ssize_t count = 0;
    while ((count = read(pipe_fds[0], buffer.data(), buffer.size())) > 0) output.append(buffer.data(), static_cast<std::size_t>(count));
    close(pipe_fds[0]); int status = 0; waitpid(process, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) throw std::runtime_error("ADB command failed: " + trim(output));
    return trim(output);
}

std::string shell(const std::string& serial, const std::vector<std::string>& command)
{
    std::vector<std::string> arguments{"adb", "-s", serial, "shell"};
    arguments.insert(arguments.end(), command.begin(), command.end());
    return run_process(arguments);
}

std::string property_value(const std::string& text, std::string_view key)
{
    const auto position = text.find(key);
    if (position == std::string::npos) return "unknown";
    const auto value_start = position + key.size();
    const auto value_end = text.find_first_of(" \t\r\n", value_start);
    return text.substr(value_start, value_end - value_start);
}

std::string matching_line(const std::string& text, std::string_view marker)
{
    const auto marker_position = text.find(marker);
    if (marker_position == std::string::npos) return "unknown";
    const auto line_start = text.rfind('\n', marker_position);
    const auto line_end = text.find('\n', marker_position);
    return trim(text.substr(line_start == std::string::npos ? 0 : line_start + 1,
                            line_end - (line_start == std::string::npos ? 0 : line_start + 1)));
}

std::string quoted_value(const std::string& text, std::string_view key)
{
    const auto start = text.find(key);
    if (start == std::string::npos) return "";
    const auto value_start = start + key.size();
    const auto value_end = text.find('"', value_start);
    return value_end == std::string::npos ? "" : text.substr(value_start, value_end - value_start);
}

}  // namespace

std::vector<AndroidDevice> AdbClient::parse_devices(const std::string& output)
{
    std::vector<AndroidDevice> devices; std::size_t start = 0;
    while (start < output.size()) {
        const auto end = output.find('\n', start); const auto line = output.substr(start, end - start);
        if (!line.empty() && line.rfind("List of devices", 0) != 0) {
            const auto separator = line.find_first_of("\t ");
            if (separator != std::string::npos) {
                const auto state_start = line.find_first_not_of("\t ", separator);
                if (state_start != std::string::npos) {
                    const auto state_end = line.find_first_of("\t ", state_start);
                    devices.push_back({line.substr(0, separator), line.substr(state_start, state_end - state_start), state_end == std::string::npos ? "" : trim(line.substr(state_end))});
                }
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return devices;
}

std::vector<ActivityLifecycleEvent> AdbClient::parse_activity_events(const std::string& output, const std::string& package_name)
{
    std::vector<ActivityLifecycleEvent> events;
    const std::string package_marker = "package=" + package_name + " ";
    std::size_t start = 0;
    while (start < output.size()) {
        const auto end = output.find('\n', start);
        const auto line = output.substr(start, end - start);
        if (line.find(package_marker) != std::string::npos) {
            const auto type_start = line.find("type=");
            if (type_start != std::string::npos) {
                const auto type_end = line.find(' ', type_start);
                const auto type = line.substr(type_start + 5, type_end - (type_start + 5));
                if (type == "ACTIVITY_RESUMED" || type == "ACTIVITY_PAUSED" || type == "ACTIVITY_STOPPED") {
                    events.push_back({quoted_value(line, "time=\""), type, property_value(line, "class=")});
                }
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return events;
}

std::vector<AndroidDevice> AdbClient::list_devices() const { return parse_devices(run_process({"adb", "devices", "-l"})); }

DeviceReadiness AdbClient::inspect_single_device() const
{
    const auto devices = list_devices();
    if (devices.size() != 1 || devices.front().state != "device") throw std::runtime_error("exactly one authorized ADB device is required");
    util::debug_log("device", "inspecting one authorized ADB device");
    const auto& device = devices.front();
    bool tcpdump_available = false;
    try { tcpdump_available = !shell(device.serial, {"which", "tcpdump"}).empty(); }
    catch (const std::exception&) { }
    const auto power = shell(device.serial, {"dumpsys", "power"});
    const auto trust = shell(device.serial, {"dumpsys", "trust"});
    const auto clock_offset = measure_clock_offset_seconds(device.serial);
    bool pcapdroid_available = false;
    std::string pcapdroid_version = "not installed";
    try {
        const auto pcapdroid = inspect_package(device.serial, "com.emanuelef.remote_capture");
        pcapdroid_available = true;
        pcapdroid_version = pcapdroid.version_name;
    } catch (const std::exception&) { }
    const auto connectivity = shell(device.serial, {"dumpsys", "connectivity"});
    return {device, shell(device.serial, {"getprop", "ro.product.manufacturer"}), shell(device.serial, {"getprop", "ro.product.model"}), shell(device.serial, {"getprop", "ro.build.version.release"}), shell(device.serial, {"getprop", "ro.build.version.sdk"}), one_line(shell(device.serial, {"ip", "route", "get", "1.1.1.1"})), shell(device.serial, {"id", "-u"}), tcpdump_available,
            contains(power, "mWakefulness=Awake"), contains(trust, "deviceLocked=1"), clock_offset,
            pcapdroid_available, pcapdroid_version, contains(connectivity, "ni{VPN CONNECTED")};
}

long long AdbClient::measure_clock_offset_seconds(const std::string& serial) const
{
    const auto before = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    const auto device_epoch = std::stoll(shell(serial, {"date", "+%s"}));
    const auto after = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    return device_epoch - ((before + after) / 2);
}

AndroidPackage AdbClient::inspect_package(const std::string& serial, const std::string& package_name) const
{
    const auto path = shell(serial, {"pm", "path", package_name});
    if (path.rfind("package:", 0) != 0) throw std::runtime_error("package is not installed: " + package_name);
    const auto details = shell(serial, {"dumpsys", "package", package_name});
    return {package_name, property_value(details, "versionName="), property_value(details, "versionCode=")};
}

std::string AdbClient::current_top_activity(const std::string& serial) const
{
    const auto activity = shell(serial, {"dumpsys", "activity", "activities"});
    const auto resumed = matching_line(activity, "ResumedActivity:");
    if (resumed != "unknown") return resumed;
    return matching_line(activity, "mResumedActivity:");
}

std::string AdbClient::resolved_home_activity(const std::string& serial) const
{
    const auto output = shell(serial, {"cmd", "package", "resolve-activity", "--brief",
                                       "-a", "android.intent.action.MAIN", "-c",
                                       "android.intent.category.HOME"});
    const auto line_start = output.rfind('\n');
    return trim(output.substr(line_start == std::string::npos ? 0 : line_start + 1));
}

PackageStateObservation AdbClient::observe_package_state(const std::string& serial, const std::string& package_name) const
{
    const auto top_activity = current_top_activity(serial);
    const auto windows = shell(serial, {"dumpsys", "window"});
    const auto power = shell(serial, {"dumpsys", "power"});
    const auto trust = shell(serial, {"dumpsys", "trust"});
    const auto current_focus = matching_line(windows, "mCurrentFocus=");
    bool process_running = false;
    try { process_running = !shell(serial, {"pidof", package_name}).empty(); }
    catch (const std::exception&) { }
    return {package_name, top_activity, matching_line(windows, "mFocusedApp="), current_focus,
            process_running, top_activity.find(package_name) != std::string::npos,
            current_focus.find("NotificationShade") != std::string::npos,
            contains(power, "mWakefulness=Awake"), contains(trust, "deviceLocked=1")};
}

std::vector<ActivityLifecycleEvent> AdbClient::recent_activity_events(const std::string& serial, const std::string& package_name, std::size_t limit) const
{
    auto events = parse_activity_events(shell(serial, {"dumpsys", "usagestats"}), package_name);
    if (events.size() > limit) events.erase(events.begin(), events.end() - static_cast<std::ptrdiff_t>(limit));
    return events;
}

void AdbClient::launch_package(const std::string& serial, const std::string& package_name) const
{
    (void)shell(serial, {"monkey", "-p", package_name, "1"});
}

void AdbClient::send_home(const std::string& serial) const
{
    // Motorola's launcher can treat a HOME key event as a transient customization
    // panel. Bringing the resolved HOME task forward explicitly produced a stable
    // launcher state when the physical screen remained untouched. Collection code
    // must still re-check ResumedActivity throughout quiet conditions.
    (void)shell(serial, {"am", "start", "-W", "-a", "android.intent.action.MAIN",
                         "-c", "android.intent.category.HOME"});
}

void AdbClient::collapse_system_ui(const std::string& serial) const
{
    (void)shell(serial, {"cmd", "statusbar", "collapse"});
}

}  // namespace ciphertracedroid::device
