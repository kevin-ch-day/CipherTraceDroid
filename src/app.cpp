#include "ciphertracedroid/app.hpp"
#include "ciphertracedroid/analysis/condition_analysis.hpp"
#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/device/adb_client.hpp"
#include "ciphertracedroid/device/android_state.hpp"
#include "ciphertracedroid/features/dataset_export.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"
#include "ciphertracedroid/experiments/session_plan.hpp"
#include "ciphertracedroid/experiments/integration_experiment.hpp"

#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <sstream>
#include <vector>
#include <thread>

#include <unistd.h>

#ifndef CIPHERTRACEDROID_VERSION
#define CIPHERTRACEDROID_VERSION "development"
#endif

namespace {

constexpr int kSuccess = 0;
constexpr int kCliError = 2;

bool use_color(std::ostream& out)
{
    return &out == &std::cout && isatty(fileno(stdout)) != 0 && std::getenv("NO_COLOR") == nullptr;
}

bool interactive_terminal()
{
    return isatty(fileno(stdin)) != 0 && isatty(fileno(stdout)) != 0;
}

const char* accent(std::ostream& out) { return use_color(out) ? "\033[38;5;45m" : ""; }
const char* muted(std::ostream& out) { return use_color(out) ? "\033[38;5;245m" : ""; }
const char* reset(std::ostream& out) { return use_color(out) ? "\033[0m" : ""; }

void print_banner(std::ostream& out)
{
    out << accent(out)
        << "  CipherTraceDroid\n"
        << reset(out) << muted(out) << "  Encrypted Android traffic research instrument • v"
        << CIPHERTRACEDROID_VERSION << reset(out) << '\n';
}

void print_usage(std::ostream& out)
{
    out << "\n" << accent(out) << "Usage" << reset(out) << "\n"
        << "  ciphertracedroid <command> [options]\n\n"
        << accent(out) << "Inspect traffic" << reset(out) << "\n"
        << "  inspect <capture.pcap> [--format text|json] [--device-ip <address>]\n"
        << "      Summarize an offline PCAP without payload inspection.\n\n"
        << accent(out) << "Prepare evidence" << reset(out) << "\n"
        << "  validate-manifest <manifest.csv>\n"
        << "      Validate capture provenance, conditions, and intervals.\n"
        << "  features <manifest.csv> <output.csv> [--device-ip <address>]\n"
        << "      Export state-bounded, schema-versioned feature rows.\n\n"
        << "  analysis conditions <manifest.csv> <new-output-dir> [--device-ip <address>]\n"
        << "      Export all-window occupancy and condition-profile evidence.\n\n"
        << "  experiment synthetic <output-root> <experiment-id>\n"
        << "      Run all six conditions using non-publication synthetic fixtures.\n\n"
        << accent(out) << "Project" << reset(out) << "\n"
        << "  status       Show current pipeline readiness.\n"
        << "  device status  Inspect the single connected Android device through ADB.\n"
        << "  session plan <package> <output.json>\n"
        << "      Write a no-overwrite collection plan with package/device provenance.\n"
        << "  session dry-run <package> <new-output.json>\n"
        << "      Test one capture-free foreground-to-background stabilization.\n"
        << "  quickstart   Show the recommended first workflow.\n"
        << "  info         Show build information.\n"
        << "  help         Show this help message.\n\n"
        << muted(out) << "Options: -h, --help    -V, --version\n"
        << "Tip: CIPHERTRACEDROID_LOG=debug enables non-sensitive diagnostics.\n" << reset(out);
}

void print_command_help(std::ostream& out, std::string_view command)
{
    if (command == "inspect") {
        out << accent(out) << "inspect" << reset(out) << " — inspect an offline Ethernet PCAP\n\n"
            << "Usage:\n  ciphertracedroid inspect <capture.pcap> [--format text|json] [--device-ip <address>]\n\n"
            << "Examples:\n  ciphertracedroid inspect pilot.pcap\n  ciphertracedroid inspect pilot.pcap --device-ip 10.42.0.2 --format json\n\n"
            << muted(out) << "Device IP is used only for direction assignment.\n" << reset(out);
        return;
    }
    if (command == "features") {
        out << accent(out) << "features" << reset(out) << " — export versioned state-bounded feature rows\n\n"
            << "Usage:\n  ciphertracedroid features <manifest.csv> <output.csv> [--device-ip <address>] [--window-seconds <seconds>]\n\n"
            << "Example:\n  ciphertracedroid features sessions.csv features.csv --device-ip 10.42.0.2 --window-seconds 5\n";
        return;
    }
    if (command == "validate-manifest") {
        out << accent(out) << "validate-manifest" << reset(out) << " — validate a session manifest\n\n"
            << "Usage:\n  ciphertracedroid validate-manifest <manifest.csv>\n\n"
            << "Checks capture files, mandatory SHA-256 values, conditions, intervals, and duplicate session IDs.\n";
        return;
    }
    if (command == "experiment") {
        out << accent(out) << "experiment synthetic" << reset(out)
            << " — validate the complete grouped experiment path\n\n"
            << "Usage:\n  ciphertracedroid experiment synthetic <output-root> <experiment-id>\n\n"
            << "Creates a no-overwrite evidence bundle. Results are software-validation only.\n";
        return;
    }
    if (command == "device") {
        out << accent(out) << "device status" << reset(out) << " — inspect the connected Android device\n\n"
            << "Usage:\n  ciphertracedroid device status\n\n"
            << "Uses read-only ADB queries. Exactly one authorized device must be connected.\n";
        return;
    }
    if (command == "session") {
        out << accent(out) << "session plan" << reset(out) << " — create a collection provenance plan\n\n"
            << "Usage:\n  ciphertracedroid session plan <package-name> <output.json>\n\n"
            << "Performs read-only ADB checks, writes a new JSON artifact, and refuses to overwrite files.\n"
            << "It does not launch an app, change device state, or start a capture.\n\n"
            << accent(out) << "session transition" << reset(out) << " — issue one controlled device state action\n\n"
            << "Usage:\n  ciphertracedroid session transition <package-name> <foreground|background>\n\n"
            << "The command closes Notification Shade, launches the package or sends HOME, then reports Android's resumed activity.\n\n"
            << accent(out) << "session observe" << reset(out) << " — collect supporting Android state evidence\n\n"
            << "Usage:\n  ciphertracedroid session observe <package-name>\n\n"
            << "Reports top activity, focus probes, and process presence. These are control-plane evidence, never features.\n\n"
            << accent(out) << "session history" << reset(out) << " — show recent Android lifecycle evidence\n\n"
            << "Usage:\n  ciphertracedroid session history <package-name>\n\n"
            << "Shows recent ACTIVITY_RESUMED, ACTIVITY_PAUSED, and ACTIVITY_STOPPED records for the package.\n";
        return;
    }
    out << "error: no command help available for '" << command << "'\n\n";
    print_usage(out);
}

void print_quickstart()
{
    print_banner(std::cout);
    std::cout << "\n" << accent(std::cout) << "Recommended workflow" << reset(std::cout) << "\n"
              << "  1. ./build-project\n"
              << "  2. ./run.sh status\n"
              << "  3. ./run.sh device status\n"
              << "  4. ./run.sh session plan com.android.chrome output/session-plan.json\n"
              << "  5. ./run.sh inspect <capture.pcap> --device-ip <device-ip>\n"
              << "  6. ./run.sh validate-manifest <sessions.csv>\n"
              << "  7. ./run.sh features <sessions.csv> <features.csv> --device-ip <device-ip>\n";
}

std::string read_line(std::string_view prompt)
{
    std::cout << accent(std::cout) << prompt << reset(std::cout) << std::flush;
    std::string value;
    std::getline(std::cin, value);
    return value;
}

int run_command_from_menu(const std::vector<std::string>& arguments)
{
    std::vector<char*> raw_arguments;
    raw_arguments.reserve(arguments.size());
    for (const auto& argument : arguments) raw_arguments.push_back(const_cast<char*>(argument.c_str()));
    return ciphertracedroid::run(static_cast<int>(raw_arguments.size()), raw_arguments.data());
}

int run_menu(const char* program_name)
{
    while (true) {
        print_banner(std::cout);
        std::cout << "\n" << accent(std::cout) << "Main menu" << reset(std::cout) << "\n"
                  << "  1. Pipeline status\n"
                  << "  2. Connected Android device status\n"
                  << "  3. Create a session collection plan\n"
                  << "  4. Inspect a PCAP capture\n"
                  << "  5. Validate a session manifest\n"
                  << "  6. Export feature CSV\n"
                  << "  7. Help and examples\n"
                  << "  0. Exit\n\n";
        const auto selection = read_line("Select an option: ");
        if (!std::cin) {
            std::cout << "\n";
            return kSuccess;
        }
        if (selection == "0" || selection == "q" || selection == "quit") return kSuccess;
        if (selection == "1") {
            run_command_from_menu({program_name, "status"});
        } else if (selection == "2") {
            run_command_from_menu({program_name, "device", "status"});
        } else if (selection == "3") {
            const auto package_name = read_line("Android package name: ");
            const auto output = read_line("New session-plan JSON path: ");
            if (package_name.empty() || output.empty()) std::cout << "Package name and output path are required.\n";
            else run_command_from_menu({program_name, "session", "plan", package_name, output});
        } else if (selection == "4") {
            const auto path = read_line("PCAP path: ");
            const auto device_ip = read_line("Device IP (optional): ");
            if (path.empty()) std::cout << "No PCAP path entered.\n";
            else if (device_ip.empty()) run_command_from_menu({program_name, "inspect", path});
            else run_command_from_menu({program_name, "inspect", path, "--device-ip", device_ip});
        } else if (selection == "5") {
            const auto path = read_line("Manifest path: ");
            if (path.empty()) std::cout << "No manifest path entered.\n";
            else run_command_from_menu({program_name, "validate-manifest", path});
        } else if (selection == "6") {
            const auto manifest = read_line("Manifest path: ");
            const auto output = read_line("Feature CSV output path: ");
            const auto device_ip = read_line("Device IP (optional): ");
            if (manifest.empty() || output.empty()) std::cout << "Manifest and output paths are required.\n";
            else if (device_ip.empty()) run_command_from_menu({program_name, "features", manifest, output});
            else run_command_from_menu({program_name, "features", manifest, output, "--device-ip", device_ip});
        } else if (selection == "7") {
            run_command_from_menu({program_name, "quickstart"});
        } else {
            std::cout << "Unknown selection. Choose 0 through 7.\n";
        }
        read_line("\nPress Enter to return to the menu...");
        std::cout << "\n";
    }
}

void print_info()
{
    print_banner(std::cout);
    std::cout << "\n" << accent(std::cout) << "Build information" << reset(std::cout) << "\n"
              << "  Version      " << CIPHERTRACEDROID_VERSION << "\n"
              << "  Language     C++20\n"
              << "  Platform     Fedora Linux\n"
              << "  Scope        Encrypted Android traffic metadata analysis\n";
}

std::string json_string(const std::string& value)
{
    std::ostringstream output;
    output << '"';
    for (const char character : value) {
        if (character == '"' || character == '\\') output << '\\' << character;
        else if (character == '\n') output << "\\n";
        else output << character;
    }
    output << '"';
    return output.str();
}

double epoch_seconds()
{
    return std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void write_dry_run_result(const std::filesystem::path& path, const std::string& package,
                          const std::string& home_component, double launch_epoch,
                          double home_epoch,
                          const ciphertracedroid::device::BackgroundStabilizerResult& result,
                          const std::vector<ciphertracedroid::device::ActivityLifecycleEvent>& lifecycle)
{
    if (std::filesystem::exists(path)) throw std::runtime_error("dry-run output already exists: " + path.string());
    const auto temporary = path.string() + ".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("could not create dry-run evidence: " + temporary);
    output << std::setprecision(17) << "{\n"
           << "  \"schema\": \"android-state-dry-run-v1\",\n"
           << "  \"target_package\": " << json_string(package) << ",\n"
           << "  \"resolved_home_component\": " << json_string(home_component) << ",\n"
           << "  \"vpn_required_inactive\": true,\n"
           << "  \"launch_epoch\": " << launch_epoch << ",\n"
           << "  \"home_invocation_epoch\": " << home_epoch << ",\n"
           << "  \"passed\": " << (result.passed ? "true" : "false") << ",\n"
           << "  \"failure_reason\": " << json_string(result.failure_reason) << ",\n"
           << "  \"guard_start_seconds\": " << result.start_seconds << ",\n"
           << "  \"guard_end_seconds\": " << result.end_seconds << ",\n"
           << "  \"final_state\": " << json_string(ciphertracedroid::device::to_string(result.final_state)) << ",\n"
           << "  \"observations\": [\n";
    for (std::size_t index = 0; index < result.observations.size(); ++index) {
        const auto& item = result.observations[index];
        output << "    {\"elapsed_seconds\": " << item.elapsed_seconds
               << ", \"state\": " << json_string(ciphertracedroid::device::to_string(item.state))
               << ", \"resumed_activity\": " << json_string(item.evidence.top_activity)
               << ", \"focused_app\": " << json_string(item.evidence.focused_app)
               << ", \"current_focus\": " << json_string(item.evidence.current_focus)
               << ", \"process_running\": " << (item.evidence.process_running ? "true" : "false")
               << ", \"screen_interactive\": " << (item.evidence.screen_interactive ? "true" : "false")
               << ", \"device_locked\": " << (item.evidence.device_locked ? "true" : "false")
               << "}" << (index + 1 == result.observations.size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"lifecycle_events\": [\n";
    for (std::size_t index = 0; index < lifecycle.size(); ++index) {
        const auto& event = lifecycle[index];
        output << "    {\"timestamp\": " << json_string(event.timestamp)
               << ", \"type\": " << json_string(event.type)
               << ", \"activity\": " << json_string(event.activity_class) << "}"
               << (index + 1 == lifecycle.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
    output.close();
    if (!output) throw std::runtime_error("could not finalize dry-run evidence");
    std::filesystem::rename(temporary, path);
}

void print_status()
{
    print_banner(std::cout);
    std::cout << "\n" << accent(std::cout) << "Pipeline status" << reset(std::cout) << "\n"
              << "  [ready] Offline PCAP inspection\n"
              << "  [ready] Manifest validation and SHA-256 provenance\n"
              << "  [ready] State-bounded feature CSV export\n"
              << "  [ready] Grouped run-level partitioning safeguard\n"
              << "  [ready] Typed capture-source enforcement\n"
              << "  [ready] Six-condition synthetic evidence bundle\n"
              << "  [next ] Validate a physical-device capture vantage\n";
}

}

namespace ciphertracedroid {

int run(int argc, char* argv[])
{
    if (argc <= 1)
    {
        if (interactive_terminal()) return run_menu(argv[0]);
        print_banner(std::cout);
        std::cout << "\nStart with " << accent(std::cout) << "ciphertracedroid help"
                  << reset(std::cout) << " to see available commands.\n"
                  << muted(std::cout) << "Scientific outputs are deterministic; diagnostics are opt-in.\n"
                  << reset(std::cout);
        return kSuccess;
    }

    const std::string_view command{argv[1]};

    if (command == "help")
    {
        if (argc == 2) print_usage(std::cout);
        else if (argc == 3) print_command_help(std::cout, argv[2]);
        else {
            std::cerr << "error: usage: ciphertracedroid help [command]\n";
            return kCliError;
        }
        return kSuccess;
    }

    if (command == "-h" || command == "--help")
    {
        print_usage(std::cout);
        return kSuccess;
    }

    if (command == "-V" || command == "--version")
    {
        std::cout << CIPHERTRACEDROID_VERSION << '\n';
        return kSuccess;
    }

    if (command == "info")
    {
        print_info();
        return kSuccess;
    }

    if (command == "status")
    {
        print_status();
        return kSuccess;
    }

    if (command == "quickstart")
    {
        print_quickstart();
        return kSuccess;
    }

    if (command == "device") {
        if (argc == 3 && std::string_view{argv[2]} == "status") {
            try {
                const auto readiness = device::AdbClient{}.inspect_single_device();
                print_banner(std::cout);
                std::cout << "\n" << accent(std::cout) << "Android device readiness" << reset(std::cout) << "\n"
                          << "  Serial       " << readiness.device.serial << "\n"
                          << "  Device       " << readiness.manufacturer << " " << readiness.model << "\n"
                          << "  Android      " << readiness.android_release << " (API " << readiness.api_level << ")\n"
                          << "  Shell UID    " << readiness.shell_uid
                          << (readiness.shell_uid == "0" ? " (root)" : " (non-root)") << "\n"
                          << "  Screen       " << (readiness.screen_interactive ? "interactive" : "asleep") << "\n"
                          << "  Lock state   " << (readiness.device_locked ? "locked" : "unlocked") << "\n"
                          << "  Clock offset " << readiness.clock_offset_seconds << " s (device - host)\n"
                          << "  tcpdump      " << (readiness.tcpdump_available ? "available" : "not available") << "\n"
                          << "  PCAPdroid    " << (readiness.pcapdroid_available ? readiness.pcapdroid_version : "not installed") << "\n"
                          << "  VPN          " << (readiness.vpn_active ? "active" : "not active") << "\n"
                          << "  Route        " << readiness.network_route << "\n"
                          << muted(std::cout) << "Read-only ADB inspection; no device setting was changed.\n" << reset(std::cout);
                return kSuccess;
            } catch (const std::exception& error) {
                std::cerr << "error: device status: " << error.what() << '\n';
                return kCliError;
            }
        }
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        std::cerr << "error: usage: ciphertracedroid device status\n";
        return kCliError;
    }

    if (command == "session") {
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc == 4 && std::string_view{argv[3]} == "--help" &&
            (std::string_view{argv[2]} == "observe" || std::string_view{argv[2]} == "transition" || std::string_view{argv[2]} == "history")) {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc == 5 && std::string_view{argv[2]} == "plan") {
            try {
                experiments::write_session_plan({argv[3], argv[4]});
                std::cout << "Created session collection plan: " << argv[4] << "\n";
                return kSuccess;
            } catch (const std::exception& error) {
                std::cerr << "error: session plan: " << error.what() << '\n';
                return kCliError;
            }
        }
        if (argc == 5 && std::string_view{argv[2]} == "dry-run") {
            const std::string package_name{argv[3]};
            const std::filesystem::path output_path{argv[4]};
            try {
                if (std::filesystem::exists(output_path)) {
                    throw std::runtime_error("dry-run output already exists: " + output_path.string());
                }
                device::AdbClient adb;
                const auto readiness = adb.inspect_single_device();
                (void)adb.inspect_package(readiness.device.serial, package_name);
                if (readiness.vpn_active) throw std::runtime_error("Android VPN must be inactive");
                if (!readiness.screen_interactive || readiness.device_locked) {
                    throw std::runtime_error("device must be interactive and unlocked");
                }
                const auto home_component = adb.resolved_home_activity(readiness.device.serial);
                const auto separator = home_component.find('/');
                if (separator == std::string::npos) throw std::runtime_error("could not resolve HOME package/component");
                const std::string launcher_package = home_component.substr(0, separator);
                const device::AndroidStatePolicy policy{
                    package_name, launcher_package,
                    {home_component.substr(separator + 1), "CustomizationPanelLauncher", "QuickstepLauncher"}};
                const double launch_epoch = epoch_seconds();
                adb.launch_package(readiness.device.serial, package_name);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                const auto foreground = adb.observe_package_state(readiness.device.serial, package_name);
                if (device::classify_android_state(foreground, policy) !=
                    device::AndroidUiState::target_app_resumed) {
                    const device::BackgroundStabilizerResult failed{
                        false, 0.0, 0.0, {}, "target app was not resumed after launch verification",
                        device::classify_android_state(foreground, policy)};
                    write_dry_run_result(output_path, package_name, home_component, launch_epoch,
                                         0.0, failed,
                                         adb.recent_activity_events(readiness.device.serial, package_name));
                    std::cout << "STATE TRANSITION DRY RUN: FAIL\nEvidence: " << output_path << '\n';
                    return kCliError;
                }
                const double home_epoch = epoch_seconds();
                adb.send_home(readiness.device.serial);
                const auto origin = std::chrono::steady_clock::now();
                device::BackgroundStabilizer stabilizer(policy);
                std::optional<device::BackgroundStabilizerResult> terminal;
                for (int second = 0; second <= 15 && !terminal; ++second) {
                    std::this_thread::sleep_until(origin + std::chrono::seconds(second));
                    const double elapsed = std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - origin).count();
                    terminal = stabilizer.observe(
                        elapsed, adb.observe_package_state(readiness.device.serial, package_name));
                }
                const auto result = terminal.value_or(stabilizer.finish());
                const auto lifecycle = adb.recent_activity_events(readiness.device.serial, package_name);
                write_dry_run_result(output_path, package_name, home_component, launch_epoch,
                                     home_epoch, result, lifecycle);
                std::cout << "STATE TRANSITION DRY RUN: " << (result.passed ? "PASS" : "FAIL")
                          << "\nEvidence: " << output_path << '\n';
                if (!result.passed) std::cout << "Failure: " << result.failure_reason << '\n';
                return result.passed ? kSuccess : kCliError;
            } catch (const std::exception& error) {
                std::cerr << "error: session dry-run: " << error.what() << '\n';
                return kCliError;
            }
        }
        if (argc == 5 && std::string_view{argv[2]} == "transition") {
            const std::string package_name{argv[3]};
            const std::string_view state{argv[4]};
            if (state != "foreground" && state != "background") {
                std::cerr << "error: transition state must be 'foreground' or 'background'\n";
                return kCliError;
            }
            try {
                device::AdbClient adb;
                const auto readiness = adb.inspect_single_device();
                (void)adb.inspect_package(readiness.device.serial, package_name);
                if (!readiness.screen_interactive || readiness.device_locked) {
                    std::cerr << "error: session transition: device must be awake and unlocked before a verified UI transition\n";
                    return kCliError;
                }
                const auto before = adb.observe_package_state(readiness.device.serial, package_name);
                if (before.notification_shade_active) {
                    std::cerr << "error: session transition: Notification Shade is active; dismiss it manually and retry so the transition can be verified\n";
                    return kCliError;
                }
                adb.collapse_system_ui(readiness.device.serial);
                if (state == "foreground") adb.launch_package(readiness.device.serial, package_name);
                else adb.send_home(readiness.device.serial);
                const auto observation = adb.observe_package_state(readiness.device.serial, package_name);
                std::cout << "Requested " << state << " transition for " << package_name << "\n"
                          << "Observed resumed activity: " << observation.top_activity << "\n"
                          << "Transition indication: "
                          << ((state == "foreground") == observation.top_activity_matches_package ? "consistent" : "not confirmed") << "\n";
                return kSuccess;
            } catch (const std::exception& error) {
                std::cerr << "error: session transition: " << error.what() << '\n';
                return kCliError;
            }
        }
        if (argc == 4 && std::string_view{argv[2]} == "observe") {
            const std::string package_name{argv[3]};
            try {
                device::AdbClient adb;
                const auto readiness = adb.inspect_single_device();
                (void)adb.inspect_package(readiness.device.serial, package_name);
                const auto observation = adb.observe_package_state(readiness.device.serial, package_name);
                print_banner(std::cout);
                std::cout << "\n" << accent(std::cout) << "Android state observation" << reset(std::cout) << "\n"
                          << "  Package       " << observation.package_name << "\n"
                          << "  Resumed act.  " << observation.top_activity << "\n"
                          << "  Focused app   " << observation.focused_app << "\n"
                          << "  Current focus " << observation.current_focus << "\n"
                          << "  Overlay       " << (observation.notification_shade_active ? "Notification Shade active" : "none detected") << "\n"
                          << "  Process       " << (observation.process_running ? "running" : "not running") << "\n"
                          << "  Top match     " << (observation.top_activity_matches_package ? "yes" : "no") << "\n"
                          << muted(std::cout) << "Use resumed activity as the primary observation; dismiss Notification Shade before a transition.\n" << reset(std::cout);
                return kSuccess;
            } catch (const std::exception& error) {
                std::cerr << "error: session observe: " << error.what() << '\n';
                return kCliError;
            }
        }
        if (argc == 4 && std::string_view{argv[2]} == "history") {
            const std::string package_name{argv[3]};
            try {
                device::AdbClient adb;
                const auto readiness = adb.inspect_single_device();
                (void)adb.inspect_package(readiness.device.serial, package_name);
                const auto events = adb.recent_activity_events(readiness.device.serial, package_name);
                std::cout << "Recent Android lifecycle events for " << package_name << ":\n";
                if (events.empty()) std::cout << "  none reported\n";
                for (const auto& event : events) {
                    std::cout << "  " << event.timestamp << "  " << event.type << "  " << event.activity_class << "\n";
                }
                return kSuccess;
            } catch (const std::exception& error) {
                std::cerr << "error: session history: " << error.what() << '\n';
                return kCliError;
            }
        }
        std::cerr << "error: usage: ciphertracedroid session plan <package-name> <output.json>\n"
                  << "       ciphertracedroid session transition <package-name> <foreground|background>\n"
                  << "       ciphertracedroid session observe <package-name>\n"
                  << "       ciphertracedroid session history <package-name>\n"
                  << "       ciphertracedroid session dry-run <package-name> <new-output.json>\n";
        return kCliError;
    }

    if (command == "analysis") {
        if (argc < 5 || std::string_view{argv[2]} != "conditions") {
            std::cerr << "error: usage: ciphertracedroid analysis conditions <manifest.csv> <new-output-dir> [--device-ip <address>]\n";
            return kCliError;
        }
        std::string device_ip;
        try {
            for (int index = 5; index < argc; index += 2) {
                if (index + 1 >= argc) throw std::invalid_argument("analysis option requires a value");
                const std::string_view option{argv[index]};
                if (option == "--device-ip") device_ip = argv[index + 1];
                else throw std::invalid_argument("unknown analysis option: " + std::string(option));
            }
            const auto path = analysis::write_condition_analysis_bundle(argv[3], argv[4], device_ip);
            std::cout << "Created complete-window and condition-profile analysis: " << path << '\n';
            return kSuccess;
        } catch (const std::exception& error) {
            std::cerr << "error: condition analysis: " << error.what() << '\n';
            return kCliError;
        }
    }

    if (command == "inspect") {
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc < 3) {
            std::cerr << "error: usage: ciphertracedroid inspect <capture.pcap> [--format json] [--device-ip <address>]\n";
            return kCliError;
        }
        std::string format = "text";
        std::string device_ip;
        for (int index = 3; index < argc; index += 2) {
            if (index + 1 >= argc) {
                std::cerr << "error: inspect option requires a value\n";
                return kCliError;
            }
            const std::string_view option{argv[index]};
            if (option == "--format") format = argv[index + 1];
            else if (option == "--device-ip") device_ip = argv[index + 1];
            else {
                std::cerr << "error: unknown inspect option: " << option << '\n';
                return kCliError;
            }
        }
        if (format != "text" && format != "json") {
            std::cerr << "error: inspect format must be 'text' or 'json'\n";
            return kCliError;
        }
        try {
            const auto capture = capture::read_pcap(argv[2], device_ip);
            std::cout << (format == "json" ? capture::summary_to_json(capture.summary)
                                           : capture::summary_to_text(capture.summary));
            return kSuccess;
        } catch (const std::exception& error) {
            std::cerr << "error: " << error.what() << '\n';
            return kCliError;
        }
    }

    if (command == "features") {
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc < 4) {
            std::cerr << "error: usage: ciphertracedroid features <manifest.csv> <output.csv> [--device-ip <address>] [--window-seconds <seconds>]\n";
            return kCliError;
        }
        features::FeatureExportOptions options;
        try {
            for (int index = 4; index < argc; index += 2) {
                if (index + 1 >= argc) throw std::invalid_argument("features option requires a value");
                const std::string_view option{argv[index]};
                if (option == "--device-ip") options.device_ip = argv[index + 1];
                else if (option == "--window-seconds") options.window_seconds = std::stod(argv[index + 1]);
                else throw std::invalid_argument("unknown features option: " + std::string(option));
            }
            const auto count = features::export_features(argv[2], argv[3], options);
            std::cout << "Exported " << count << " feature rows\n";
            return kSuccess;
        } catch (const std::exception& error) {
            std::cerr << "error: " << error.what() << '\n';
            return kCliError;
        }
    }

    if (command == "experiment") {
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc != 5 || std::string_view{argv[2]} != "synthetic") {
            std::cerr << "error: usage: ciphertracedroid experiment synthetic <output-root> <experiment-id>\n";
            return kCliError;
        }
        try {
            const auto result = experiments::run_synthetic_six_condition_experiment();
            const auto path = experiments::write_synthetic_evidence_bundle(result, argv[3], argv[4]);
            std::cout << "SYNTHETIC SOFTWARE-VALIDATION RESULT — NOT RESEARCH EVIDENCE\n"
                      << "Completed all six grouped conditions\n"
                      << "Evidence bundle: " << path << '\n';
            return kSuccess;
        } catch (const std::exception& error) {
            std::cerr << "error: synthetic experiment: " << error.what() << '\n';
            return kCliError;
        }
    }

    if (command == "validate-manifest") {
        if (argc == 3 && std::string_view{argv[2]} == "--help") {
            print_command_help(std::cout, command);
            return kSuccess;
        }
        if (argc != 3) {
            std::cerr << "error: usage: ciphertracedroid validate-manifest <manifest.csv>\n";
            return kCliError;
        }
        try {
            const auto rows = experiments::read_session_manifest(argv[2]);
            std::cout << "Valid manifest: " << rows.size() << " rows\n";
            return kSuccess;
        } catch (const std::exception& error) {
            std::cerr << "error: " << error.what() << '\n';
            return kCliError;
        }
    }

    std::cerr << "error: unknown command: " << command << "\n"
              << "hint: run 'ciphertracedroid help' to list available commands\n\n";
    print_usage(std::cerr);

    return kCliError;
}

}
