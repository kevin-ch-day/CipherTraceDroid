#include "ciphertracedroid/app.hpp"
#include "ciphertracedroid/capture/pcap_reader.hpp"
#include "ciphertracedroid/features/dataset_export.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

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
        << accent(out) << "Project" << reset(out) << "\n"
        << "  status       Show current pipeline readiness.\n"
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
            << "Usage:\n  ciphertracedroid features <manifest.csv> <output.csv> [--device-ip <address>] [--window-seconds <seconds>] [--idle-gap-seconds <seconds>]\n\n"
            << "Example:\n  ciphertracedroid features sessions.csv features.csv --device-ip 10.42.0.2 --window-seconds 5\n";
        return;
    }
    if (command == "validate-manifest") {
        out << accent(out) << "validate-manifest" << reset(out) << " — validate a session manifest\n\n"
            << "Usage:\n  ciphertracedroid validate-manifest <manifest.csv>\n\n"
            << "Checks capture files, mandatory SHA-256 values, conditions, intervals, and duplicate session IDs.\n";
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
              << "  3. ./run.sh inspect <capture.pcap> --device-ip <device-ip>\n"
              << "  4. ./run.sh validate-manifest <sessions.csv>\n"
              << "  5. ./run.sh features <sessions.csv> <features.csv> --device-ip <device-ip>\n";
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

void print_status()
{
    print_banner(std::cout);
    std::cout << "\n" << accent(std::cout) << "Pipeline status" << reset(std::cout) << "\n"
              << "  [ready] Offline PCAP inspection\n"
              << "  [ready] Manifest validation and SHA-256 provenance\n"
              << "  [ready] State-bounded feature CSV export\n"
              << "  [ready] Grouped run-level partitioning safeguard\n"
              << "  [next ] Validate a physical-device capture vantage\n";
}

}

namespace ciphertracedroid {

int run(int argc, char* argv[])
{
    if (argc <= 1)
    {
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
            std::cerr << "error: usage: ciphertracedroid features <manifest.csv> <output.csv> [--device-ip <address>] [--window-seconds <seconds>] [--idle-gap-seconds <seconds>]\n";
            return kCliError;
        }
        features::FeatureExportOptions options;
        try {
            for (int index = 4; index < argc; index += 2) {
                if (index + 1 >= argc) throw std::invalid_argument("features option requires a value");
                const std::string_view option{argv[index]};
                if (option == "--device-ip") options.device_ip = argv[index + 1];
                else if (option == "--window-seconds") options.window_seconds = std::stod(argv[index + 1]);
                else if (option == "--idle-gap-seconds") options.idle_gap_seconds = std::stod(argv[index + 1]);
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
