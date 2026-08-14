#pragma once

#include <filesystem>
#include <string>

namespace ciphertracedroid::experiments {

struct SessionPlanOptions {
    std::string package_name;
    std::filesystem::path output_file;
};

// Writes a new provenance-and-procedure record. This does not launch, stop, or modify the Android device.
void write_session_plan(const SessionPlanOptions& options);

}  // namespace ciphertracedroid::experiments
