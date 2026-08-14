#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace ciphertracedroid::features {

struct FeatureExportOptions {
    double window_seconds{5.0};
    std::string device_ip;
};

[[nodiscard]] std::size_t export_features(const std::filesystem::path& manifest_path,
                                          const std::filesystem::path& output_path,
                                          const FeatureExportOptions& options);

}  // namespace ciphertracedroid::features
