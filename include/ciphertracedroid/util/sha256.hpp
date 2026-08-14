#pragma once

#include <filesystem>
#include <string>

namespace ciphertracedroid::util {

[[nodiscard]] std::string sha256_file(const std::filesystem::path& path);
[[nodiscard]] bool is_sha256_hex(const std::string& value);

}  // namespace ciphertracedroid::util
