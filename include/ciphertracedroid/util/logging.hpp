#pragma once

#include <string_view>

namespace ciphertracedroid::util {

// Diagnostic output is opt-in and never changes scientific outputs.
[[nodiscard]] bool debug_logging_enabled();
void debug_log(std::string_view component, std::string_view message);

}  // namespace ciphertracedroid::util
