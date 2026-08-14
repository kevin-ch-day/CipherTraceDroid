#include "ciphertracedroid/util/logging.hpp"

#include <cstdlib>
#include <iostream>

namespace ciphertracedroid::util {

bool debug_logging_enabled()
{
    const char* setting = std::getenv("CIPHERTRACEDROID_LOG");
    return setting != nullptr && std::string_view(setting) == "debug";
}

void debug_log(std::string_view component, std::string_view message)
{
    if (debug_logging_enabled()) std::clog << "[debug] " << component << ": " << message << '\n';
}

}  // namespace ciphertracedroid::util
