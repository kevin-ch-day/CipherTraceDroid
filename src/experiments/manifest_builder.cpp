#include "ciphertracedroid/experiments/manifest_builder.hpp"

#include <stdexcept>

namespace ciphertracedroid::experiments {

void ManifestBuilder::add_interval(
    SessionManifestRow row,
    const std::optional<device::BackgroundStabilizerResult>& background_gate)
{
    if (row.state == ActivityState::background &&
        (!background_gate.has_value() || !background_gate->passed)) {
        throw std::invalid_argument("background interval requires a passing stabilizer result");
    }
    rows_.push_back(std::move(row));
}

}  // namespace ciphertracedroid::experiments
