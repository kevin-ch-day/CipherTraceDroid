#pragma once

#include "ciphertracedroid/device/android_state.hpp"
#include "ciphertracedroid/experiments/session_manifest.hpp"

#include <optional>
#include <vector>

namespace ciphertracedroid::experiments {

class ManifestBuilder {
public:
    void add_interval(SessionManifestRow row,
                      const std::optional<device::BackgroundStabilizerResult>& background_gate = std::nullopt);
    [[nodiscard]] const std::vector<SessionManifestRow>& rows() const noexcept { return rows_; }

private:
    std::vector<SessionManifestRow> rows_;
};

}  // namespace ciphertracedroid::experiments
