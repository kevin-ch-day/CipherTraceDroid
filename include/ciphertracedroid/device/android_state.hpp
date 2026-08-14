#pragma once

#include "ciphertracedroid/device/adb_client.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ciphertracedroid::device {

enum class AndroidUiState {
    target_app_resumed,
    launcher_environment,
    launcher_owned_transient,
    unrelated_overlay,
    locked,
    unknown,
};

struct AndroidStatePolicy {
    std::string target_package;
    std::string launcher_package;
    std::vector<std::string> normal_launcher_components;
};

struct ClassifiedStateObservation {
    double elapsed_seconds{};
    PackageStateObservation evidence;
    AndroidUiState state{AndroidUiState::unknown};
};

struct BackgroundStabilizerResult {
    bool passed{};
    double start_seconds{};
    double end_seconds{};
    std::vector<ClassifiedStateObservation> observations;
    std::string failure_reason;
    AndroidUiState final_state{AndroidUiState::unknown};
};

[[nodiscard]] AndroidUiState classify_android_state(const PackageStateObservation& observation,
                                                    const AndroidStatePolicy& policy);
[[nodiscard]] std::string to_string(AndroidUiState state);

class BackgroundStabilizer {
public:
    BackgroundStabilizer(AndroidStatePolicy policy, double required_seconds = 15.0,
                         double maximum_observation_gap_seconds = 1.75);
    [[nodiscard]] std::optional<BackgroundStabilizerResult> observe(
        double elapsed_seconds, const PackageStateObservation& observation);
    [[nodiscard]] BackgroundStabilizerResult finish() const;

private:
    [[nodiscard]] BackgroundStabilizerResult result(bool passed,
                                                    std::string failure_reason) const;
    AndroidStatePolicy policy_;
    double required_seconds_{};
    double maximum_gap_seconds_{};
    std::vector<ClassifiedStateObservation> observations_;
    std::optional<BackgroundStabilizerResult> terminal_;
};

}  // namespace ciphertracedroid::device
