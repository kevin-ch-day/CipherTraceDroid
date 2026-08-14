#include "ciphertracedroid/device/android_state.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace ciphertracedroid::device {
namespace {

bool contains(const std::string& text, const std::string& value)
{
    return !value.empty() && text.find(value) != std::string::npos;
}

bool unusable(const std::string& value)
{
    return value.empty() || value == "unknown" || value.find("null") != std::string::npos;
}

}  // namespace

AndroidUiState classify_android_state(const PackageStateObservation& observation,
                                      const AndroidStatePolicy& policy)
{
    if (!observation.screen_interactive || observation.device_locked) return AndroidUiState::locked;
    if (observation.notification_shade_active ||
        observation.current_focus.find("NotificationShade") != std::string::npos) {
        return AndroidUiState::unrelated_overlay;
    }
    if (unusable(observation.top_activity)) return AndroidUiState::unknown;
    if (contains(observation.top_activity, policy.target_package)) {
        return AndroidUiState::target_app_resumed;
    }
    if (contains(observation.top_activity, policy.launcher_package)) {
        const bool normal = std::any_of(policy.normal_launcher_components.begin(),
                                        policy.normal_launcher_components.end(),
                                        [&](const std::string& component) {
                                            return contains(observation.top_activity, component);
                                        });
        return normal ? AndroidUiState::launcher_environment
                      : AndroidUiState::launcher_owned_transient;
    }
    return AndroidUiState::unrelated_overlay;
}

std::string to_string(AndroidUiState state)
{
    switch (state) {
        case AndroidUiState::target_app_resumed: return "target_app_resumed";
        case AndroidUiState::launcher_environment: return "launcher_environment";
        case AndroidUiState::launcher_owned_transient: return "launcher_owned_transient";
        case AndroidUiState::unrelated_overlay: return "unrelated_overlay";
        case AndroidUiState::locked: return "locked";
        case AndroidUiState::unknown: return "unknown";
    }
    throw std::logic_error("unknown Android UI state");
}

BackgroundStabilizer::BackgroundStabilizer(AndroidStatePolicy policy, double required_seconds,
                                           double maximum_observation_gap_seconds)
    : policy_(std::move(policy)), required_seconds_(required_seconds),
      maximum_gap_seconds_(maximum_observation_gap_seconds)
{
    if (policy_.target_package.empty() || policy_.launcher_package.empty()) {
        throw std::invalid_argument("state policy requires target and launcher packages");
    }
    if (!std::isfinite(required_seconds_) || required_seconds_ <= 0.0 ||
        !std::isfinite(maximum_gap_seconds_) || maximum_gap_seconds_ <= 0.0) {
        throw std::invalid_argument("stabilizer durations must be finite and positive");
    }
}

std::optional<BackgroundStabilizerResult> BackgroundStabilizer::observe(
    double elapsed_seconds, const PackageStateObservation& observation)
{
    if (terminal_) return terminal_;
    if (!std::isfinite(elapsed_seconds) || elapsed_seconds < 0.0 ||
        (!observations_.empty() && elapsed_seconds <= observations_.back().elapsed_seconds)) {
        terminal_ = result(false, "observation timestamps are invalid or non-increasing");
        return terminal_;
    }
    if (!observations_.empty() &&
        elapsed_seconds - observations_.back().elapsed_seconds > maximum_gap_seconds_) {
        terminal_ = result(false, "observation gap exceeded configured maximum");
        return terminal_;
    }
    const auto state = classify_android_state(observation, policy_);
    observations_.push_back({elapsed_seconds, observation, state});
    if (state == AndroidUiState::target_app_resumed) {
        terminal_ = result(false, "target app resumed during background guard");
    } else if (state == AndroidUiState::locked) {
        terminal_ = result(false, "device locked or screen stopped being interactive");
    } else if (state == AndroidUiState::unrelated_overlay) {
        terminal_ = result(false, "unrelated app or overlay appeared during background guard");
    } else if (state == AndroidUiState::unknown) {
        terminal_ = result(false, "Android state evidence was unknown or unparseable");
    } else if (elapsed_seconds - observations_.front().elapsed_seconds >= required_seconds_) {
        if (state != AndroidUiState::launcher_environment) {
            terminal_ = result(false, "guard ended without the normal launcher environment");
        } else {
            terminal_ = result(true, "");
        }
    }
    return terminal_;
}

BackgroundStabilizerResult BackgroundStabilizer::finish() const
{
    if (terminal_) return *terminal_;
    return result(false, "guard ended before the required stable duration");
}

BackgroundStabilizerResult BackgroundStabilizer::result(bool passed,
                                                        std::string failure_reason) const
{
    return {.passed = passed,
            .start_seconds = observations_.empty() ? 0.0 : observations_.front().elapsed_seconds,
            .end_seconds = observations_.empty() ? 0.0 : observations_.back().elapsed_seconds,
            .observations = observations_,
            .failure_reason = std::move(failure_reason),
            .final_state = observations_.empty() ? AndroidUiState::unknown
                                                 : observations_.back().state};
}

}  // namespace ciphertracedroid::device
