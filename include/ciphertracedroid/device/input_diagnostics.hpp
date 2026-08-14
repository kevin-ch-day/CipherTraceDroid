#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ciphertracedroid::device {

enum class InputEvidenceKind { none_observed, touch_contact, key_event, unavailable };
enum class StateGateFailureCause {
    external_input_contamination,
    launcher_shortcut_activation,
    target_app_resumed_without_observed_input,
    task_transition_unattributed,
    unrelated_overlay,
    locked,
    unknown_state,
    excessive_poll_gap,
    none
};

struct InputDiagnosticSummary {
    InputEvidenceKind kind{InputEvidenceKind::unavailable};
    std::vector<std::string> relevant_events;
};

[[nodiscard]] InputDiagnosticSummary summarize_getevent(std::string_view output);
[[nodiscard]] StateGateFailureCause classify_state_gate_failure(
    bool target_resumed, const InputDiagnosticSummary& input, bool launcher_shortcut_aligned,
    bool task_transition_observed);
[[nodiscard]] std::string to_string(InputEvidenceKind kind);
[[nodiscard]] std::string to_string(StateGateFailureCause cause);

}  // namespace ciphertracedroid::device
