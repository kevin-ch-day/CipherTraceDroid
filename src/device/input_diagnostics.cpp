#include "ciphertracedroid/device/input_diagnostics.hpp"

#include <sstream>

namespace ciphertracedroid::device {

InputDiagnosticSummary summarize_getevent(std::string_view output)
{
    InputDiagnosticSummary result;
    if (output.empty() || output.find("Permission denied") != std::string_view::npos) return result;
    result.kind = InputEvidenceKind::none_observed;
    std::istringstream input{std::string(output)};
    for (std::string line; std::getline(input, line);) {
        const bool touch = line.find("BTN_TOUCH") != std::string::npos ||
                           (line.find("ABS_MT_TRACKING_ID") != std::string::npos && line.find("ffffffff") == std::string::npos);
        const bool key = line.find("KEY_") != std::string::npos &&
                         (line.find("DOWN") != std::string::npos || line.find(" 00000001") != std::string::npos);
        if (!touch && !key) continue;
        result.relevant_events.push_back(line);
        if (touch) result.kind = InputEvidenceKind::touch_contact;
        else if (result.kind == InputEvidenceKind::none_observed) result.kind = InputEvidenceKind::key_event;
    }
    return result;
}

StateGateFailureCause classify_state_gate_failure(bool target_resumed,
                                                  const InputDiagnosticSummary& input,
                                                  bool launcher_shortcut_aligned,
                                                  bool task_transition_observed)
{
    if (input.kind == InputEvidenceKind::touch_contact || input.kind == InputEvidenceKind::key_event) {
        return launcher_shortcut_aligned ? StateGateFailureCause::launcher_shortcut_activation
                                         : StateGateFailureCause::external_input_contamination;
    }
    if (!target_resumed) return StateGateFailureCause::none;
    return task_transition_observed ? StateGateFailureCause::task_transition_unattributed
                                    : StateGateFailureCause::target_app_resumed_without_observed_input;
}

std::string to_string(InputEvidenceKind kind)
{
    switch (kind) {
        case InputEvidenceKind::none_observed: return "no_input_observed";
        case InputEvidenceKind::touch_contact: return "touch_contact";
        case InputEvidenceKind::key_event: return "key_event";
        case InputEvidenceKind::unavailable: return "input_unavailable";
    }
    return "input_unavailable";
}

std::string to_string(StateGateFailureCause cause)
{
    switch (cause) {
        case StateGateFailureCause::external_input_contamination: return "external_input_contamination";
        case StateGateFailureCause::launcher_shortcut_activation: return "launcher_shortcut_activation";
        case StateGateFailureCause::target_app_resumed_without_observed_input: return "target_app_resumed_without_observed_input";
        case StateGateFailureCause::task_transition_unattributed: return "task_transition_unattributed";
        case StateGateFailureCause::unrelated_overlay: return "unrelated_overlay";
        case StateGateFailureCause::locked: return "locked";
        case StateGateFailureCause::unknown_state: return "unknown_state";
        case StateGateFailureCause::excessive_poll_gap: return "excessive_poll_gap";
        case StateGateFailureCause::none: return "none";
    }
    return "none";
}

}  // namespace ciphertracedroid::device
