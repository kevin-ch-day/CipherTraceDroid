#include "ciphertracedroid/experiments/capture_source.hpp"

#include <stdexcept>

namespace ciphertracedroid::experiments {

CaptureSourceKind parse_capture_source(std::string_view value)
{
    if (value == "routed_primary") return CaptureSourceKind::routed_primary;
    if (value == "pcapdroid_vpn_boundary_auxiliary") return CaptureSourceKind::pcapdroid_auxiliary;
    if (value == "synthetic_fixture") return CaptureSourceKind::synthetic_fixture;
    throw std::invalid_argument("unknown capture source '" + std::string(value) + "'");
}

std::string to_string(CaptureSourceKind source)
{
    switch (source) {
        case CaptureSourceKind::routed_primary: return "routed_primary";
        case CaptureSourceKind::pcapdroid_auxiliary: return "pcapdroid_vpn_boundary_auxiliary";
        case CaptureSourceKind::synthetic_fixture: return "synthetic_fixture";
    }
    throw std::logic_error("unhandled capture source");
}

CaptureCapabilities capabilities_for(CaptureSourceKind source)
{
    switch (source) {
        case CaptureSourceKind::routed_primary:
            // These are requirements for admitting a validated routed capture, not a claim
            // that the current physical capture path has passed validation.
            return {true, false, true, true, true, true, true};
        case CaptureSourceKind::pcapdroid_auxiliary:
            return {false, true, false, false, false, true, false};
        case CaptureSourceKind::synthetic_fixture:
            return {false, false, false, false, false, true, false};
    }
    throw std::logic_error("unhandled capture source");
}

bool publication_primary_eligible(CaptureSourceKind source)
{
    return capabilities_for(source).publication_primary_eligible;
}

void require_source_for_primary_experiment(CaptureSourceKind source)
{
    if (!publication_primary_eligible(source)) {
        throw std::invalid_argument("capture source '" + to_string(source) +
                                    "' is not eligible for a routed-primary experiment");
    }
}

void require_source_capability(CaptureSourceKind source, bool require_routed_timing)
{
    if (require_routed_timing && !capabilities_for(source).routed_timing_fidelity) {
        throw std::invalid_argument("capture source '" + to_string(source) +
                                    "' does not provide routed timing fidelity");
    }
}

}  // namespace ciphertracedroid::experiments
