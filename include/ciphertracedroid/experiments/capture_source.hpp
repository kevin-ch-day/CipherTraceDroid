#pragma once

#include <string>
#include <string_view>

namespace ciphertracedroid::experiments {

enum class CaptureSourceKind {
    routed_primary,
    pcapdroid_auxiliary,
    synthetic_fixture,
};

struct CaptureCapabilities {
    bool whole_device_visibility{};
    bool target_app_attribution{};
    bool routed_ip_length_fidelity{};
    bool routed_timing_fidelity{};
    bool original_transport_semantics{};
    bool direction_available{};
    bool publication_primary_eligible{};
};

[[nodiscard]] CaptureSourceKind parse_capture_source(std::string_view value);
[[nodiscard]] std::string to_string(CaptureSourceKind source);
[[nodiscard]] CaptureCapabilities capabilities_for(CaptureSourceKind source);
[[nodiscard]] bool publication_primary_eligible(CaptureSourceKind source);
void require_source_for_primary_experiment(CaptureSourceKind source);
void require_source_capability(CaptureSourceKind source, bool require_routed_timing);

}  // namespace ciphertracedroid::experiments
