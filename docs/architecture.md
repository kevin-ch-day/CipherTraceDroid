# Architecture

`main.cpp` delegates directly to the application layer. `ciphertracedroid_core` currently holds command handling plus deterministic traffic-window and feature-extraction functions. Capture ingestion will feed normalized `PacketRecord` values into windows, then the versioned feature CSV. Classification is deliberately deferred until capture-to-feature export and session-level partitioning are complete.

`PacketRecord` retains timestamps, lengths, network/transport classifications, endpoint addresses and ports, and explicitly assigned direction. It does not retain application payload bytes.

For physical experiments, ADB is a separate control plane: it launches a selected package, sends HOME, records host-side event timestamps, and checks Android state. Network observation collects encrypted traffic metadata, and analysis consumes only the capture plus manifest labels. ADB state, package metadata, and lifecycle information are never classifier inputs.
