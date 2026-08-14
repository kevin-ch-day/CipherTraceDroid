# CipherTraceDroid

CipherTraceDroid is a small C++20 research instrument for studying how encrypted Android network-traffic metadata changes between controlled foreground and background activity states. It uses no decrypted application data or identity-bearing application-layer metadata in its primary feature matrix.

Current scope: offline Ethernet PCAP inspection, packet normalization, state-bounded windows, and schema-versioned feature contracts are implemented. Manifest-driven datasets and classification remain future gates.

## Fedora build

Install build tools plus `libpcap-devel` for offline capture inspection, then run:

```bash
./scripts/build.sh
./scripts/qa.sh
./build/ciphertracedroid --help
./build/ciphertracedroid info
```

Root-level shortcuts are also available:

```bash
./build-project
./run.sh --help
./clean-project
```

`clean-project` removes only generated `build`, `build-qa`, and `build-asan` directories.

Inspect a capture with an explicit device address for direction assignment:

```bash
./build/ciphertracedroid inspect capture.pcap --device-ip 192.168.0.23
./build/ciphertracedroid inspect capture.pcap --format json
```

The initial reader supports Ethernet-link PCAP files through libpcap. Unsupported link types and malformed packets are reported explicitly.

Export features from a strict, capture-relative session manifest:

```bash
./build/ciphertracedroid features data/manifests/sessions.csv data/processed/features.csv \
  --device-ip 192.168.0.23 --window-seconds 5 --idle-gap-seconds 1
```

Every included row stays associated with its declared session ID; this command does not partition, shuffle, or train on windows.

Validate capture files, mandatory SHA-256 values, interval ranges, and labels before export:

```bash
./build/ciphertracedroid validate-manifest data/manifests/sessions.csv
```

For non-sensitive runtime diagnostics, set `CIPHERTRACEDROID_LOG=debug`; messages go to stderr and never alter CSV/JSON results. For a read-only NetworkManager/AP diagnostic bundle, run `./scripts/ap-pilot-diagnose.sh`.

Feature rows use schema version 1 and include window/session/app/run/state provenance. Fixed windows are constructed independently within each manifest-provided activity-state interval, so they never span a state boundary. Direction remains unknown unless a user-supplied device identity matches an endpoint.

Raw captures and generated models/results are ignored by Git. Keep only controlled synthetic fixtures in tests; do not add production captures to the repository.

## Physical-device readiness

ADB is the experiment-control and ground-truth plane, never a source of classifier features. Check one connected Android endpoint without changing it:

```bash
./scripts/device-check.sh
./scripts/device-check.sh --package com.android.chrome
```

See [physical-device.md](docs/physical-device.md) for the state-transition workflow, metadata, timestamping, and capture constraints.
