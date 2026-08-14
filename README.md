# CipherTraceDroid

CipherTraceDroid is a small C++20 research instrument for studying how encrypted Android network-traffic metadata changes between controlled foreground and background activity states. It uses no decrypted application data or identity-bearing application-layer metadata in its primary feature matrix.

Current scope: offline Ethernet/raw-IP PCAP inspection, typed capture-source provenance, state-bounded Feature Schema v1, grouped six-condition experiments, a native integration baseline, multiclass metrics, and no-overwrite evidence bundles are implemented. Physical routed capture remains a required external gate.

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
When launched from an interactive terminal with no arguments, `./run.sh` opens a menu for the primary evidence-pipeline tasks. Supplying a command, or using a pipe/redirect, keeps the standard non-interactive CLI behavior.

Inspect a capture with an explicit device address for direction assignment:

```bash
./build/ciphertracedroid inspect capture.pcap --device-ip 192.168.0.23
./build/ciphertracedroid inspect capture.pcap --format json
```

The reader supports Ethernet-link PCAP files and raw-IP (`DLT_RAW`) PCAP files through libpcap. The latter permits inspection of PCAPdroid VPN-boundary artifacts; unsupported link types and malformed packets are reported explicitly.

Export features from a strict, capture-relative session manifest:

```bash
./build/ciphertracedroid features data/manifests/sessions.csv data/processed/features.csv \
  --device-ip 192.168.0.23 --window-seconds 5
```

Every included row stays associated with its declared session ID; this command does not partition, shuffle, or train on windows.

Preserve every scheduled window and build separately versioned condition profiles without changing Feature Schema v1:

```bash
./run.sh analysis conditions data/manifests/sessions.csv output/analysis/new-bundle \
  --device-ip 192.168.0.23
```

The no-overwrite bundle contains a complete-window ledger, occupancy summary, 5/10/15/30/60-second duration sweep, condition profiles, and checksums. Empty windows retain zero traffic volume while packet-dependent statistics remain unavailable. See [Condition Profile Schema v1](docs/research/condition-profile-schema-v1.md).

Validate capture files, mandatory SHA-256 values, interval ranges, and labels before export:

```bash
./build/ciphertracedroid validate-manifest data/manifests/sessions.csv
```

The strict manifest header is:

```text
session_id,app_id,run_id,state,capture_file,capture_sha256,capture_source,start_offset_s,end_offset_s,include,synthetic_test_only,pilot
```

`capture_source` is one of `routed_primary`, `pcapdroid_vpn_boundary_auxiliary`, or `synthetic_fixture`. The synthetic flag must agree with the typed source.

For non-sensitive runtime diagnostics, set `CIPHERTRACEDROID_LOG=debug`; messages go to stderr and never alter CSV/JSON results. For a read-only NetworkManager/AP diagnostic bundle, run `./scripts/ap-pilot-diagnose.sh`.

Feature rows use schema version 1 and include typed capture-source plus window/session/app/run/state provenance. Fixed complete windows are constructed independently within each manifest-provided activity-state interval, so they never span a state boundary. Direction remains unknown unless a user-supplied device identity matches an endpoint. See [Feature Schema v1](docs/research/feature-schema-v1.md).

Run the complete software-validation experiment without physical evidence:

```bash
./run.sh experiment synthetic output/results synthetic-check-001
```

This executes FG→FG, FG→BG, BG→BG, BG→FG, Mixed→FG, and Mixed→BG with grouped synthetic runs and writes a checksummed bundle. The output is explicitly ineligible for publication evidence.

Raw captures and generated models/results are ignored by Git. Keep only controlled synthetic fixtures in tests; do not add production captures to the repository.

## Physical-device readiness

ADB is the experiment-control and ground-truth plane, never a source of classifier features. Check one connected Android endpoint without changing it:

```bash
./run.sh device status
./scripts/device-check.sh
./scripts/device-check.sh --package com.android.chrome
```

`device status` is implemented in C++ and invokes ADB with fixed argument vectors rather than a command shell. It reports one authorized device's OS details, privilege level, available on-device capture tooling, and active network route. Future device-control operations will remain explicit commands with clear preconditions; the launcher scripts only build or start the executable.

Create a provenance-and-procedure artifact before a collection session:

```bash
./run.sh session plan com.android.chrome output/chrome-session-plan.json
```

This command verifies the selected installed package, records read-only device and package facts, writes collection gates, and refuses to overwrite a prior plan. It does not launch the package or begin a capture; only use a finalized PCAP after its capture vantage has been validated.

Once a capture path has been validated, the C++ control plane can issue explicit state actions and show the post-action Android activity probe:

```bash
./run.sh session transition com.android.chrome foreground
./run.sh session transition com.android.chrome background
```

`foreground` closes Notification Shade and launches the named installed package; `background` closes it and sends Android HOME. Neither command force-stops an app or starts packet capture. Record host UTC boundaries and apply the transition guard before adding intervals to the manifest.

If the device reports Notification Shade as active, the transition stops before changing state. Dismiss or unlock the device manually, then rerun the command; this prevents a system overlay from producing an unverified label.

Transitions also require the screen to be awake and the device unlocked. `device status` reports both preconditions; this project does not try to bypass Android lock-screen security.

`device status` also measures whole-second device-to-host clock offset. Record that value with session provenance; PCAP interval boundaries remain host-relative.

It also reports PCAPdroid availability and whether a VPN is active. PCAPdroid is an opt-in, user-consented fallback with a different measurement point; see [capture architecture](docs/research/capture-architecture.md) before using it.

For a read-only state probe at either boundary:

```bash
./run.sh session observe com.android.chrome
./run.sh session history com.android.chrome
```

It reports `ResumedActivity` from `dumpsys activity activities` as the primary signal, with focused-app/current-window and process-presence probes as supporting evidence. Process presence does not mean foreground activity; ADB observations belong in session provenance only.

Run one capture-free state-control qualification attempt with immutable JSON evidence:

```bash
./run.sh session dry-run com.android.chrome output/state-control/attempt01.json
```

This command requires the Android VPN to be inactive, verifies Chrome foreground, sends one resolved HOME action, and polls state for 15 consecutive seconds. Target resumption, lock, Notification Shade, unrelated activity, unknown evidence, or excessive observation gaps fail immediately. It never starts packet capture.

See [ADB control-plane contract](docs/adb-control-plane.md) for the command matrix and the foreground/background label protocol.

See [physical-device.md](docs/physical-device.md) for the state-transition workflow, metadata, timestamping, and capture constraints.
