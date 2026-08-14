# Physical Android endpoint

The attached physical Android device is the controlled endpoint for the initial study. ADB is the control and ground-truth plane; packet capture is the independent network-observation plane; CipherTraceDroid analysis uses only capture-derived encrypted-traffic metadata.

## Readiness and provenance

Run `./run.sh device status` before a session. The C++ control plane performs read-only ADB queries and reports concise device/build/network/capture readiness data. Create `./run.sh session plan <package> <new-output.json>` before a run to verify the installed package and save a no-overwrite provenance-and-procedure record. Store this output as session metadata, not as classifier features. `scripts/device-check.sh` remains available for its more detailed operator-oriented checks.

On this Android 15 device, window-focus fields and `dumpsys activity top` can be stale. Use `ResumedActivity` from `dumpsys activity activities` as the primary state probe, with window focus and lifecycle history as supporting provenance. Repeat delayed verification while the display is interactive before every collection campaign.

## Controlled foreground/background run

1. Confirm device readiness and a verified, non-destructive capture location.
2. Record host UTC time `T0`; launch the selected package with `adb shell monkey -p <package> 1` or its documented launchable activity.
3. Verify `ResumedActivity` identifies the selected package; record the start of the foreground interval after the configured settling period.
4. End foreground observation and bring the resolved Android HOME task forward explicitly.
5. Exclude the configurable transition guard. Verify again after the guard that the launcher remains resumed and the target is not resumed before recording background.
6. Record the final host UTC timestamp, package version, device/network provenance, capture hash, and all interval boundaries.

The equivalent C++ commands are `./run.sh session transition <package> foreground` and `./run.sh session transition <package> background`. They first require one authorized device and an installed package, collapse Notification Shade to prevent an overlay intercepting the action, use `monkey` only for foreground launch, explicitly bring forward the Android HOME activity for backgrounding, and print the post-action resumed-activity observation. The host operator remains responsible for timestamps, settling windows, guards, and capture start/stop.

The first Chrome auxiliary pilot exposed an important device-specific failure: a raw HOME key did not provide a verified stable boundary. An immediate observation therefore gave a false sense of success. The control plane now starts the resolved HOME activity explicitly, and the protocol requires a second verification after the full transition guard.

A later whole-device retry showed that a physical/tap-style event can still relaunch the target after a successful guard. Android logged a launcher-UID `MAIN/LAUNCHER` start from the Chrome icon bounds, not an automatic HOME timeout. For physical pilots, keep the device untouched and sample `ResumedActivity` once per analysis window during quiet conditions. Boundary-only checks cannot detect a transient or mid-condition violation.

PCAPdroid 1.9.1 also returned success for an ADB stop intent without reliably stopping the active capture; one sequence then opened a separate zero-byte default-named capture. A PCAPdroid auxiliary run is not clean until the intended named file is finalized, `tun0` remains absent across delayed checks, and the default route is restored. Never merge an unintended follow-on capture into the named artifact.

If the pre-transition observation identifies Notification Shade, CipherTraceDroid stops before sending any state action. Dismiss/unlock the device manually and repeat the transition. On the tested Motorola build, shell-issued collapse, HOME, and touch events did not dismiss an already active shade, so continuing would make the background boundary untrustworthy.

Transitions additionally require an interactive, unlocked screen, which `device status` determines from Android power and trust services. CipherTraceDroid will not attempt to bypass the lock screen; unlock the device normally before starting a controlled run.

At a boundary, run `./run.sh session observe <package>`. It records three evidence types: `ResumedActivity` from `dumpsys activity activities` (primary), `mFocusedApp` and `mCurrentFocus` from `dumpsys window` (supporting), and whether the package process exists (supporting only). A running process does not establish foreground state. On this device, Notification Shade made `dumpsys activity top` stale and a window-focus field can be stale; retain the full observation rather than treating one field as ground truth.

The complete C++ command contract and label sequence are in [adb-control-plane.md](adb-control-plane.md).

The C++ session-plan artifact is intentionally not a session manifest and cannot make a capture valid by itself. After a capture, calculate its SHA-256, record actual start/end boundaries, and create the strict CSV manifest used by `validate-manifest` and `features`.

Do not use force-stop as backgrounding. Do not clear storage, disable services, change account state, or inspect application data. Keep charging, screen, Wi-Fi, VPN, battery-saver, and other material conditions consistent across repeated sessions and record intentional controls.

## Capture status

Capture topology is discovered rather than assumed. On-device `tcpdump` requires both an existing binary and sufficient privileges. If unavailable, investigate a Fedora-side interface or controlled AP only after verifying that it observes the device's traffic. Validate any streaming capture separately for PCAP readability, packet counts, integrity, and termination before using it for research evidence.
