# Physical Android endpoint

The attached physical Android device is the controlled endpoint for the initial study. ADB is the control and ground-truth plane; packet capture is the independent network-observation plane; CipherTraceDroid analysis uses only capture-derived encrypted-traffic metadata.

## Readiness and provenance

Run `scripts/device-check.sh` before a session. It performs read-only ADB queries and reports concise device/build/network/capture readiness data. It also accepts `--package <name>` to report only that installed package's version fields. Store the relevant output as session metadata, not as classifier features.

On this Android 15 device, `dumpsys window` `mFocusedApp=` identified Chrome after launch but remained Chrome after HOME while Notification Shade held `mCurrentFocus`. It is therefore not sufficient alone for background verification. `dumpsys activity top` identified Chrome after launch and the Motorola launcher after HOME; use it as the primary package-state probe, recording both commands as supporting provenance. Repeat this check while the display is interactive before every collection campaign.

## Controlled foreground/background run

1. Confirm device readiness and a verified, non-destructive capture location.
2. Record host UTC time `T0`; launch the selected package with `adb shell monkey -p <package> 1` or its documented launchable activity.
3. Verify `mFocusedApp` identifies the selected package; record the start of the foreground interval after the configured settling period.
4. End foreground observation, record the boundary, send `adb shell input keyevent KEYCODE_HOME`, then verify that the selected package is no longer `mFocusedApp`.
5. Exclude the configurable transition guard. Record the background interval only after the guard expires.
6. Record the final host UTC timestamp, package version, device/network provenance, capture hash, and all interval boundaries.

Do not use force-stop as backgrounding. Do not clear storage, disable services, change account state, or inspect application data. Keep charging, screen, Wi-Fi, VPN, battery-saver, and other material conditions consistent across repeated sessions and record intentional controls.

## Capture status

Capture topology is discovered rather than assumed. On-device `tcpdump` requires both an existing binary and sufficient privileges. If unavailable, investigate a Fedora-side interface or controlled AP only after verifying that it observes the device's traffic. Validate any streaming capture separately for PCAP readability, packet counts, integrity, and termination before using it for research evidence.
