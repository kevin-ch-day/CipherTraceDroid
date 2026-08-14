# ADB state evidence

This file is label and provenance evidence only. None of these values are predictors.

- Capture activation was verified through `tun0` with device address `10.215.173.1` before the target-state gate.
- Chrome was force-stopped after capture activation. After a 20-second guard, the Motorola launcher was resumed and the Chrome process was absent.
- Device control: 12 of 12 five-second sentinels showed `com.motorola.launcher3/com.android.launcher3.CustomizationPanelLauncher`; Chrome was absent at the end gate.
- Foreground: Chrome was resumed and focused after the 15-second guard. Checkpoints after the page load, +30-second scroll, +60-second reload, +90-second scroll, and end gate all showed Chrome resumed.
- Background: after HOME and a 15-second guard, 24 of 24 five-second sentinels showed the Motorola launcher resumed. Chrome remained a resident process but was never the resumed activity.
- Screen was interactive and unlocked at preflight. No system overlay was reported at state gates.
- Host-to-device clock offset was zero seconds.
- Chrome standby bucket was 10 before and after collection and was not changed.
- The intended VPN was stopped from PCAPdroid's visible Stop control. `tun0` was absent in six checks over 18 seconds and routing returned to Wi-Fi.

The first stop intent did not stop capture and later initiated an unwanted zero-byte default-named capture. That second capture was stopped through the visible control and is excluded. Only the explicitly named, hashed artifact is referenced by the manifest.
