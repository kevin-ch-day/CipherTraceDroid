# ADB control-plane contract

ADB establishes experimental conditions and records supporting provenance. It never supplies packet features and cannot attribute whole-device routed traffic to an individual application.

## Command matrix

| C++ command | Device effect | Evidence produced | Research use |
|---|---|---|---|
| `device status` | None | OS, API level, shell privilege, tcpdump availability, route | Preflight capability check |
| `session plan <package> <new.json>` | None | Package/device snapshot and required collection gates | Immutable pre-run provenance |
| `session observe <package>` | None | Top activity, focus fields, process presence | Boundary evidence |
| `session history <package>` | None | Recent Android lifecycle events and device timestamps | Supporting boundary timeline |
| `session transition <package> foreground` | Launches the installed package | Post-action state observation | Begin a foreground settling period |
| `session transition <package> background` | Sends HOME | Post-action state observation | Begin a background transition guard |
| `session dry-run <package> <new.json>` | Launches package once, sends HOME once | Approximately one-second classified observations and lifecycle history | Capture-free state-control qualification |

All commands require exactly one authorized ADB device. Commands that write an artifact refuse an existing file. The control plane does not force-stop apps, clear data, grant permissions, install software, alter network state, or start packet capture.

Before a transition, CipherTraceDroid checks for Notification Shade through `mCurrentFocus`. If active, it refuses the action and requires manual dismissal. A system overlay can intercept or mask a HOME transition; the tool must fail closed instead of emitting a questionable state label.

Transitions also require Android to report an awake screen and an unlocked user. The tool uses the power and trust service reports as gates and never attempts to bypass a device lock screen.

`session dry-run` additionally requires the VPN to be inactive and the explicit `--hands-off-confirmed` acknowledgment after the phone has been untouched for at least five seconds. Its stabilizer requires 15 continuous seconds of non-target state and a normal launcher final state. Launcher-owned transients are permitted only within the excluded guard. Target resumption, lock, Notification Shade, unrelated activity, unknown evidence, or an excessive polling gap fails immediately. A future coordinator-generated background manifest row requires the resulting pass object; legacy manifests remain readable for artifact traceability.

`device status` samples Android and host epoch seconds around an ADB query and reports the whole-second device-minus-host offset. This records clock alignment for provenance; PCAP boundaries are still host-relative because the capture originates on Fedora.

## PCAPdroid fallback

`device status` also reports whether PCAPdroid is installed and whether Android currently reports an active VPN. PCAPdroid must be activated through its own explicit user-consent/API-key workflow; CipherTraceDroid neither stores its API key nor attempts to bypass the Android VPN consent flow. Its non-root VPN capture is an auxiliary attribution/validation plane, not a primary capture replacement. PCAPdroid app identity, UID, and process association are ground truth only and cannot become model features.

## State-label protocol

1. Run `device status` and create one `session plan` per intended collection run.
2. Start the independently validated packet capture process and record host UTC `capture_start`.
3. Run foreground transition; record host UTC `foreground_requested` and `session observe` output.
4. Wait the configured settling period. Record the foreground interval start only after that period.
5. Run background transition; record host UTC `background_requested` and `session observe` output.
6. Exclude the configured transition guard. Record the background interval start only after the guard.
7. During physical pilots, sample `ResumedActivity` at the feature-window cadence; abort the affected condition on an unexpected target resume.
8. Stop capture, verify delayed VPN/interface cleanup, hash the explicitly named PCAP, and populate strict manifest intervals relative to capture start.

`ResumedActivity` from `dumpsys activity activities` is the primary state indication. `mFocusedApp`, `mCurrentFocus`, and process existence are supporting evidence only. A process can continue running after HOME, and window focus can reflect Notification Shade or another overlay. This device showed that `dumpsys activity top` can remain stale while Notification Shade is expanded. Multi-window or picture-in-picture requires the run to be excluded or separately labelled.

`session history` filters `dumpsys usagestats` to the selected package's `ACTIVITY_RESUMED`, `ACTIVITY_PAUSED`, and `ACTIVITY_STOPPED` records. These timestamps support a boundary timeline but are not substituted for host UTC capture boundaries, which remain the alignment reference for PCAP intervals.

On the tested PCAPdroid 1.9.1 build, an ADB stop intent can return success without stopping and can initiate a separate default-named capture. Verify the live VPN interface and route after stop; accept only the intended explicitly named and hashed artifact.

## Why HOME, not force-stop

HOME models a normal user navigation event. A background Android activity can remain alive and later be killed by the system; force-stopping changes app/process behavior and is reserved only for a separately labelled `device_control` baseline. Android documents that activity lifecycle transitions distinguish active, visible, stopped, and destroyed states; these are not interchangeable labels.

## Source basis

Android documents ADB's per-device `-s` targeting and `adb shell` command model in its [ADB guide](https://developer.android.com/tools/adb). Android's [activity lifecycle reference](https://developer.android.com/reference/android/app/Activity) distinguishes foreground, visible, stopped, and process states, while its [activity state-change guide](https://developer.android.com/guide/components/activities/state-changes) explains HOME/Overview behavior and multi-window ambiguity. The C++ implementation therefore uses structured ADB arguments, avoids interpreting process presence as a foreground label, and records rather than hides probe disagreements.
