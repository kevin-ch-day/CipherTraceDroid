# Research-question readiness

**Status date:** 2026-08-14  
**Scope:** encrypted Android traffic metadata under controlled target-app conditions.

This is a decision record, not a result report. It separates evidence that is useful for protocol development from evidence that can answer the primary study questions.

## Evidence currently available

| Evidence plane | Current artifact | What it establishes | What it does not establish |
| --- | --- | --- | --- |
| ADB control plane | Three Chrome capture-free qualifications: two passes and one fail | `ResumedActivity` can detect a stable launcher interval and reject a target resume | That a HOME transition is repeatable enough for collection without a pass immediately before each run |
| Auxiliary capture plane | `chrome_exploratory_run01_retry02`, 443.7 seconds and 8,391 packets | PCAPdroid can provide a valid whole-device VPN-boundary pilot with verified scheduled state sentinels | Physical routed packet behavior, app ownership of individual packets, or a general state effect |
| Analysis plane | Condition-profile bundle v3 | Complete-window accounting, occupancy summaries, and duration sensitivity can be produced without dropping empty windows | Cross-state application identification or uncertainty across independent runs |
| Primary network plane | None | — | The planned whole-device routed measurement |

## Research-question matrix

| Question | Current position | Missing evidence | Collection gate |
| --- | --- | --- | --- |
| Does target foreground/background state alter encryption-visible traffic characteristics? | Open. One auxiliary pilot has descriptive occupancy differences only. | Repeated independent runs, controlled applications, and a validated routed-primary observer. | State qualification passes immediately before every run; primary vantage is proven to contain the device's traffic. |
| Can applications be identified across state changes? | Not started. Only Chrome has a valid all-condition pilot. | Multiple applications, repeated runs per application and state, and run-grouped evaluation. | No application, package, UID, lifecycle, or PCAPdroid association value may enter the predictor matrix. |
| Are state effects asymmetric between foreground→background and background→foreground evaluation? | Not started. | Both state labels for every application across independent runs, then held-out-run directional evaluations. | Use the predefined grouped partitions; do not split windows from one run across train and test. |
| Is `device_control` distinct from target background? | Plausible but unproven. The one auxiliary pilot has 2/12 active control windows and 6/24 active background windows. | Repeated whole-device observations under the explicit force-stopped baseline. | Keep `device_control` separate from background in manifests, profiles, and training labels. |
| Is PCAPdroid acceptable as the main observer? | No. It is useful for auxiliary validation and attribution context. | A routed-primary capture pilot. | Preserve the typed source label and prohibit VPN-boundary evidence from routed-primary claims. |

## State-control decision

The resolved Motorola HOME activity is `com.motorola.launcher3/com.android.launcher3.CustomizationPanelLauncher`. The three immutable qualification attempts are:

| Attempt | Outcome | Guard observation |
| --- | --- | --- |
| `attempt01.json` | Pass | Normal launcher observed for 15 seconds. |
| `attempt02.json` | Fail | Chrome resumed at the two-second observation. |
| `attempt03.json` | Pass | Normal launcher observed for 15 seconds. |

The qualification rate is currently 2/3. This is evidence that the present guard is valuable, not permission to assume that a HOME action always creates a valid background condition. A failed qualification excludes the attempted condition; it must not be repaired by relabeling the interval.

## Minimum next dataset

Do not begin a large collection until a routed-primary pilot proves the observation point. Once that gate is met, the smallest useful exploratory dataset is:

1. Three applications with intentionally different expected network behavior.
2. Three independent accepted runs per application, with equal planned `device_control`, foreground, and background durations.
3. A fresh state qualification before each run and state sentinels at least once per analysis window.
4. One auxiliary PCAPdroid counterpart only where it helps assess attribution or VPN-boundary distortion; never pool it with routed-primary samples.
5. Condition profiles first, followed only by grouped run-level baselines when there are enough independent runs to leave complete runs out for testing.
6. A declared warm-up path and interaction ledger that keeps action details in provenance, never predictors.

Longer captures or more windows within one run do not replace independent runs. Empty scheduled windows remain part of the condition accounting.

## Highest-value next action

Validate a routed capture topology that demonstrably sees the Android device's traffic, then run a short no-content pilot with the state gate. The built-in RTL8852BE AP remains the first candidate, but its initial discovery result needs a manual Android Settings scan because an ADB-requested scan can be throttled. A direct Android-Ethernet segment or managed-network capture point are viable alternatives; USB RNDIS remains invalid. See [routed-primary topology options](routed-topology-options.md). Until this gate is solved, improve the auxiliary protocol and analysis only as method development, not as an answer to the primary research question.
