# Exploratory hypotheses and assumptions

This document separates statements registered before controlled exploratory collection from observations. None is a research finding.

## Hypotheses

- H1: traffic intensity differs between foreground and background operation.
- H2: inter-arrival and burst behavior differs between foreground and background operation.
- H3: IP packet-size distributions differ by activity state.
- H4: directional composition changes by activity state.
- H5: same-state application identification exceeds cross-state identification.
- H6: FG→BG and BG→FG performance changes may be asymmetric.
- H7: state-balanced mixed training may improve cross-state application identification.
- H8: some applications' background traffic may resemble `device_control`, while others remain distinguishable.

## Assumptions

- A verified `ResumedActivity` is the primary Android foreground-state observation.
- HOME can produce a stable non-foreground state without force-stopping the target; every run must verify this rather than assume it.
- PCAPdroid app-filtered data provides auxiliary target-app VPN-boundary evidence, not routed packet behavior.
- A target-app-filtered `device_control` interval is expected to be empty when the target is force-stopped and cannot replace the whole-device control baseline.
- Five-second complete windows are provisionally suitable for exploratory summaries.

## Observed pilot evidence

- `chrome_pilot_run01_20260814T0400Z` produced a valid Chrome-filtered DLT_RAW artifact and 11 verified foreground windows.
- The first HOME transition did not produce a stable background state: Chrome resumed during the intended background gate.
- The run is quarantined and provides no foreground/background comparison.
- `chrome_exploratory_run01` started a whole-device auxiliary capture, but PCAPdroid's capture-control completion reactivated an existing Chrome task. The device-control gate failed before any condition interval began, so the attempt is invalid.
- `chrome_exploratory_run01_retry02` is a valid, unfiltered PCAPdroid VPN-boundary **auxiliary** pilot. Its scheduled state sentinels passed for 60 seconds of `device_control`, 120 seconds of foreground, and 120 seconds of background. It is not routed-primary evidence and cannot establish an app-level or state-effect finding.
- In the associated five-second ledger, foreground had traffic in 23/24 scheduled windows, background in 6/24, and `device_control` in 2/12. These are descriptive observations from one run, not estimates of a state effect.
- Capture-free Chrome state qualification has passed twice and failed once on the tested device. The failed attempt resumed Chrome two seconds after HOME; the later repeat held the normal launcher for the full 15-second guard. The gate therefore detects intermittent contamination but has not yet shown the repeatability needed for collection.

## Unresolved questions

- What caused Chrome to resume repeatedly after HOME during the PCAPdroid capture?
- Can a launcher transition be made stable by returning to the normal launcher home activity before starting the guard?
- Should whole-device unfiltered and target-filtered auxiliary captures be separate protocol variants?
- Does PCAPdroid change Chrome lifecycle behavior, or was the result caused by the launched browser intent or launcher state?
- Does force-stopping Chrome after PCAPdroid activation, followed by explicit HOME and delayed verification, prevent capture-control task return from contaminating device control?
