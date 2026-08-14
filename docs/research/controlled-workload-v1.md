# Controlled workload protocol v1

**Status:** proposed for the first routed-primary pilot.  
**Purpose:** make target-app conditions comparable without treating content, identities, or Android control data as model features.

## Problem addressed

Foreground/background is not the only source of traffic variation. First-run onboarding, background sync, account notifications, network retries, and different user actions can all change packet timing and sizes. A condition label is meaningful only when the surrounding workload is recorded and intentionally constrained.

## Run preparation

Before every independent run, record as provenance:

- target package and app version;
- device build, battery/charging state, screen state, Wi-Fi or Ethernet link, VPN state, and host/device clock offset;
- capture source and topology identifier;
- whether the app has been warmed in a separately labelled preparation step;
- environmental exceptions such as an incoming notification, connection drop, lock event, or operator interaction.

Do not place any of these values in the feature matrix or use them as labels for application identification.

## Condition schedule

Use equal planned durations for the first routed-primary exploratory runs:

| Segment | Planned duration | Required state | Permitted deliberate interaction |
| --- | ---: | --- | --- |
| `device_control` | 120 seconds | Target force-stopped; normal launcher visible | None after the start boundary. |
| foreground | 120 seconds | Target `ResumedActivity` verified | One predeclared, repeatable app action before the timed interval; then none. |
| transition guard | At least 15 seconds | Launcher qualification passes | None. This interval is excluded from features. |
| background | 120 seconds | Launcher remains verified; target is not resumed | None. |

The timed foreground interval begins only after the predeclared action has completed and the app has settled. The action itself belongs in a separate transition/provenance interval, not in a feature window. If an app cannot perform a comparable benign action without credentials, private content, or a user-specific feed, use only the open-and-settle condition and label the limitation.

## Interaction ledger

Every run gets a short immutable ledger. It records the action category and timing, not sensitive content.

| Field | Example | Rule |
| --- | --- | --- |
| `run_id` | `app_a_run03` | Matches manifest run grouping. |
| `phase` | `foreground_preparation` | Never an analysis state label. |
| `action_category` | `launch`, `open_static_screen`, `refresh`, `none` | Use a controlled vocabulary. |
| `host_epoch` | UTC timestamp | Aligns with capture and ADB provenance. |
| `completion_observation` | `ResumedActivity verified` | Records that the action completed. |
| `exception` | `none` | Records only protocol-relevant deviations. |

Never record URLs, search terms, message text, account names, contacts, page titles, DNS names, cookies, payloads, or screenshots in this ledger. The ledger must not be merged into exported feature rows.

## Application selection

Choose applications before collection using these inclusion criteria:

1. Installed and launchable through ADB without bypassing Android security.
2. Can remain open without credentials or intentional private content.
3. Has an understandable warm-up path recorded outside the timed condition.
4. Can complete the same state schedule with no notification or overlay interference.
5. Has a stable version recorded for all its repeated runs.

Exclude an application/run when onboarding, a permission prompt, a captive portal, a system overlay, a notification-driven task return, or an account-specific event changes a timed interval. Exclusion preserves validity; it is not a missing label to fill later.

## Analysis safeguards

- Retain complete scheduled empty windows in condition accounting.
- Group all intervals from one run in the same train/test partition.
- Report condition profiles before model scores.
- Compare routed-primary data only with routed-primary data. Use PCAPdroid counterparts solely to characterize the auxiliary measurement plane.
- Treat a state effect as an open question until repeated independent routed-primary runs support it.

## Pilot acceptance

The first pilot is accepted only if the topology gates, pre-run state qualification, every scheduled state sentinel, capture integrity checks, and interaction ledger all pass. A valid pilot establishes a collection method; it does not establish an effect size or classification result.
