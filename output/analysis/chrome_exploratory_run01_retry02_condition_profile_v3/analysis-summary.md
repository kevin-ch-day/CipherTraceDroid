# Retry 02 condition analysis

Status: **exploratory observation from one auxiliary run**

The canonical pilot bundle was read but not modified. This analysis preserves all 60 scheduled five-second windows in a separate ledger:

- Device control: 12 scheduled, 2 active, 10 quiet; occupancy 0.1667; longest quiet sequence 30 seconds.
- Foreground: 24 scheduled, 23 active, 1 quiet; occupancy 0.9583; longest quiet sequence 5 seconds.
- Background: 24 scheduled, 6 active, 18 quiet; occupancy 0.25; longest quiet sequence 50 seconds.

The condition profiles preserve full-interval packet rates and quietness without converting empty packet statistics into zero-valued Schema-v1 features. Application, condition, run ID, ADB state, and capture source remain metadata rather than predictors.

Recommended provisional modeling view: **condition-level profiles only** for the initial cross-state model. Five-second windows remain useful for timelines, transition inspection, occupancy, and active-window characterization. Longer windows increase occupancy but reduce a condition to very few correlated within-run observations; they do not increase independent replication.

No state effect, repeatability, classification performance, or publication claim is supported by this one PCAPdroid auxiliary run.
