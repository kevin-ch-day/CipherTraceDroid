# Provisional sample planning

The independent replication unit is one physical run, not a packet or five-second window.

| Plan | Profiles per app/condition | Intended use | Limitation |
|---|---:|---|---|
| 3 pilot runs per app | 3 | Validate automation, estimate gross operational variation, identify failures. | Too few to claim stable performance or final adequacy. |
| 5 independent runs per app | 5 | Exploratory grouped evaluation and variance inspection. | Still a provisional design; confidence intervals will be wide. |
| 8 independent runs per app | 8 | Better estimate of between-run variability and grouped cross-state behavior. | Not automatically statistically sufficient; effect size and variance remain unknown. |

Packet totals and active-window counts are workload diagnostics, not substitutes for independent runs. The preferred initial modeling sample is one Condition Profile Schema v1 row per run and condition.

Future protocol recommendation: use equal 120-second device-control, foreground, and background intervals, with variable excluded transition guards. Equal duration simplifies rates and direct descriptive comparisons. This is a recommendation only; adopting it requires a versioned protocol update.
