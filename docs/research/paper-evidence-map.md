# Paper evidence map

No table below implies a result. It maps future validated inputs to required outputs.

| Question | Required input | Experiment | Metric/output | Paper destination |
|---|---|---|---|---|
| RQ1: activity-state traffic characterization | Routed-primary, state-bounded runs | Foreground versus background feature characterization grouped by run | Per-state descriptive statistics and limited distribution comparisons | Traffic-characteristics table/figure |
| RQ2: cross-state app identification | Routed-primary runs with multiple app labels | FG→FG, FG→BG, BG→BG, BG→FG | Macro F1, per-app metrics, confusion matrices | Six-condition matrix and confusion figure |
| RQ3: state-balanced training | Same routed dataset; balance from training runs only | Mixed→FG and Mixed→BG versus single-state training | Macro F1 comparison and per-app changes | Mixed-training table |
| Secondary control | Background plus separately collected `device_control` | Background versus target-force-stopped control | Feature characterization only unless later justified | Threats/control subsection |

Canonical future bundle files are `six-condition-matrix.csv`, `metrics.csv`, `confusion-matrix.csv`, `predictions.csv`, and a later `feature-characterization.csv`.
