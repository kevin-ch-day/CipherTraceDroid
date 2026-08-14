# Evidence-backed research gap

Existing encrypted-traffic work establishes that app identity and fine-grained activity can be inferred in several observation models. PACKETPRINT studies open-world wireless app/action inference without endpoint identities. BACKTRACKER is a close, potentially overlapping 2025 background-traffic study and must be cited and checked against its full paper before submission.

The proposed study is narrower: it evaluates whether an application-identification model changes when training and test traffic are separated by independently verified Android foreground/background state. The required result is a session-grouped matrix of FG→FG, FG→BG, BG→BG, BG→FG, mixed→FG, and mixed→BG results, plus traffic-characteristic comparisons. It excludes URLs and other endpoint identities from primary features.

This is an investigation, not a priority claim. If the full BACKTRACKER paper already reports this exact matrix under a comparable metadata-only threat model, adjust the paper toward replication under Android 15, explicit state validation, and grouped-session evaluation rather than claiming novelty.
