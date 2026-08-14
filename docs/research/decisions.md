# Research decisions

## 2026-08-13 — Primary observer features

**Decision:** use packet timing, lengths, direction, IP version, and transport class; exclude endpoint identities, DNS, SNI, certificates, URLs, plaintext, package/version, and ADB state.

**Reason:** the study measures encryption-visible metadata under a conservative passive-observer model.

**Alternatives:** URL/SNI-based separation, rejected because it changes the threat model and overlaps BACKTRACKER's reported URL-similarity approach.

## 2026-08-13 — Partition unit

**Decision:** group train/test partitions by session/run, never window.

**Reason:** windows from one run are correlated and would leak capture-specific behavior.

**Alternatives:** window-level random splitting, rejected for the primary study.

## 2026-08-13 — State boundaries

**Decision:** create windows only inside manifest state intervals; transition intervals are retained as provenance and excluded by default.

**Reason:** avoids ambiguous state labels.

**Alternatives:** label windows spanning a transition, rejected.

## 2026-08-13 — Capture vantage validation

**Decision:** do not use normal host-interface capture as evidence until it demonstrably includes the phone's packets.

**Reason:** a host Wi-Fi interface generally captures its own traffic, while observing another protected Wi-Fi client can require a validated monitor-mode or AP vantage point.

**Alternatives:** assume promiscuous mode is sufficient, rejected because it can silently omit protected client traffic.

## 2026-08-13 — Study framing and control

**Decision:** frame the paper MVP as whole-device controlled target-app conditions and add `device_control`.

**Reason:** routed device capture provides no defensible packet-to-app attribution. The control estimates shared device/environment traffic.

**Alternatives:** per-app packet claims, deferred until a capture source supplies attribution without entering the predictor matrix.

## 2026-08-14 — Capture-source enforcement

**Decision:** represent routed-primary, PCAPdroid auxiliary, and synthetic sources with a typed capability model carried in sample metadata.

**Reason:** publication eligibility and routed-timing requirements must fail before training when a source cannot support them.

## 2026-08-14 — Feature Schema v1

**Decision:** packet size means IP packet length; non-IP frames are capture diagnostics only; direction uses explicit device identity; primary windows are complete fixed-duration intervals.

**Reason:** these definitions correspond to the intended routed observer and avoid frame-header, tail-duration, and direction-guess artifacts.

## 2026-08-14 — Mixed training

**Decision:** mixed training contributes the same deterministic sample count from each application/run/state group, using training data only.

**Reason:** a longer state segment must not dominate solely by producing more windows. Test-set information is never consulted.

## 2026-08-14 — State qualification is a per-run gate

**Decision:** require a newly passing capture-free state qualification before each physical collection run, and exclude any condition whose sentinel detects an unexpected target resume.

**Reason:** on the tested Motorola device, two 15-second qualifications held the normal launcher while one resumed Chrome at two seconds. A HOME request alone is therefore insufficient evidence of a background label.

**Alternatives:** infer background from process presence, a single immediate launcher probe, or the command success result; rejected because all can miss a later task return.

## 2026-08-14 — Manifest integrity before analysis

**Decision:** recompute every capture SHA-256, reject overlapping ranges within a capture, and require each manifest interval to fit the readable PCAP timeline before accepting a manifest for analysis.

**Reason:** file presence and a hash-shaped string do not establish that the current capture matches the recorded evidence. Overlapping or out-of-coverage intervals can duplicate observations or turn an absent capture tail into apparent quiet traffic.

**Alternatives:** defer these checks to feature export; rejected because a separately successful `validate-manifest` command must be meaningful on its own.
