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
