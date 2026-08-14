# Focused literature review

## Most relevant work

| Work | Problem and observation | Method/evaluation | Relevance and limitation |
|---|---|---|---|
| Li et al., *PACKETPRINT*, NDSS 2022 | Open-world app and action inference from encrypted Wi-Fi traffic; packet size and direction, without endpoint identities | Sequential XGBoost and hierarchical bag-of-words; addresses unsegmented, multiplexed traffic | Strong motivation for a conservative feature boundary, but does not evaluate foreground-trained to background-tested app identification. |
| Liu et al., *BACKTRACKER*, IJCNN 2025 | Identifies mobile-app background traffic using Android plus network interception | URL-similarity foreground/background differentiation and a hierarchical deep model | Closest overlap. Its URL-based distinction is outside this project's primary threat model, and its stated goal is background-traffic identification rather than a session-grouped cross-state app-ID matrix. Confirm details from the publisher PDF before paper submission. |
| Saltaformaggio et al., *NetScope*, WOOT 2016 | Fine-grained Android/iOS activity inference from encrypted traffic | IP-header traffic rates, exchanges, and data movement | Demonstrates activity-related leakage, but predates Android 15 and does not isolate foreground/background state effects on app identification. |
| Li et al., *FOAP*, USENIX Security 2022 | Fine-grained open-world Android app fingerprinting | Encrypted TCP-oriented traffic analysis | Useful comparison point; older TCP emphasis motivates recording UDP and probable QUIC rather than assuming TCP-only traffic. |
| van Ede et al., *FlowPrint*, NDSS 2020 | Semi-supervised Android/iOS app fingerprints based on temporal destination correlations | App recognition plus unseen-app detection | Studies evolving apps and traffic dynamics, but does not present the six foreground/background train/test conditions. |
| He et al., *Mobile app identification for encrypted network flows by traffic correlation*, 2018 | Correlates encrypted flows for Android app identification and recognizes that apps continue running after HOME | Flow-correlation app identification | Confirms that background execution matters, but the accessible publisher material does not show the controlled cross-state matrix proposed here. |

## Current protocol and Android context

TLS 1.3 protects application data ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)); QUIC uses TLS 1.3 ([RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001)); and ECH became an IETF standard in 2026 ([RFC 9849](https://datatracker.ietf.org/doc/html/rfc9849)). This strengthens the decision to exclude DNS, SNI, certificates, endpoint identities, and plaintext from the primary matrix.

Android's current documentation says background execution and network access depend on process/app/device state, standby bucket, charging, screen/Doze conditions, and user restrictions. The experiment must record these conditions and avoid silently changing them. See [Android power-management limits](https://developer.android.com/topic/performance/power/power-details) and [background-task restrictions](https://developer.android.com/develop/background-work/background-tasks/bg-work-restrictions).

## Focused overlap check, 2026-08-14

Searches of IEEE, ACM, NDSS, and USENIX publisher material found related background-traffic identification, app fingerprinting, open-world evaluation, app multiplexing, and lifecycle-aware labelling. The reviewed material did not establish an exact prior evaluation containing all six FG/BG train/test conditions with run-grouped splits and the same endpoint-free predictor boundary. This is not an exhaustive novelty claim. BACKTRACKER remains the closest recent work and its complete publisher paper must be reviewed before submission.
