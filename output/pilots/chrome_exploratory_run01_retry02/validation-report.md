# Validation report

Status: **VALID AUXILIARY PILOT — insufficient modeling volume**

Passed before feature extraction:

- Fresh, explicitly named, unfiltered whole-device PCAPdroid artifact.
- TLS decryption, full-payload dumping, and QUIC blocking disabled.
- DLT_RAW capture ingested with 8,391 IPv4 packets and no malformed packets.
- Exact non-overlapping intervals: 60 seconds device control, 120 foreground, and 120 background.
- ADB state gates and periodic sentinels passed for every included interval.
- Capture hash recorded and the manifest references only that hash.
- Standby bucket unchanged at 10.
- VPN interface removed and Wi-Fi route restored after stopping.
- Manifest validation passed for all three rows.
- Feature extraction produced 31 finite schema-v1 rows.

Window-volume result:

- Device control: 2 of 12 complete windows were non-empty and exported.
- Foreground: 23 of 24 complete windows were non-empty and exported.
- Background: 6 of 24 complete windows were non-empty and exported.
- Total: 31 of 60 scheduled complete windows were non-empty under schema v1.

The run is valid for capture/control-path validation and descriptive diagnostics. It is not large enough for training, testing, state-effect inference, or repeatability claims. Schema v1 omits empty windows; that rule makes quiet-state duration, rather than total packet count, the limiting factor.

Payload-free transport diagnostics found 337 foreground and 142 background UDP/443 packets. UDP/443 is only a probable-QUIC heuristic: it can include non-QUIC traffic and miss QUIC on other ports, so it is not treated as confirmed protocol identity. The apparent foreground/background differences are descriptive only and cannot establish a state effect.

Limitations:

- This is VPN-boundary auxiliary evidence, not primary routed capture.
- It is one valid exploratory run, so repeatability is unknown.
- A preceding retry was invalidated by a physical/tap-style Chrome launch and is not merged with this run.
- The stop intent is unreliable and initiated a separate zero-byte capture; cleanup required the visible PCAPdroid control.
- No state effect or application-identification claim is supported by one run.
