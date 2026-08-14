# Validation report

Status: **QUARANTINED**

Passed:

- Correct auxiliary source and unique artifact name.
- TLS decryption and full-payload dumping disabled.
- Capture stopped cleanly; VPN inactive afterward.
- Capture copied and hashed.
- DLT_RAW ingested with 41,109 valid IPv4 packets and no malformed packets.
- Chrome was verified as resumed during the included foreground interval.

Failed:

- Chrome resumed after HOME during the intended background gate.
- No verified `device_control` interval was collected.
- No valid background interval exists.

Permitted use: parser, provenance, foreground-feature, and transition-control diagnostics only. This run must not enter a six-condition dataset or any publication analysis.
