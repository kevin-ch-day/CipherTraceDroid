# ADB state evidence

- Capture confirmed: `2026-08-14T04:05:17.183060207Z`
- Foreground start: `2026-08-14T04:05:17.337691885Z`
- Foreground observation: Chrome `ResumedActivity`; consistent.
- Foreground end: `2026-08-14T04:06:15.248891024Z`
- HOME sent: `2026-08-14T04:06:15.445290512Z`
- Immediate observation: Motorola launcher `CustomizationPanelLauncher` resumed.
- Intended background start check: `2026-08-14T04:06:37.804644125Z`
- Intended background observation: Chrome was `ResumedActivity`; inconsistent.
- Stop requested: `2026-08-14T04:07:17.535148225Z`
- Cleanup: VPN inactive after stop.

The attempted background interval is excluded. Only the verified foreground interval is included in `state-intervals.csv`.
