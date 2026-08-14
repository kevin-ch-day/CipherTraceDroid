# Threats to validity

- One Android 15 device and one Wi-Fi environment limit generalization.
- App versions, accounts, network conditions, charging, screen state, VPN, Doze, battery restrictions, and unrelated system traffic can change observations.
- Foreground/background labels require independent ADB verification and a documented transition guard.
- Windows are correlated; session/run is the partition unit.
- A capture point may omit or alter observable traffic. Validate its scope before collection.
- Monitor-mode capture can lose packets through channel changes; do not channel-hop during a controlled run.
- Small app/run counts constrain uncertainty estimates; prioritize independent repeated runs over long captures.
