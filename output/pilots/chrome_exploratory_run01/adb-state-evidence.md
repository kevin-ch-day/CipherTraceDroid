# ADB state evidence

Before capture, Chrome was force-stopped, its process was absent, the launcher was resumed, the screen was interactive/unlocked, and standby bucket was 10.

After PCAPdroid capture activation, the explicit HOME transition initially reported the Motorola launcher. Three seconds later the required gate observation reported Chrome as `ResumedActivity` with a running process. The device-control interval therefore never began; the subsequently printed timer timestamp is an invalid attempted boundary.

At cleanup, Chrome was no longer resumed, standby bucket remained 10, and PCAPdroid VPN was inactive after the researcher manually stopped it.
