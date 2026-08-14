# Capture architecture decision

## VPN-boundary IP-length semantics

DLT_RAW observations produced at the PCAPdroid VPN/TUN boundary can contain IP representations larger than a physical routed-interface MTU. These observations may reflect aggregation, synthesis, or pre-segmentation behavior. The exact mechanism is not assumed without authoritative evidence. CipherTraceDroid therefore describes them as VPN-boundary IP-length observations, never physical wire-packet sizes. Feature Schema v1 retains its IP-length definition, while capture source remains mandatory provenance so routed and VPN-boundary measurements are not pooled as equivalent.

## Observed Fedora topology

The development host reaches the current LAN and Internet through wired `enp2s0` (`192.168.0.139`). Its unused `wlp3s0` is a Realtek RTL8852BE and advertises AP and monitor modes. The Android device is a separate Wi-Fi client (`192.168.0.23`). A WireGuard interface is also active. No host network configuration was changed during this assessment.

| Option | Feasibility now | What it measures | Decision |
|---|---|---|---|
| Existing host capture | Not sufficient | Host traffic, not reliably another protected Wi-Fi client's unicast traffic | Reject as an evidence source unless a pilot proves device packets are present. |
| Fedora wired-to-Wi-Fi AP | Hardware-capable; requires activation | Whole-device IP traffic routed through the host, normally Ethernet-link PCAP on the routed interface | Recommended after user approval. |
| Monitor-mode Wi-Fi | Hardware-capable; requires activation/channel control | 802.11 frames, potentially encrypted and incomplete | Not selected for the paper MVP. |
| Android VPNService / PCAPdroid | Installed (v1.9.1); requires per-capture user consent or a user-managed API key | Target-app-filtered packets at the VPN TUN boundary, not post-VPN Internet packets | Auxiliary attribution and validation evidence; never the primary observer. |

## Recommended method

Use `wlp3s0` as a dedicated NetworkManager AP sharing the wired `enp2s0` connection, then capture the phone's routed IP traffic on the host. AP activation changes Wi-Fi state, creates DHCP/NAT/forwarding rules, and makes the host part of the traffic path; it therefore requires explicit approval before activation. It does not decrypt TLS, but it does measure a host-routed vantage rather than a passive over-the-air observer. Validate the eventual link type with `pcap_datalink()` and run a short pilot before collection.

### 2026-08-13 pilot result

NetworkManager successfully activated a WPA AP on channel 11 with gateway `10.42.0.1`, while the wired route remained healthy. The Android device did not discover the SSID in a fresh ADB-requested scan and `cmd wifi connect-network` returned `Network is unreachable`; no Android packets reached the AP, no capture was started, and the profile was deleted. The initial AP method is therefore **not validated**. Investigate radio/firmware/channel compatibility with a user-visible phone scan or a second Wi-Fi adapter before retrying; do not treat host-side AP activation as proof of client reachability.

## PCAPdroid fallback assessment

The attached device has PCAPdroid 1.9.1 installed and its capture-control activity is present. A read-only `get_status` Intent completed without starting a VPN. Its VPN capture must still be started with the user's consent dialog or a user-generated API key; CipherTraceDroid does not store or generate that key.

This fallback is suitable for app-filtered connection metadata and an independently auditable control capture. It is an **auxiliary attribution plane**, not a substitute for routed capture: PCAPdroid documents that non-root mode captures the app-to-VPN leg and synthesizes aspects of L3/L4 behavior. App filter identity, Android UID, and PCAPdroid association remain ground truth only and never enter the feature matrix. Do not enable TLS decryption or full-payload dumping for this project.

PCAPdroid's documented caller authorization relies on an Android app using `startActivityForResult`, which does not fit a host-side ADB caller. Unattended ADB control therefore requires PCAPdroid's user-generated API key. CipherTraceDroid now builds fixed argument vectors for `get_status`, start, stop, and artifact pull, forces TLS decryption/full payload off, validates artifact names, and redacts the key in any diagnostic representation. It does not expose a live start command until orchestration and status confirmation are complete. The documented Intent API necessarily places the key in the `adb`/Android activity-manager argument chain, so a same-host or privileged device observer may briefly see it; use the runtime environment only, never plans or result artifacts.

The first non-exporting control request ultimately produced a 77.6-second PCAP-file artifact after PCAPdroid's UI flow was completed. It uses raw-IP `DLT_RAW` (12), which CipherTraceDroid now parses. The artifact contains TCP/443 and UDP/443 traffic, so it is evidence that probable QUIC remained present under the VPN capture mechanism. It is not yet a controlled Chrome dataset: capture start/stop was not fully API-controlled, Chrome had just updated/onboarded, and the app filter has not been independently audited from the packet artifact.

USB RNDIS tethering was also assessed and rejected as a phone-traffic capture path. It makes Fedora a tethered client of the phone, so it does not put the phone's own Wi-Fi egress through a host-observable interface.

## Attribution and control

Frame/packet attribution to an individual app is not available from a whole-device routed capture. The immediate study is therefore a **whole-device controlled-condition study**: the label denotes the controlled target-app state while Android/system traffic remains part of the observer's measurement. It must not claim every packet is generated by the target app.

Collect `device_control` separately: launcher visible, no deliberate interaction, and the target package force-stopped specifically for this baseline. It is not a background label. Compare it with target-background windows to identify shared device/environment behavior.

## Sources

NetworkManager supports AP/shared connections when the adapter advertises AP mode. Android `VpnService` delivers packets through a TUN interface; PCAPdroid documents that its non-root PCAP is at that VPN boundary. See the [NetworkManager manual](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html), [Android VpnService](https://developer.android.com/reference/android/net/VpnService.html), and [PCAPdroid architecture](https://github.com/emanuele-f/PCAPdroid/blob/master/docs/how_it_works.md).
