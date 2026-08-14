# Routed capture requirements

Current status: **BLOCKED ON VALID ROUTED NETWORK TOPOLOGY**.

The built-in RTL8852BE AP activated on Fedora but the phone did not discover or join it. Another attempt is deferred. USB RNDIS tethering is unsuitable because it routes Fedora through the phone instead of routing phone traffic through Fedora.

## Current host finding

The RTL8852BE (`rtw89_8852be`) advertises 2.4 GHz and 5 GHz AP support, and the previous NetworkManager profile reached the activated state on 2.4 GHz channel 11 with a shared IPv4 address. This is host-side capability evidence only; it does not validate Android discovery or association.

At the latest read-only check, Fedora Wi-Fi was software-blocked and `wlp3s0` was unavailable. No AP retry is meaningful until the host operator enables Wi-Fi and the preflight confirms that the radio is usable. This is a current host precondition, not evidence about the Android device or the earlier discovery failure.

An external adapter or alternate topology must provide:

- an in-kernel Linux driver where possible;
- stable 2.4 GHz AP mode with WPA2 on a non-DFS channel;
- NetworkManager shared mode or standard hostapd compatibility;
- successful Android association, DHCP, DNS, and Internet access;
- visibility of the phone's pre-NAT IP traffic on Fedora;
- a libpcap-readable supported link type;
- a stable device IP for explicit direction assignment;
- complete teardown without changing the wired uplink or unrelated VPN configuration.

The pilot must verify packet visibility and direction with a short known device action before any collection protocol is approved. Marketing claims or an adapter merely advertising AP mode are insufficient evidence.

## AP retry gates

Run the read-only diagnostic before and after any approved retry:

```bash
./scripts/ap-pilot-diagnose.sh --output-dir output/diagnostics/ap-preflight-<timestamp>
```

An approved retry may proceed only when all of the following are recorded:

1. `nmcli radio all` reports Wi-Fi enabled and `rfkill` reports no software or hardware block for the Wi-Fi PHY.
2. `wlp3s0` is available to NetworkManager, the wired `enp2s0` uplink remains active, and no unrelated route or VPN change is required.
3. The AP uses a fixed, non-DFS 2.4 GHz channel and WPA2-compatible security; the SSID is confirmed from the phone's visible Wi-Fi settings, not only a host-side scan.
4. Android associates, receives the expected shared-subnet address, resolves a benign test hostname, and reaches a benign HTTPS endpoint.
5. Fedora records the client in `iw dev wlp3s0 station dump` and sees the Android client IP on the AP-side interface during a short known action.
6. A test PCAP is readable by CipherTraceDroid, has the expected link type, and its direction assignment is verified from the assigned phone IP.

Failure at any gate ends the pilot and preserves its diagnostics; it must not be converted into collection evidence.

The first discovery check was requested through ADB. Android limits Wi-Fi scan request frequency on recent releases, so it cannot by itself prove that the phone cannot see an AP. Require a user-visible Android Settings scan for the retry, then preserve the result with the host diagnostic bundle. See [routed-primary topology options](routed-topology-options.md) for the compatible AP profile and Ethernet/managed-network alternatives.
