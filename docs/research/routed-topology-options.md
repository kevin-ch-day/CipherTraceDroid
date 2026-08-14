# Routed-primary topology options

This decision aid is for the planned whole-device, routed-primary observer. It does not change the separate role of PCAPdroid as VPN-boundary auxiliary evidence.

## Requirement

The selected path must make the Android device's ordinary IP traffic traverse an observable capture point before it reaches the Internet. Fedora must be able to record a supported PCAP, know the Android address used for direction, and preserve the captured artifact without TLS decryption or full-payload inspection.

## Options ranked by research value

| Option | Measurement fit | Main dependency | Recommendation |
| --- | --- | --- | --- |
| Fedora wired uplink → dedicated Wi-Fi AP → Android | Strong: Fedora routes the phone traffic and can capture on the AP-side interface | Stable AP discovery and association | Retry only through the explicit preflight gates. |
| Android USB-C Ethernet → second Fedora Ethernet interface → Fedora wired uplink | Strong: a direct routed Ethernet segment gives clear device-IP visibility | Compatible USB-C Ethernet hardware and a spare Fedora network interface | Best fallback when available; avoids Wi-Fi radio uncertainty. |
| Existing AP uplink through a managed-switch mirror, or a router that records its own client-side PCAP | Strong only if the device traffic and direction are demonstrably visible at the mirror/router capture point | Administrative access and an exportable PCAP | Good alternative when network equipment is available. Capture on the router/client-side point, not merely on Fedora's unrelated host interface. |
| Dedicated Linux-supported USB Wi-Fi adapter as Fedora AP | Potentially strong | AP-mode driver quality, Android association, and the same routed-pilot gates | Practical replacement if the built-in adapter continues to fail. |
| Wi-Fi monitor mode | Weak for this MVP | Channel lock, protected-frame handling, loss behavior, and difficult packet reconstruction | Do not use as the primary path. |
| Android phone hotspot with Fedora as a client | Does not fit | Fedora observes its own client traffic, while the phone remains the router | Reject. |
| USB RNDIS tethering from Android to Fedora | Does not fit | Fedora is a client of the phone's routing/NAT | Reject. |
| Android VPN to Fedora | Does not fit | Captures an outer tunnel or VPN boundary and changes transport behavior | Keep only as an auxiliary-method comparison. |

## Existing-AP retry: diagnostic sequence

The first failed discovery check used an ADB-requested scan. Android limits scan request frequency on recent releases, so that result is insufficient to diagnose radio visibility on its own. Android's Wi-Fi settings screen is the required visibility check for an approved retry; it should show the exact SSID, security type, and signal before any attempt to join.

After host Wi-Fi is enabled, use a new no-autoconnect pilot profile with these compatibility-oriented settings:

| Property | Initial value | Why |
| --- | --- | --- |
| Band/channel | 2.4 GHz, fixed non-DFS channel 1, 6, or 11 | Makes channel selection explicit and avoids DFS behavior. |
| Channel width | 20 MHz | Reduces compatibility variables. |
| Security | WPA personal using RSN/WPA2 and CCMP | Avoids a WPA3-only requirement. |
| Protected management frames | Optional, never required | NetworkManager documents optional and required modes; requiring it can exclude older clients. |
| SSID | Visible, unique, no reused saved network name | Lets the human observer verify the exact AP and prevents stale Android network state from being mistaken for the pilot. |
| Autoconnect | Disabled | Prevents an experimental AP profile from changing host state outside the approved pilot. |

Use a new profile ID and a new evidence directory for each attempt. Record the before/after diagnostic bundle, Android's manual visibility result, association status, DHCP lease, client station record, and a readable short test PCAP. A missing SSID, association failure, DHCP failure, or absent station entry is a topology failure, not a dataset row.

## Ethernet fallback design

If the phone supports a USB-C Ethernet adapter, connect it to a dedicated Fedora Ethernet interface that is not the current Internet uplink. Configure Fedora to route that interface to the existing wired uplink, assign the Android Ethernet address through a controlled DHCP range, and capture on the dedicated interface. Verify Android uses Ethernet for the test route before collecting any research traffic. This approach requires hardware compatibility testing but avoids the Wi-Fi AP and scan-control variables.

## Decision rule

Choose the first topology that completes the entire pilot chain: device-visible link, association or Ethernet link, address assignment, benign Internet test, device-IP packet visibility, readable PCAP, and clean teardown. Do not choose based on advertised AP support alone.

## Sources

Android documents that recent releases limit Wi-Fi scan requests, so an ADB-triggered scan may be throttled. [Android Wi-Fi scanning overview](https://developer.android.com/develop/connectivity/wifi/wifi-scan)

NetworkManager documents fixed Wi-Fi band/channel settings, WPA personal modes, protected-management-frame modes, and hotspot creation. [NetworkManager Wi-Fi settings](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html) and [nmcli hotspot reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)
