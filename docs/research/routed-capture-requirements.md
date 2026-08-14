# Routed capture requirements

Current status: **BLOCKED ON VALID ROUTED NETWORK TOPOLOGY**.

The built-in RTL8852BE AP activated on Fedora but the phone did not discover or join it. Another attempt is deferred. USB RNDIS tethering is unsuitable because it routes Fedora through the phone instead of routing phone traffic through Fedora.

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
