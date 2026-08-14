#!/usr/bin/env bash
set -euo pipefail

interface="wlp3s0"
output_dir=""
if [[ $# -gt 0 ]]; then
    if [[ $# -ne 2 || $1 != "--output-dir" ]]; then
        echo "Usage: $0 [--output-dir <directory>]" >&2
        exit 2
    fi
    output_dir=$2
fi
if [[ -z $output_dir ]]; then output_dir=$(mktemp -d /tmp/ciphertracedroid-ap-diagnose.XXXXXX); fi
mkdir -p "$output_dir"

capture() {
    local name=$1
    shift
    "$@" > "$output_dir/$name" 2>&1 || true
}

capture date-utc.txt date -u
capture uname.txt uname -a
capture nmcli-radio.txt nmcli radio all
capture nmcli-device-status.txt nmcli device status
capture nmcli-wifi-device.txt nmcli -f GENERAL,IP4,IP6,WIRED-PROPERTIES device show "$interface"
capture nmcli-active-connections.txt nmcli connection show --active
capture nmcli-wifi-list.txt nmcli -f ACTIVE,SSID,BSSID,CHAN,FREQ,MODE,SECURITY device wifi list ifname "$interface" --rescan no
capture ip-route.txt ip route
capture iw-dev.txt iw dev
capture iw-phy.txt iw phy
capture rfkill.txt rfkill list
capture station-dump.txt iw dev "$interface" station dump
capture neighbors.txt ip neigh show dev "$interface"
capture dns.txt resolvectl status
capture kernel-wifi-log.txt journalctl -k -b --no-pager
capture networkmanager-wifi-log.txt journalctl -u NetworkManager -b --no-pager

echo "AP diagnostic bundle: $output_dir"
echo "Contains host radio, driver-capability, NetworkManager, route, station, neighbor, and boot-log diagnostics only."
