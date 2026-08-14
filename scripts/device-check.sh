#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 [--package <package-name>]"
}

package_name=""
if [[ $# -gt 0 ]]; then
    if [[ $# -ne 2 || $1 != "--package" || ! $2 =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$ ]]; then
        usage >&2
        exit 2
    fi
    package_name=$2
fi

if ! command -v adb >/dev/null; then
    echo "error: adb is not available on PATH" >&2
    exit 1
fi

mapfile -t devices < <(adb devices | awk '$2 == "device" { print $1 }')
if [[ ${#devices[@]} -ne 1 ]]; then
    echo "error: exactly one authorized ADB device is required; found ${#devices[@]}" >&2
    adb devices -l >&2
    exit 1
fi

serial=${devices[0]}
adb_cmd=(adb -s "$serial")
prop() { "${adb_cmd[@]}" shell getprop "$1" | tr -d '\r'; }

route=$("${adb_cmd[@]}" shell ip route get 1.1.1.1 2>/dev/null || true)
interface=$(awk '{ for (i = 1; i <= NF; ++i) if ($i == "dev") print $(i + 1) }' <<<"$route" | head -n 1)
device_ip=$(awk '{ for (i = 1; i <= NF; ++i) if ($i == "src") print $(i + 1) }' <<<"$route" | head -n 1)
shell_uid=$("${adb_cmd[@]}" shell id -u | tr -d '\r')
su_path=$("${adb_cmd[@]}" shell which su 2>/dev/null | tr -d '\r' || true)
tcpdump_path=$("${adb_cmd[@]}" shell which tcpdump 2>/dev/null | tr -d '\r' || true)

echo "ADB: available"
echo "Device: authorized"
echo "Serial: $serial"
echo "Manufacturer/model: $(prop ro.product.manufacturer) / $(prop ro.product.model)"
echo "Android release/API: $(prop ro.build.version.release) / $(prop ro.build.version.sdk)"
echo "Security patch: $(prop ro.build.version.security_patch)"
echo "Build fingerprint: $(prop ro.build.fingerprint)"
echo "Network route: ${route:-unavailable}"
echo "Active interface/IP: ${interface:-unknown} / ${device_ip:-unknown}"
echo "ADB shell UID: $shell_uid"
echo "Root indication: $([[ $shell_uid == 0 ]] && echo available || echo unavailable)"
echo "su binary: ${su_path:-not found}"
echo "tcpdump: ${tcpdump_path:-not found}"
echo "Foreground probe (mFocusedApp):"
"${adb_cmd[@]}" shell dumpsys window | awk '/mFocusedApp=/{print; exit}'
echo "Current-focus probe (mCurrentFocus):"
"${adb_cmd[@]}" shell dumpsys window | awk '/mCurrentFocus=/{print; exit}'

if [[ -n $package_name ]]; then
    if ! "${adb_cmd[@]}" shell pm path "$package_name" >/dev/null; then
        echo "error: package is not installed: $package_name" >&2
        exit 1
    fi
    echo "Package: $package_name"
    "${adb_cmd[@]}" shell dumpsys package "$package_name" |
        awk '/versionCode=|versionName=/{print; if (++count == 2) exit}'
fi
