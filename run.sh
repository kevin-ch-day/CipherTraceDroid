#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary="$project_dir/build/ciphertracedroid"

if [[ ! -x $binary ]]; then
    echo "error: build/ciphertracedroid is missing; run ./build-project first" >&2
    exit 1
fi

exec "$binary" "$@"
