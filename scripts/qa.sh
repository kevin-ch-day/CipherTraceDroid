#!/usr/bin/env bash
set -euo pipefail

if ! command -v cmake >/dev/null || ! command -v ninja >/dev/null || ! command -v c++ >/dev/null; then
    echo "error: cmake, ninja, and a C++ compiler are required" >&2
    exit 1
fi

git diff --check
rm -rf build-qa
cmake -S . -B build-qa -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-qa
ctest --test-dir build-qa --output-on-failure
./build-qa/ciphertracedroid >/dev/null
./build-qa/ciphertracedroid --help >/dev/null
./build-qa/ciphertracedroid --version >/dev/null
./build-qa/ciphertracedroid info >/dev/null
if ./build-qa/ciphertracedroid unknown-command >/dev/null 2>&1; then
    echo "error: unknown command unexpectedly succeeded" >&2
    exit 1
fi
echo "QA PASS"
