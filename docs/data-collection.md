# Data collection

Capture controlled, repeatable application runs with independently recorded intervals for `foreground`, `background`, and `transition`. Identify the Android device explicitly (initially with `--device-ip`); endpoint ordering is never used as a proxy for direction. Retain transition metadata, but exclude it from the primary foreground/background evaluation unless intentionally included.

Associate each raw capture with a SHA-256 value in the manifest. Do not commit raw PCAP/PCAPNG/CAP files.

Use host UTC timestamps immediately before and after each ADB action. The device clock is recorded for diagnostic comparison only; state boundaries use host-controlled timestamps. Establish and document a configurable transition guard before the first data run, then exclude that interval from foreground/background windows.
