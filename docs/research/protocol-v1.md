# Collection Protocol v1

**PROVISIONAL — awaiting routed-capture pilot**

The independent unit is one physical run. A run contains foreground, transition, background, and optionally `device_control` segments under one `run_id`. Every segment from that run remains in the same train/test partition.

## Planned sequence

1. Record device, Android, application version, power, charging, Wi-Fi, VPN, Doze/battery-saver, host/device clock, and capture-source provenance.
2. Verify the screen is interactive and unlocked and no system overlay blocks control.
3. Start the selected capture and confirm its observation point. For a PCAPdroid auxiliary run, perform target force-stop and HOME verification after capture activation because the capture-control activity may return Android to a prior target-app task.
4. Launch the target and verify it through `ResumedActivity`.
5. Observe a configurable foreground interval.
6. Send HOME, verify the launcher is resumed, and exclude a configurable transition guard.
7. Observe a configurable background interval. Sample `ResumedActivity` at least once per analysis window on a physical-device pilot; any unexpected target resume invalidates that condition, even if the end gate later passes.
8. Stop and finalize the capture, verify both route restoration and VPN-interface removal, record the link type and timestamp precision, and hash the explicitly named artifact. Treat a capture application's reported stop success as insufficient without these checks.
9. For a separate `device_control` segment, force-stop the target, show the launcher, and perform no deliberate interaction.

The initial window duration is five seconds. Only complete windows wholly contained in one labelled interval are primary samples. Transition windows and incomplete tails are excluded. Schema v1 also omits empty windows, so pilots must report both scheduled complete windows and exported non-empty windows by condition. Failed state verification, capture interruption, hash mismatch, unexpected VPN state, missing direction identity, or overlapping intervals invalidates the affected run; a retry receives a new run ID.

No TLS decryption, full-payload capture, private browsing, credentials, messages, or other intentional private content is permitted. PCAPdroid runs remain auxiliary pilots and synthetic fixtures remain software-validation inputs. Neither can enter the routed-primary dataset.

Run duration, transition guard, application set, repeat count, and environmental controls remain configurable and must be recorded. They will be finalized only after a routed pilot measures capture behavior and operational variance.
