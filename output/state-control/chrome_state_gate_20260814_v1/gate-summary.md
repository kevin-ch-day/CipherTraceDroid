# Chrome state-control gate

Result: **STATE CONTROL NOT READY**

PCAPdroid and Android VPN remained inactive. The device was interactive and unlocked.

| Attempt | Result | Evidence |
|---|---|---|
| 01 | PASS | 16 observations over 15.000 seconds; approximately one-second cadence; launcher environment throughout. |
| 02 | FAIL | Launcher at 0 and 1 seconds; Chrome resumed at 2 seconds. Stabilizer failed immediately. |
| 03 | NOT RUN | Protocol requires stopping on the first failure. |

Android logs for attempt 02 show a Quickstep `TO_FRONT` transition for the existing Chrome task at local time `00:01:17.798`, about 1.8 seconds after HOME. No new ADB Chrome `START` occurred at that moment. Available evidence does not distinguish physical/gesture input from launcher behavior, so no cause is asserted.

No packet capture was started. No background interval was authorized.
