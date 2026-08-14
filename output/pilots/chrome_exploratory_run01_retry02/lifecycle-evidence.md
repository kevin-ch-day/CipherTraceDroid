# Chrome lifecycle evidence

Android usage history for Retry 02 showed:

- `2026-08-13 23:32:41` — `ACTIVITY_RESUMED`, Chrome foreground transition.
- `2026-08-13 23:35:22` — `ACTIVITY_PAUSED`, Chrome background transition.
- `2026-08-13 23:35:23` — `ACTIVITY_STOPPED`, Chrome background transition.
- No later Chrome resume occurred before the capture stop request at `23:37:59` local time.

The lifecycle history agrees with the higher-frequency `ResumedActivity` sentinels. Process presence during background is provenance only and does not establish foreground state.
