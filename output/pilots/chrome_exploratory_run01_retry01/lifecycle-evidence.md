# Chrome lifecycle evidence

- `2026-08-13 23:22:03` — Chrome resumed for the foreground condition.
- `2026-08-13 23:24:43` — Chrome paused and stopped after HOME.
- `2026-08-13 23:25:06` — Chrome unexpectedly resumed during the intended background condition.
- `2026-08-13 23:25:13` — Chrome paused and stopped.
- `2026-08-13 23:25:16` — Chrome unexpectedly resumed again.
- `2026-08-13 23:27:14` — Chrome paused at capture-stop handling.

The first unexpected resume occurred about 23 seconds after HOME and about one second after the intended background timer began.
