# Chrome lifecycle evidence

Recent Android usage events showed repeated Chrome resume/pause/stop activity during the intended background period, including resumes at local device times `23:06:36`, `23:06:45`, `23:06:46`, and `23:07:03`. Chrome paused and stopped after the capture stop request.

This supports quarantine: the target did not remain outside the resumed state for a verified background interval.
