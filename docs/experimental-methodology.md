# Experimental methodology

The unit of train/test partitioning is a capture session/run, never an individual window. This prevents correlated windows from one capture appearing in both partitions. Primary comparisons will cover foreground-to-foreground, foreground-to-background, background-to-background, background-to-foreground, and mixed-state training evaluated separately by state.

Windows are generated inside declared state intervals. Excluded intervals, including transitions, produce no primary samples. Feature extraction uses encryption-visible metadata only: timing, lengths, protocol class, IP version, direction, counts, rates, and deterministic burst statistics. A zero denominator is represented as the schema-defined value `0.0`; non-finite values are rejected before CSV serialization.

ADB is used solely for controlled state transitions and independent labels. It must not contribute app package, version, foreground/background state, process data, or lifecycle information to the feature matrix.

`device_control` is a distinct experimental baseline: the target package is force-stopped, launcher is visible, and no deliberate interaction occurs. It must not be labeled as background or pooled into primary foreground/background training.
