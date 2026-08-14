# Architecture

`main.cpp` delegates directly to the application layer. `ciphertracedroid_core` owns typed capture-source contracts, packet normalization, complete state-bounded windows, Feature Schema v1, grouped experiment specifications, the nearest-centroid integration baseline, metrics, and evidence-bundle finalization.

`PacketRecord` retains capture-frame lengths for diagnostics and an explicit IP packet length for predictors. Ports are optional because later IP fragments do not carry them. Non-IP and malformed frames remain capture-summary counts and never become predictor rows.

`SampleMetadata` contains labels and provenance. `FeatureVector` contains numeric predictors only, and the classifier accepts only `FeatureVector`. Capture-source capabilities are checked before an experiment, then preserved through predictions and the evidence bundle.

For physical experiments, ADB is a separate control plane: it launches a selected package, sends HOME, records host-side event timestamps, and checks Android state. Network observation collects encrypted traffic metadata, and analysis consumes only the capture plus manifest labels. ADB state, package metadata, and lifecycle information are never classifier inputs.

The executable owns ADB integration. Its device client launches `adb` through structured process arguments, so device identifiers and command parameters do not pass through host-shell interpolation. The initial `device status` command is read-only and requires exactly one authorized endpoint; it establishes an auditable readiness check before any future, separately explicit device-control action.

`session plan <package> <output.json>` is the first collection-workflow artifact. It validates the package name and installation, snapshots selected read-only device/package facts, and records collection gates without changing the device. It is provenance only: the later strict manifest remains the source of capture hashes and interval labels.
