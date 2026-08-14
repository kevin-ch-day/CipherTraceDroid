# Capture-source limitations

- Source: PCAPdroid VPN-boundary auxiliary, unfiltered whole-device scope.
- Publication-primary eligibility: false.
- DLT_RAW IP lengths are VPN/TUN-boundary representations, not physical wire-packet sizes.
- Values larger than a routed-interface MTU may reflect aggregation, synthesis, or pre-segmentation behavior; the exact mechanism is not asserted.
- UDP source/destination port 443 is only a probable-QUIC heuristic. It is descriptive and is not confirmed QUIC identity.
- The run is one independent physical run. Its windows are correlated within-run observations.
