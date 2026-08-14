# Validation report

Status: **INVALID**

Capture checks passed:

- Whole-device unfiltered PCAPdroid VPN-boundary source.
- Unique artifact preserved and hashed.
- DLT_RAW capture readable.
- 16,642 valid IPv4 packets; zero malformed packets.
- Standby bucket remained 10.
- Manual stop and VPN-inactive cleanup confirmed.

Experiment gate failed:

- Chrome resumed after PCAPdroid activation despite the pre-capture force-stop.
- The required launcher-visible, Chrome-not-resumed device-control state was false.
- No condition interval began; no state manifest, features, comparisons, or timeline may be generated.

Likely instrumentation cause: PCAPdroid's capture-control completion returned Android to an existing Chrome task. The next attempt must force-stop Chrome after capture activation, bring HOME forward, and pass delayed state verification before starting the control timer.
