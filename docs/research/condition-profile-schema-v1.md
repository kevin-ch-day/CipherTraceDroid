# Condition Profile Schema v1

Status: **PROVISIONAL — requires repeated physical runs and routed-capture validation.**

One profile represents one independent physical run under one fixed condition. Metadata and predictors are separate types. Application, condition, run/session identifiers, package, ADB state, lifecycle state, and capture source are not numeric predictors.

| Predictor | Type | Unit | Definition | Empty-traffic behavior | Source requirement |
|---|---|---:|---|---|---|
| `condition_duration_seconds` | `double` | seconds | Included fixed-condition duration. | Retained. | Valid interval timing |
| `total_ip_packets` | `double` | packets | Valid IP packets in the full interval. | Zero. | Valid IP parsing |
| `total_ip_bytes` | `double` | bytes | Sum of IP lengths at the recorded observation boundary. | Zero. | IP-length parsing |
| `packets_per_second` | `double` | packets/s | Total packets divided by condition duration. | Zero. | Timing |
| `ip_bytes_per_second` | `double` | bytes/s | Total IP bytes divided by condition duration. | Zero. | Timing and IP lengths |
| aggregate packet statistics | optional Feature Schema v1 vector | mixed | Packet-size, direction, IAT, and transport summaries across all packets in the condition. | Unavailable, not zero-filled. | Packet-bearing condition |
| `scheduled_window_count` | `double` | windows | Complete diagnostic windows wholly inside the condition. | Retained. | Window schedule |
| `active_window_count` | `double` | windows | Scheduled windows containing at least one valid IP packet. | Zero. | Packet timing |
| `active_window_fraction` | `double` | fraction | Active windows divided by scheduled windows. | Zero when scheduled windows exist and all are quiet. | Packet timing |
| `longest_quiet_duration_seconds` | `double` | seconds | Longest consecutive sequence of empty diagnostic windows. | Full scheduled duration. | Window schedule |
| `time_to_first_packet_seconds` | optional `double` | seconds | Offset from interval start to first valid IP packet. | Unavailable. | Packet timing |

The default diagnostic window is five seconds, but it does not define the independent unit. Window observations describe occupancy and timing within a run; they are not treated as independent application samples.

PCAPdroid profiles are auxiliary and publication-ineligible. IP lengths at its DLT_RAW VPN/TUN boundary are not physical wire-packet sizes. Capture source is mandatory provenance and remains outside predictors.
