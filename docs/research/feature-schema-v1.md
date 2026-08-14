# Feature Schema v1

Status: **FROZEN for routed-pilot validation.** A change to any predictor's meaning or order requires a new schema version.

Each sample is one complete five-second window by default. The duration is configurable and recorded. Windows are constructed independently inside one labelled interval; incomplete tails and empty primary windows are omitted. Predictors consume valid IPv4 or IPv6 packets only.

Packet size always means IP packet length: IPv4 Total Length, or the 40-byte IPv6 fixed header plus IPv6 Payload Length. Capture-frame lengths remain diagnostics and are not predictors. Direction is assigned only by matching an explicit device IP to the source or destination address.

| Column | C++ type | Unit | Definition and edge behavior | Source requirement |
|---|---|---:|---|---|
| `packet_count` | `double` | packets | Valid IP packets in the window. | Valid IP parsing |
| `total_ip_bytes` | `double` | bytes | Sum of IP packet lengths. | IP-length fidelity |
| `packets_per_second` | `double` | packets/s | Packet count divided by complete window duration. | Timing |
| `ip_bytes_per_second` | `double` | bytes/s | IP bytes divided by complete window duration. | Timing and IP length |
| `ip_size_mean` | `double` | bytes | Arithmetic mean IP length; zero for no packets. | IP length |
| `ip_size_stddev` | `double` | bytes | Population standard deviation; zero below two packets. | IP length |
| `ip_size_min` | `double` | bytes | Minimum IP length; zero for no packets. | IP length |
| `ip_size_max` | `double` | bytes | Maximum IP length; zero for no packets. | IP length |
| `ip_size_median` | `double` | bytes | Linearly interpolated median; zero for no packets. | IP length |
| `ip_size_q1` | `double` | bytes | Linearly interpolated 25th percentile; zero for no packets. | IP length |
| `ip_size_q3` | `double` | bytes | Linearly interpolated 75th percentile; zero for no packets. | IP length |
| `outbound_packet_count` | `double` | packets | Packets whose source equals the explicit device IP. | Direction identity |
| `inbound_packet_count` | `double` | packets | Packets whose destination equals the explicit device IP. | Direction identity |
| `unknown_packet_count` | `double` | packets | Packets matching neither direction rule. | None |
| `outbound_ip_bytes` | `double` | bytes | IP bytes assigned outbound. | Direction and IP length |
| `inbound_ip_bytes` | `double` | bytes | IP bytes assigned inbound. | Direction and IP length |
| `unknown_ip_bytes` | `double` | bytes | IP bytes with unknown direction. | IP length |
| `outbound_packet_fraction` | `double` | fraction | Outbound count divided by packet count; zero when count is zero. | Direction |
| `inbound_packet_fraction` | `double` | fraction | Inbound count divided by packet count; zero when count is zero. | Direction |
| `unknown_packet_fraction` | `double` | fraction | Unknown count divided by packet count; zero when count is zero. | Direction |
| `outbound_byte_fraction` | `double` | fraction | Outbound IP bytes divided by total IP bytes; zero when total is zero. | Direction and IP length |
| `inbound_byte_fraction` | `double` | fraction | Inbound IP bytes divided by total IP bytes; zero when total is zero. | Direction and IP length |
| `unknown_byte_fraction` | `double` | fraction | Unknown IP bytes divided by total IP bytes; zero when total is zero. | Direction and IP length |
| `iat_mean` | `double` | seconds | Mean adjacent inter-arrival time; zero below two packets. | Timing |
| `iat_stddev` | `double` | seconds | Population standard deviation of adjacent IATs. | Timing |
| `iat_median` | `double` | seconds | Median adjacent IAT. | Timing |
| `iat_min` | `double` | seconds | Minimum adjacent IAT. Equal timestamps produce zero. | Timing |
| `iat_max` | `double` | seconds | Maximum adjacent IAT. | Timing |
| `tcp_packet_fraction` | `double` | fraction | TCP packets divided by packet count. | Transport parsing |
| `udp_packet_fraction` | `double` | fraction | UDP packets divided by packet count. | Transport parsing |
| `other_transport_fraction` | `double` | fraction | Other or unresolved transport divided by packet count. | IP parsing |

All numeric values must be finite before serialization. Metadata—application label, run/session IDs, condition, capture source, device/app provenance, addresses, ports, and ADB observations—is structurally separate and cannot be passed to classifier prediction methods.
