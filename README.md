# Credential-less Prometheus exporter for SSH transport layer (RFC 4253)

[![Go Version](https://img.shields.io/github/go-mod/go-version/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/go.mod)
[![Latest Release](https://img.shields.io/github/v/release/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/releases/latest)
[![License](https://img.shields.io/github/license/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/LICENSE)
[![CI](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml)

Prometheus exporter `ssh_transport_exporter` is credential-less by design and
strictly limits its probing to the SSH transport layer ([RFC
4253](https://datatracker.ietf.org/doc/html/rfc4253)). Specifically, it makes
the underlying TCP connection, the initial key exchange, and the server host
key verification observable. This can, for example, help to identify path
MTU or TCP MSS issues, which are difficult to detect with the `blackbox_exporter`,
without requiring any SSH credentials.

Support for the SSH Authentication Protocol ([RFC
4252](https://datatracker.ietf.org/doc/html/rfc4252)) is intentionally omitted
to avoid the need for credentials and to reduce the potential attack surface.
Consequently, also the SSH Connection Protocol ([RFC
4254](https://datatracker.ietf.org/doc/html/rfc4254)) is not supported.

If probing for the full SSH protocol stack is required, the suitable
alternative that provides these capabilities is the
[`ssh_exporter`](https://github.com/treydock/ssh_exporter).

> [!NOTE]
> This exporter depends on a fork of `golang.org/x/crypto` (see the `replace`
> directive in [`go.mod`](./go.mod)), which adds a `TransportReadyCallback`
> hook to `ssh.ClientConfig` used to surface the negotiated algorithms and the
> server identification string before aborting the connection. The intent is to
> upstream this hook; until then the fork is pinned by commit. As the exporter
> is credential-less by design, it never holds keys or secrets.

## Configuration

The exporter itself is configured via the following parameters:

```
usage: ssh_transport_exporter [<flags>]

Flags:
  -h, --help               Show context-sensitive help (also try --help-long and --help-man).
      --version            Show application version.
      --web.listen-address=":10022"
                           Address to listen on for web interface and telemetry
      --log-level=info     Log level (debug, info, warn, error)
      --config.file="ssh_transport_exporter.yaml"
                           Path to the exporter's YAML config file with module definitions)
      --probe.timeout=5s   Hard upper bound for a single probe; Prometheus scrape timeout may shorten it.
      --probe.max-concurrent=500
                           Maximum probes running at once; further requests get 503 rather than queueing. 0 disables the limit.
      --allow-all-targets  Probe any target when no allowed_targets is set; for fleets too diverse to enumerate. An explicit list always wins.
```

Probes are defined in a YAML configuration file, which is specified via the
`--config.file` parameter. The default path is `ssh_transport_exporter.yaml`.

See
[`ssh_transport_exporter.example.yaml`](./ssh_transport_exporter.example.yaml)
for a fully annotated example configuration file.

### Probe timeout

`--probe.timeout` (default `5s`) is a hard upper bound on a single probe,
applied even when a request carries no `X-Prometheus-Scrape-Timeout-Seconds`
header. When Prometheus does send that header, the effective timeout is the
**smaller** of the two - so a per-job `scrape_timeout` is the right place to
tune timeouts per target set.

Prefer the smallest value that comfortably covers a healthy handshake: an
offline or filtered target (no connection refused) holds a probe open for the
full timeout on every scrape, so a large value multiplies resource use across a
big fleet.

### Probe concurrency

`--probe.max-concurrent` (default `500`) sheds requests above the limit with
`503` rather than queueing them.

Size it against the cardinality of targets to probe, not the exporter. Every
probe occupies an unauthenticated connection slot on the SSH server it probes,
and OpenSSH's `MaxStartups` defaults to `10:30:100`: random drops from 10
concurrent unauthenticated connections, hard refusal past 100. Probes are
indistinguishable from logins at that stage, so exceeding a target's budget can
lead to drops of legitimate pre-auth SSH connections.

Each in-flight probe holds roughly two file descriptors, so the default of 500
targets needs approximately 1000 file descriptors. If the hard file descriptor
limit is pinned low, the exporter emits a warning.

## Exported Metrics

The following probe result metrics are exported by the
`ssh_transport_exporter`s `/probe` endpoint for a successful probe:

```
# HELP ssh_transport_cipher_info Negotiated cipher per direction. Constant 1. Absent if key exchange did not complete.
# TYPE ssh_transport_cipher_info gauge
ssh_transport_cipher_info{cipher="aes128-gcm@openssh.com",direction="read"} 1
ssh_transport_cipher_info{cipher="aes128-gcm@openssh.com",direction="write"} 1

# HELP ssh_transport_host_key_verify_algorithm_info Negotiated host key algorithm. Constant 1. Absent if key exchange did not complete.
# TYPE ssh_transport_host_key_verify_algorithm_info gauge
ssh_transport_host_key_verify_algorithm_info{algorithm="ssh-ed25519"} 1

# HELP ssh_transport_host_key_verify_success Whether the server host key was successfully verified.
# TYPE ssh_transport_host_key_verify_success gauge
ssh_transport_host_key_verify_success 1

# HELP ssh_transport_identification_server_version_info SSH version banner presented by the server (RFC 4253 4.2). Constant 1. Absent if the identification string exchange did not complete.
# TYPE ssh_transport_identification_server_version_info gauge
ssh_transport_identification_server_version_info{version="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10"} 1

# HELP ssh_transport_kex_algorithm_info Negotiated key exchange algorithm. Constant 1. Absent if key exchange did not complete.
# TYPE ssh_transport_kex_algorithm_info gauge
ssh_transport_kex_algorithm_info{algorithm="curve25519-sha256"} 1

# HELP ssh_transport_kex_duration_seconds Time taken for the SSH transport layer handshake. Omitted on failure.
# TYPE ssh_transport_kex_duration_seconds gauge
ssh_transport_kex_duration_seconds 0.090082416

# HELP ssh_transport_kex_success Whether the SSH transport layer key exchange (RFC 4253) completed successfully.
# TYPE ssh_transport_kex_success gauge
ssh_transport_kex_success 1

# HELP ssh_transport_tcp_connect_duration_seconds Time taken to establish the TCP connection. Omitted on failure.
# TYPE ssh_transport_tcp_connect_duration_seconds gauge
ssh_transport_tcp_connect_duration_seconds 0.026296792

# HELP ssh_transport_tcp_connect_negotiated_mss_bytes Negotiated TCP maximum segment size (MSS) observed at TCP connect time. Omitted if unavailable.
# TYPE ssh_transport_tcp_connect_negotiated_mss_bytes gauge
ssh_transport_tcp_connect_negotiated_mss_bytes 1448

# HELP ssh_transport_tcp_connect_success Whether a TCP connection to the target could be established.
# TYPE ssh_transport_tcp_connect_success gauge
ssh_transport_tcp_connect_success 1
```

In case of an unsuccessful probe, an additional
`ssh_transport_exporter_error_info` metric will be emitted, and the
`*_duration_seconds` metrics will be omitted. The
`ssh_transport_exporter_error_info` metric contains an error reason and the
stage at which the error occurred as a label value.

The following is an example of the emitted metrics where DNS resolution for the
probe target failed:

```
# HELP ssh_transport_error_info Stage and reason this probe failed. Constant 1. Absent if the probe fully succeeded.
# TYPE ssh_transport_error_info gauge
ssh_transport_error_info{reason="dns_failure",stage="tcp_connect"} 1

# HELP ssh_transport_host_key_verify_success Whether the server host key was successfully verified.
# TYPE ssh_transport_host_key_verify_success gauge
ssh_transport_host_key_verify_success 0

# HELP ssh_transport_kex_success Whether the SSH transport layer key exchange (RFC 4253) completed successfully.
# TYPE ssh_transport_kex_success gauge
ssh_transport_kex_success 0

# HELP ssh_transport_tcp_connect_success Whether a TCP connection to the target could be established.
# TYPE ssh_transport_tcp_connect_success gauge
ssh_transport_tcp_connect_success 0
```

## Error Stages and Reasons

When a probe does not fully succeed, the exporter emits a single
`ssh_transport_error_info` metric (constant `1`) carrying two labels `stage`
and `reason`, and omits the `*_duration_seconds` metrics. The `stage` label
identifies *how far* the probe got before failing; the `reason` label explains
*why* it failed at that stage.

### Stages

The stage reflects the last phase the probe reached. Probing proceeds strictly
in this order: *TCP connect*, *key exchange*, *host key verification*.

| Stage | Description |
| --- | --- |
| `tcp_connect` | Failure while establishing the underlying TCP connection to the target (before anything SSH). |
| `kex` | Failure during the SSH transport-layer key exchange (RFC 4253), after the TCP connection was established. |
| `host_key_verify` | The transport-layer handshake completed, but verification of the server's host key against the configured `known_hosts` failed. |

### Reasons

The reason narrows down the cause within a stage.

| Reason | Typical Stage(s) | Description |
| --- | --- | --- |
| `connection_refused` | `tcp_connect` | The target actively refused the connection (`ECONNREFUSED`) — commonly nothing listening on the port, or a firewall sending a reset. |
| `no_route_to_host` | `tcp_connect` | The destination *network* is reachable, but the specific *host* is not (`EHOSTUNREACH`) — often a down host or an ICMP host-unreachable from a router. |
| `network_unreachable` | `tcp_connect` | There is no route to the destination *network* at all (`ENETUNREACH`) — typically a missing route, absent default gateway, or a down interface on the prober side. |
| `dns_failure` | `tcp_connect` | The target hostname could not be resolved (DNS lookup error). |
| `connection_reset` | `kex` | The connection was closed unexpectedly during key exchange (e.g. the peer reset it, or it was torn down mid-handshake). |
| `timeout` | `tcp_connect`, `kex` | The operation exceeded its deadline (the scrape timeout or a network-level timeout). |
| `unknown_host` | `host_key_verify` | The server presented a host key, but the target host has no matching entry in `known_hosts`. |
| `mismatch` | `host_key_verify` | The server's host key did **not** match the key pinned for that host in `known_hosts` — a potential man-in-the-middle indicator or an un-rotated key. |
| `revoked` | `host_key_verify` | The server's host key is explicitly listed as revoked in `known_hosts`. |
| `other` | any | The failure did not match any of the classified cases above. If you see this frequently, please open an issue with the target and (debug-level) logs so the classification can be improved. |
