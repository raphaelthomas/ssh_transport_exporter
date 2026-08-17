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

## Quick Start

Create `ssh_transport_exporter.yaml` with a `known_hosts` source to verify
targets against, and the targets the exporter is allowed to probe:

```yaml
known_hosts_file: /etc/ssh/ssh_known_hosts
allowed_targets:
  - "*.example.com"
```

Run the exporter:

```
docker run --rm -p 10022:10022 \
  -v ./ssh_transport_exporter.yaml:/ssh_transport_exporter.yaml:ro \
  -v /etc/ssh/ssh_known_hosts:/etc/ssh/ssh_known_hosts:ro \
  ghcr.io/raphaelthomas/ssh_transport_exporter:latest
```

Like other multi-target exporters, the target to probe is passed to the exporter
as a URL parameter, so Prometheus is pointed at the exporter and the intended
target is moved into `__param_target` by relabelling:

```yaml
scrape_configs:
  - job_name: ssh_transport
    metrics_path: /probe
    params:
      module: [default]
    scrape_timeout: 5s
    static_configs:
      - targets:
          - bastion.example.com          # probed on the module's target_port
          - 192.0.2.10:2222              # explicit port, must be in allowed_ports
    relabel_configs:
      # the target becomes the ?target= parameter
      - source_labels: [__address__]
        target_label: __param_target
      # label the series with the probed target rather than the exporter
      - source_labels: [__param_target]
        target_label: instance
      # and actually scrape the exporter
      - target_label: __address__
        replacement: 127.0.0.1:10022

  # the exporter's own metrics, scraped directly
  - job_name: ssh_transport_exporter
    static_configs:
      - targets: ['127.0.0.1:10022']
```

## Installation

Container images are published to GHCR for `linux/amd64` and `linux/arm64`. The
image is built `FROM scratch` and runs as UID 65534.

Binaries for Linux, macOS and Windows, an SPDX SBOM per archive, and a checksums
file are attached to every
[release](https://github.com/raphaelthomas/ssh_transport_exporter/releases).
Every published artifact carries SLSA build provenance, which can be verified
against this repository:

```
gh attestation verify ssh_transport_exporter-<version>-linux-amd64.tar.gz \
  --repo raphaelthomas/ssh_transport_exporter
```

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
                           Path to the exporter's YAML config file with module definitions
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

Use one job per module, each with its own `params.module`, since the module
selects the `known_hosts`, the allowed targets, and the advertised algorithms.

### Configuration reload

`SIGHUP` re-reads the configuration file and the `known_hosts` files it
references, which is how a host key rotation is picked up without a restart:

```
kill -HUP $(pidof ssh_transport_exporter)
```

The new configuration is validated before it is swapped in. If it is rejected,
the error is logged and the previous configuration stays active, so a bad edit
cannot take the exporter down.

## Tuning

### Probe timeout

`--probe.timeout` (default `5s`) is a hard upper bound on a single probe,
applied even when a request carries no `X-Prometheus-Scrape-Timeout-Seconds`
header. When Prometheus does send that header, the effective timeout is the
**smaller** of the two, so a per-job `scrape_timeout` is the right place to
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

## Security Considerations

`/probe` is unauthenticated. Anyone able to reach it can have the exporter open
a TCP connection to a target and report whether it answered, which makes the
exporter a probing tool for whoever can call it. As with `blackbox_exporter`,
keep it on a trusted network.

`allowed_targets` is the access control and denies everything by default: a
module with no list configured refuses every target, and `--allow-all-targets`
only relaxes that when no list is configured anywhere. `allowed_ports` is the
second axis and defaults to just `target_port`; widening it turns the exporter
into a port scanner for the allowed hosts, because `ssh_transport_error_info`
distinguishes `connection_refused` from `timeout` and so reveals whether a port
is open.

The exporter holds no credentials and never authenticates, so a probed host
cannot obtain anything from it. Data coming back from a target is treated as
untrusted and never reaches a Prometheus label unvalidated.

The one label a target still controls is the identification string on
`ssh_transport_identification_server_version_info`, so a host that varies its
banner varies the series. Setting `strip_server_version_comment` on a module
reduces the label to the software version, and dropping the metric at scrape
time bounds it entirely:

```yaml
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: ssh_transport_identification_server_version_info
        action: drop
```

## Exported Metrics

The following probe result metrics are exported by the
`ssh_transport_exporter`'s `/probe` endpoint for a successful probe:

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

# HELP ssh_transport_identification_server_version_valid Whether the server's identification string conformed to RFC 4253 4.2. 0 means one was presented but rejected, and no server_version_info is exported for it. Absent if the probe never observed one.
# TYPE ssh_transport_identification_server_version_valid gauge
ssh_transport_identification_server_version_valid 1

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

One further metric is absent above because the sample negotiated an AEAD
cipher, which authenticates without a separate MAC. It appears whenever a
non-AEAD cipher is agreed, which is what makes a module restricted to CBC or
RC4 ciphers able to audit MAC choice:

```
# HELP ssh_transport_mac_info Negotiated MAC algorithm per direction. Constant 1. Absent for AEAD ciphers (aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com), which provide integrity without a separate MAC, and absent if key exchange did not complete.
# TYPE ssh_transport_mac_info gauge
ssh_transport_mac_info{direction="read",mac="hmac-sha2-256-etm@openssh.com"} 1
ssh_transport_mac_info{direction="write",mac="hmac-sha2-256-etm@openssh.com"} 1
```

An unsuccessful probe adds an `ssh_transport_error_info` metric, reports `0` for
the `*_success` gauges, and omits the `*_duration_seconds` metrics. See [Error
Stages and Reasons](#error-stages-and-reasons) for the label values. For a probe
whose target failed DNS resolution:

```
# HELP ssh_transport_error_info Stage and reason this probe failed. Constant 1. Absent if the probe fully succeeded.
# TYPE ssh_transport_error_info gauge
ssh_transport_error_info{reason="dns_failure",stage="tcp_connect"} 1
```

### Exporter Metrics

The exporter's own metrics are served from `/metrics`, under the
`ssh_transport_exporter` namespace, alongside the standard Go runtime and
process collectors:

```
# HELP ssh_transport_exporter_build_info A metric with a constant '1' value labeled by version, revision, branch, goversion from which ssh_transport_exporter was built, and the goos and goarch for the build.
# TYPE ssh_transport_exporter_build_info gauge
ssh_transport_exporter_build_info{branch="main",goarch="amd64",goos="linux",goversion="go1.26.5",revision="0000000",tags="unknown",version="0.11.5"} 1

# HELP ssh_transport_exporter_probe_requests_total Total probe requests served by module and HTTP status code. Module is empty when the request named no configured module.
# TYPE ssh_transport_exporter_probe_requests_total counter
ssh_transport_exporter_probe_requests_total{code="200",module="default"} 1
ssh_transport_exporter_probe_requests_total{code="400",module=""} 1
ssh_transport_exporter_probe_requests_total{code="403",module="default"} 1

# HELP ssh_transport_exporter_probes_in_flight Probes currently running.
# TYPE ssh_transport_exporter_probes_in_flight gauge
ssh_transport_exporter_probes_in_flight 0

# HELP ssh_transport_exporter_config_last_reload_successful Whether the most recent configuration load succeeded. 0 means the exporter is still serving the previously loaded configuration.
# TYPE ssh_transport_exporter_config_last_reload_successful gauge
ssh_transport_exporter_config_last_reload_successful 1

# HELP ssh_transport_exporter_config_last_reload_success_timestamp_seconds Unix timestamp of the most recent successful configuration load.
# TYPE ssh_transport_exporter_config_last_reload_success_timestamp_seconds gauge
ssh_transport_exporter_config_last_reload_success_timestamp_seconds 1.7712e+09
```

`config_last_reload_successful` goes to `0` when a `SIGHUP` reload fails, while
the exporter keeps serving the previously loaded configuration, so it is worth
alerting on.

`probe_requests_total` counts every request to `/probe` by module and response
code: `400` for a missing or malformed target and for an unknown module, `403`
for a target or port the module does not allow, and `503` once
`--probe.max-concurrent` is reached. The module label is empty when the request
named no configured module, which keeps an unknown module name from creating
series.

`probes_in_flight` tracks probes currently running and is what to compare
against `--probe.max-concurrent` when sizing it.

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
| `connection_refused` | `tcp_connect` | The target actively refused the connection (`ECONNREFUSED`), commonly because nothing is listening on the port or a firewall sent a reset. |
| `no_route_to_host` | `tcp_connect` | The destination *network* is reachable, but the specific *host* is not (`EHOSTUNREACH`), often a down host or an ICMP host-unreachable from a router. |
| `network_unreachable` | `tcp_connect` | There is no route to the destination *network* at all (`ENETUNREACH`), typically a missing route, an absent default gateway, or a down interface on the prober side. |
| `dns_failure` | `tcp_connect` | The target hostname could not be resolved (DNS lookup error). |
| `connection_reset` | `kex` | The connection was closed unexpectedly by the peer during key exchange, with the probe deadline still unexpired. |
| `timeout` | `tcp_connect`, `kex` | The operation exceeded its deadline (the effective probe timeout, or a network-level timeout). |
| `canceled` | `tcp_connect`, `kex` | The caller went away before the probe finished, typically Prometheus abandoning the scrape. The response is discarded in that case, so this mostly shows up in debug logs. |
| `unknown_host` | `host_key_verify` | The server presented a host key, but the target host has no matching entry in `known_hosts`. |
| `mismatch` | `host_key_verify` | The server's host key did **not** match the key pinned for that host in `known_hosts`, which indicates either a man-in-the-middle or an un-rotated key. |
| `revoked` | `host_key_verify` | The server's host key is explicitly listed as revoked in `known_hosts`. |
| `other` | any | The failure did not match any of the classified cases above. If you see this frequently, please open an issue with the target and (debug-level) logs so the classification can be improved. |
