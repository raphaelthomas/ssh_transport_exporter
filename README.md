# Credential-less Prometheus exporter for SSH transport layer (RFC 4253)

[![Go Version](https://img.shields.io/github/go-mod/go-version/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/go.mod)
[![Latest Release](https://img.shields.io/github/v/release/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/releases/latest)
[![License](https://img.shields.io/github/license/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/LICENSE)
[![CI](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml)

> [!CAUTION]
> **Experimental exporter for probing the SSH transport layer. Not suitable for
> production use yet.**

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

## Configuration

The exporter itself is configured via the following parameters:

```
usage: ssh_transport_exporter [<flags>]

Flags:
  -h, --help            Show context-sensitive help (also try --help-long and --help-man).
      --version         Show application version.
      --web.listen-address=":10022"
                        Address to listen on for web interface and telemetry
      --log-level=info  Log level (debug, info, warn, error)
      --config.file="ssh_transport_exporter.yaml"
                        Path to the exporter's YAML config file with module definitions)
```

Probes are defined in a YAML configuration file, which is specified via the
`--config.file` parameter. The default path is `ssh_transport_exporter.yaml`.

See
[`ssh_transport_exporter.example.yaml`](./ssh_transport_exporter.example.yaml)
for a fully annotated example configuration file.

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
