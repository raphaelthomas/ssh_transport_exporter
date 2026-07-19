# Credential-less Prometheus exporter for SSH transport layer (RFC 4253)

[![Go Version](https://img.shields.io/github/go-mod/go-version/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/go.mod)
[![Latest Release](https://img.shields.io/github/v/release/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/releases/latest)
[![License](https://img.shields.io/github/license/raphaelthomas/ssh_transport_exporter)](https://github.com/raphaelthomas/ssh_transport_exporter/blob/main/LICENSE)
[![CI](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/raphaelthomas/ssh_transport_exporter/actions/workflows/ci.yml)

Prometheus exporter `ssh_transport_exporter` is credential-less by design and
strictly limits its probing to the SSH transport layer ([RFC
4253](https://datatracker.ietf.org/doc/html/rfc4253)).

Support for the SSH Authentication Protocol ([RFC
4252](https://datatracker.ietf.org/doc/html/rfc4252)) is intentionally omitted
to avoid the need for credentials and to reduce the potential attack surface.
Consequently, also the SSH Connection Protocol ([RFC
4254](https://datatracker.ietf.org/doc/html/rfc4254)) is not supported.

If probing for the full SSH protocol stack is required, the suitable
alternative that provides these capabilities is the
[`ssh_exporter`](https://github.com/treydock/ssh_exporter).
