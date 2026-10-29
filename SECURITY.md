# Security Policy

## Supported Versions

Only the latest release receives security fixes.

## Reporting a Vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/raphaelthomas/ssh_transport_exporter/security/advisories/new),
not in a public issue.

Include the affected version, how to reproduce the issue, and its impact.

## What to Expect

Reports are acknowledged within 14 days. A confirmed issue is fixed in a new
release and published as a GitHub security advisory, crediting you unless you
prefer otherwise. Please keep it private until then.

## Scope

Some behaviour is by design and documented under
[Security Considerations](README.md#security-considerations), for example that
`/probe` is unauthenticated unless `--web.config.file` enables basic auth.
