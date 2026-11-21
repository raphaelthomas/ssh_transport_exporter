# AGENTS.md

Prometheus exporter for the SSH transport layer (RFC 4253).

## Principles

- By design, the exporter is strictly limited to the SSH transport layer
  (RFC 4253). It never authenticates (RFC 4252), never opens a channel
  (RFC 4254) and never holds credentials: no private keys, passwords or agent
  access, ever.
- The probe establishes the SSH transport connection like the SSH client
  implementation its profile names, OpenSSH by default. It succeeds and fails
  where that implementation would, and may give a more specific reason.
- Every way the supported clients differ is a config key. A profile
  (`internal/profile`) presets these keys; the default, `openssh`, follows
  OpenSSH 10.6, limited to what `golang.org/x/crypto` implements.
- Keep the x/crypto fork to its `TransportReadyCallback`. Work around x/crypto
  here, with tests that fail if its behaviour changes.
- Names: RFC 4253's terms, else OpenSSH's (`known_hosts`, `@cert-authority`,
  host certificate, plain key).
- Wrap errors with `%w` and map them to reasons only in the `classify*`
  functions in `internal/probe`. Never match error text.
- No filesystem writes, not even temp files. The probe reads no files:
  `known_hosts` is read at config load only.
- Name versions with closed ranges ("10.3 to 10.6"), never "latest".

## Code and docs

- Tight code. Comment only a non-obvious why, or what the code can't show.
  Exported identifiers get a one-line doc comment.
- README: OpenSSH's terms ("listed for the target", never "pinned"), short
  sentences, observable behaviour only.
- Document every outcome that differs from OpenSSH under "Differences from
  OpenSSH".
- Checks: `make test vet lint vuln e2e`.

## New OpenSSH release

Diff `myproposal.h`, `sshconnect.c`, `sshconnect2.c`, `hostfile.c` and
`sshkey.c` against the previous release. No change in behaviour: add an alias
in `internal/profile`. Otherwise: add a profile there, move `openssh` to it,
and update the golden tests. Update the version ranges in the README and here.

Profiles start at 8.8. 8.5 to 8.7 differ only by also offering `ssh-rsa`.
Before 8.5, host key ordering differs and needs two new keys.

## x/crypto fork

`go.mod` replaces `golang.org/x/crypto` with `github.com/raphaelthomas/crypto`.
`go get` doesn't work with that replace. After rebasing the fork: push it, run
`go mod edit -replace golang.org/x/crypto=github.com/raphaelthomas/crypto@<sha>`
and `go mod tidy`, then set the `require` version to the upstream tag the fork
is based on.
