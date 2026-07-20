# Security Policy

safefetch ships security primitives, so we take reports seriously.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Instead, use
GitHub's private ["Report a vulnerability"](../../security/advisories/new)
advisory flow on this repository.

Include: affected version, a reproduction, and the impact you see. We aim to
acknowledge within a few business days.

## Scope

The SSRF guard (`safefetch.guard`) is the highest-value target. Reports we
especially want:

- A redirect chain, DNS answer, URL shape, or IP-literal encoding that reaches a
  private / loopback / link-local / CGNAT / reserved address past `validate_url`,
  `safe_get`/`safe_post`, or a `Guard`.
- Any way the fail-closed contract is violated (a blocked target that still gets
  fetched), or an allowlist escape (a target outside `allow_hosts`/`allow_cidrs`
  that is nonetheless fetched).

## Non-goals (documented, not bugs)

- `validate_url` is a *pre-flight* check; the authoritative defense is
  `safe_get`/`safe_post` (and `Guard.get`/`.post`), which re-validate every
  redirect hop. Using bare `requests` after `validate_url` reintroduces the
  redirect gap by design.
- TOCTOU between DNS resolution and connect is mitigated (any private answer
  rejects the hostname) but not eliminated; pin-and-connect is a caller concern.
- Response-side risks (body-size/decompression limits) and network-layer egress
  control are out of scope. See the threat model in the README.
