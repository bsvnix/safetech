# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

Renamed from `reconkit` to `safefetch` and refocused on the SSRF guard as the
headline feature.

### Added

- `Guard` class carrying a reusable SSRF policy, with `.check()`, `.get()`,
  `.post()`, and `.request()`.
- **Allowlist mode** via `Guard(allow_hosts=..., allow_cidrs=...)` — permit only
  named hosts (with `*.` wildcards) and/or CIDRs, blocking everything else
  including redirects that try to leave. `allow_cidrs` may name private ranges.
- **`on_block(url, reason)` hook** on `Guard`, `safe_get`, and `safe_post` for
  metrics/logging. A hook that raises is swallowed and can never open the guard.
- Explicit rejection of CGNAT (`100.64.0.0/10`), NAT64 (`64:ff9b::/96`),
  TEST-NET, and benchmarking ranges, independent of CPython version.
- Tests covering encoded IP literals (decimal/octal/hex), IPv4-mapped IPv6,
  NAT64-embedded loopback, redirect escapes, allowlist mode, and the block hook.

### Changed

- Package renamed `reconkit` → `safefetch`; the `net` subpackage was flattened,
  so imports move from `reconkit.net.ssrf` to `safefetch.guard` (or the
  top-level `from safefetch import ...`).
- `ALLOWED_INTERNAL_HOSTS` renamed to `BLOCKED_HOSTS` (old name kept as an
  alias).
- README narrowed to a single headline (SSRF-through-redirects) and now carries
  an explicit threat model.

### Fixed

- **CGNAT `100.64.0.0/10` was treated as a public address** by the previous
  `_is_public_ip`, since `ipaddress` does not flag it as private. It is now
  blocked.

## [0.1.0]

Initial internal release as `reconkit`: SSRF guard with redirect re-validation,
cross-process Redis rate limiter, and fail-open HTTP cache.
