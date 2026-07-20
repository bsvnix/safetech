# Contributing to reconkit

Thanks for helping! PRs that add resolvers, tighten the SSRF checks, or add
rate-limit/cache backends are very welcome.

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. Sign off
every commit to certify you wrote the patch and can submit it under the project
license:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. That's the whole
process — no copyright assignment.

## Dev setup

```bash
pip install -e ".[dev]"
pytest -q
```

## Guidelines

- Keep the core dependency-free; new third-party deps go under an optional extra.
- Security-relevant changes need a test that fails without the fix.
- Match the existing fail-closed (security) / fail-open (cache) contracts.
