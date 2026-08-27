---
name: Implementation report
about: You built an issuer or verifier — tell us how it went
labels: implementation
---

## What did you implement?

- [ ] Issuer
- [ ] Verifier
- Language / stack:

## Conformance result

Paste the output of `node conformance.mjs [your-endpoint] [certId]`:

```
(output here)
```

## Anything in the spec that was ambiguous, surprising, or annoying?

This is the most valuable part of the report — rough edges you hit become
spec fixes for everyone.

## Want to be listed?

If your deployment is public and passes conformance, open a PR adding it to
`implementations.json` (CI will judge it automatically).
