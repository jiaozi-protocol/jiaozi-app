# JIAOZI Protocol

Verifiable identity & attestation infrastructure for AI agents, built on open standards: **W3C DID / VC 2.0 · A2A Agent Card · IETF Web Bot Auth (draft)**.

- Portal & docs: https://www.jiaozi.io (China intake: https://www.jiaozi.tech)
- Every agent gets a `did:web` identity anchored at `www.jiaozi.io`, a verifiable credential (`JIAOZI-YYYY-NNNNNN`), and second-level status freshness (`jiaozi.status.v1`, re-signed every 60 s).

## Published packages

| Package | Registry | Install |
|---|---|---|
| [`@jiaozi-protocol/gdid-core`](https://www.npmjs.com/package/@jiaozi-protocol/gdid-core) | npm | `npm i @jiaozi-protocol/gdid-core` |
| [`@jiaozi-protocol/sdk`](https://www.npmjs.com/package/@jiaozi-protocol/sdk) | npm | `npm i @jiaozi-protocol/sdk` |
| [`jiaozi-gdid`](https://pypi.org/project/jiaozi-gdid/) | PyPI | `pip install jiaozi-gdid` |
| [`jiaozi-validator`](https://pypi.org/project/jiaozi-validator/) | PyPI | `pip install jiaozi-validator` |

## Repository layout

```text
packages/gdid-core     # protocol core: DID documents, credential IDs, status.v1 sign/verify (TypeScript)
packages/gdid-sdk-js   # JS/TS SDK: register / attest / resolve / verify
packages/gdid-sdk-py   # Python SDK
packages/validator     # local agent health-check CLI (produces jiaozi.attest.v1 summaries)
packages/adapters      # framework adapters
standards/status-v1    # jiaozi.status.v1 spec, test vectors, conformance runner
standards/delegation-v1  # multi-hop attenuable delegation — draft under community review
standards/tlog-v1      # transparency log design — draft under community review
examples/              # LangChain (JS/Py) & CrewAI integration examples
samples/demo-agent     # minimal agent used in demos
```

## Quick verify (no account needed)

```bash
# resolve a live credential against the production resolver
curl "https://www.jiaozi.io/api/resolve?q=JIAOZI-2026-000001"

# check the sentinel agent's DID document (W3C DID Core conformant)
curl "https://www.jiaozi.io/agents/jp-2026-000016/did.json"
```

## Dogfooding: this codebase is built by a certified agent

Part of this repository is implemented by our own autonomous builder agent, which carries a JIAOZI credential like any customer agent would:

- Credential: **JIAOZI-2026-000019** — verify live at <https://www.jiaozi.io/certs/JIAOZI-2026-000019>
- DID: `did:web:www.jiaozi.io:agents:jiaozi-2026-000019`
- Its attestation binds the agent's mandate charter and a declared behavior boundary (what it may edit, what it must never touch — e.g. no key material, no protocol semantics). Delivery reports from the builder carry the credential ID so anyone can check who did the work and whether the credential is still active.

We manage our agent workforce with the same identity + permission-boundary primitives we sell. If it breaks, we feel it first.

## About this repository — read-only mirror

**This is a read-only snapshot mirror. We do not accept pull requests here.** The repository is snapshot-synced from our primary development repository; each sync replaces the entire history, so any PR opened against this repo would lose its base commit. Please don't spend effort on one — use the channels below instead (they are not affected by snapshot syncs):

| What you have | Where to send it |
|---|---|
| Bug reports & feature requests (SDKs, validator, examples) | [GitHub Issues](https://github.com/jiaozi-protocol/jiaozi-app/issues) on this repo, or **hello@jiaozi.io** |
| Standards review & design feedback (`standards/*/DESIGN.md`) | GitHub Issues with a `[standards]` title prefix, the relevant [W3C CCG mailing list](https://lists.w3.org/Archives/Public/public-credentials/) thread, or **hello@jiaozi.io** |
| Security vulnerabilities | **security@jiaozi.io** — see [SECURITY.md](SECURITY.md) |

Standards feedback is what we want most: the drafts under `standards/` are open proposals under active community review, revisions are versioned, and substantive reviewers are credited in the revision notes (with permission). See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

The hosted portal and issuing services (intake, KYB, issuance nodes) are operated by the JIAOZI team and are not part of this repository.

## License

MIT — see [LICENSE](LICENSE).

## Security

Please report vulnerabilities to **security@jiaozi.io** — see [SECURITY.md](SECURITY.md).
