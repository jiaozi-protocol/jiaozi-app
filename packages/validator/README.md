# jiaozi-validator

Local health-check CLI for AI agents. Scans your agent directory, computes a
software gene hash, and produces a `jiaozi.attest.v1` summary — optionally
submitting it to [JIAOZI](https://www.jiaozi.io) for credential issuance.

Your code never leaves your machine: only hashes and check results are
submitted.

```bash
pip install jiaozi-validator

# 1) Generate your owner key pair (once). The credential binds to this key —
#    it is what proves the agent is YOURS. Keep owner.pem safe.
node -e "const c=require('crypto'),f=require('fs');const{publicKey,privateKey}=c.generateKeyPairSync('ed25519');f.writeFileSync('owner.pem',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});const d=publicKey.export({type:'spki',format:'der'});f.writeFileSync('owner.pub','z'+d.subarray(d.length-32).toString('base64url')+'\n');console.log('written: owner.pem (private, keep safe) + owner.pub')"

# 2) Print the attestation summary only (nothing is sent anywhere)
jiaozi-validator --agent-name MyAgent --path ./my-agent \
  --owner-pubkey-file owner.pub --dry-run

# 3) Submit for issuance (requires an API key)
export JIAOZI_API_KEY=your-key
jiaozi-validator --agent-name MyAgent --path ./my-agent \
  --owner-pubkey-file owner.pub \
  --api-url https://www.jiaozi.io/api/verify
```

China deployment: use `--api-url https://www.jiaozi.tech/api/verify`.

## Owner key is required

Since 0.3.2 the CLI **refuses to run without an owner public key**. Earlier
versions silently fell back to a public demo placeholder key, which meant the
issued credential bound its "owner" to a key anyone could claim — ownership
proof was void without the user noticing.

- Normal use: pass `--owner-pubkey-file <file>` (generate one with the
  one-liner above, or `node scripts/gen-owner-key.mjs <name>` inside the
  jiaozi_app repo).
- Demo / smoke-test only: pass `--demo-owner-key` to explicitly opt in to the
  placeholder key. A loud warning is printed to stderr and the local report
  gains `"_local": { "ownerKeyDemo": true }`. The marker stays in the
  local-only `_local` section and is never part of the submitted payload; a
  credential issued this way cannot prove ownership.

## What it checks

- Software gene hash (deterministic digest of your agent's code)
- Secret-leak scan (common credential patterns)
- Structure and metadata sanity

The output schema `jiaozi.attest.v1` is part of the open protocol
([jiaozi-protocol](https://github.com/jiaozi-protocol) GitHub org); the
credential's live revocation status is verifiable by anyone via the
[`jiaozi.status.v1`](https://github.com/jiaozi-protocol/status-v1) spec.

## Development

```bash
cd packages/validator
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
python -m unittest discover -s tests -v
```

MIT License.
