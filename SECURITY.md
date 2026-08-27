# Security Policy

## Reporting a vulnerability

Email **security@jiaozi.io** with:

- affected component (package name / endpoint / spec section)
- reproduction steps or proof of concept
- impact assessment if you have one

We aim to acknowledge reports within 3 business days. Please practice responsible disclosure and give us reasonable time to remediate before publishing.

## Scope

- Published packages: `@jiaozi-protocol/gdid-core`, `@jiaozi-protocol/sdk`, `jiaozi-gdid`, `jiaozi-validator`
- The `jiaozi.status.v1` specification and its reference conformance tooling
- Production endpoints under `www.jiaozi.io` and `www.jiaozi.tech`

## Credential / key compromise

To request emergency suspension or revocation of an issued credential, email **revoke@jiaozi.io**.

## About this mirror

This repository is a read-only public slice of our internal engineering repository,
containing only open-source SDKs, standards proposals, and examples. If you spot
**sensitive information that may have been synced here by mistake** (keys, tokens,
internal URLs, credentials), please tell us privately via **security@jiaozi.io** —
do not post it publicly. We will act immediately and rotate any affected credentials.
