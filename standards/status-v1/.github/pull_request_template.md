## What kind of change is this?

- [ ] Registry addition (`implementations.json`) — CI runs conformance against
      your endpoint; green = merged, red = not yet.
- [ ] Spec editorial (wording only, no wire-behavior change)
- [ ] Spec behavioral (changes what implementations must do)
- [ ] Tooling (conformance tester, generator, CI)

## For behavioral spec changes (delete otherwise)

- [ ] `test-vectors.json` regenerated and updated
- [ ] `conformance.mjs` updated to check the new behavior
- [ ] Versioning respected: incompatible changes bump the schema string
      (`jiaozi.status.v2`), they do not mutate v1
- [ ] Reference deployment (`www.jiaozi.io`) either already conforms or a
      rollout plan is described below

## Description
