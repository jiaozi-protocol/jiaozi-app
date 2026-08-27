import assert from "node:assert/strict";
import { test } from "node:test";
import {
  consistencyPath,
  emptyTreeRoot,
  fromPrefixedHash,
  hashChildren,
  hashLeaf,
  inclusionPath,
  merkleRootFromLeafHashes,
  toPrefixedHash,
  verifyConsistency,
  verifyConsistencyProofJson,
  verifyInclusion,
  verifyInclusionProofJson,
} from "./merkle.js";

// RFC 6962 / RFC 9162 §2.1.1 share the same MTH; these are the widely
// reproduced known-answer leaves from the CT reference test data.
const RFC6962_LEAVES = [
  "",
  "00",
  "10",
  "2021",
  "3031",
  "40414243",
  "5051525354555657",
  "606162636465666768696a6b6c6d6e6f",
].map((hex) => Buffer.from(hex, "hex"));

const RFC6962_ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

function leafHashes(count: number): Buffer[] {
  return RFC6962_LEAVES.slice(0, count).map((l) => hashLeaf(l));
}

/** Deterministic synthetic leaf hashes for larger property-style sweeps. */
function syntheticLeafHashes(count: number): Buffer[] {
  const out: Buffer[] = [];
  for (let i = 0; i < count; i++) out.push(hashLeaf(Buffer.from(`leaf-${i}`, "utf8")));
  return out;
}

test("empty tree root is SHA-256 of the empty string", () => {
  assert.equal(
    emptyTreeRoot().toString("hex"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(merkleRootFromLeafHashes([]).toString("hex"), emptyTreeRoot().toString("hex"));
});

test("MTH matches the RFC 6962 known-answer roots for tree sizes 1..8", () => {
  for (let n = 1; n <= 8; n++) {
    assert.equal(
      merkleRootFromLeafHashes(leafHashes(n)).toString("hex"),
      RFC6962_ROOTS[n - 1],
      `root mismatch at tree size ${n}`,
    );
  }
});

test("domain separation: leaf and node prefixes differ", () => {
  const a = Buffer.alloc(32, 1);
  const b = Buffer.alloc(32, 2);
  assert.notDeepEqual(hashLeaf(Buffer.concat([a, b])), hashChildren(a, b));
});

test("inclusion proofs verify for every (leafIndex, treeSize) up to 64 leaves", () => {
  const all = syntheticLeafHashes(64);
  for (const n of [1, 2, 3, 5, 7, 8, 13, 32, 33, 64]) {
    const hashes = all.slice(0, n);
    const root = merkleRootFromLeafHashes(hashes);
    for (let i = 0; i < n; i++) {
      const path = inclusionPath(i, hashes);
      assert.ok(
        verifyInclusion({
          leafHash: hashes[i],
          leafIndex: i,
          treeSize: n,
          auditPath: path,
          rootHash: root,
        }),
        `inclusion (${i}, ${n}) must verify`,
      );
    }
  }
});

test("tampered inclusion proofs fail", () => {
  const hashes = syntheticLeafHashes(11);
  const root = merkleRootFromLeafHashes(hashes);
  const path = inclusionPath(4, hashes);
  const good = { leafHash: hashes[4], leafIndex: 4, treeSize: 11, auditPath: path, rootHash: root };
  assert.ok(verifyInclusion(good));
  // wrong leaf index
  assert.ok(!verifyInclusion({ ...good, leafIndex: 5 }));
  // wrong root
  assert.ok(!verifyInclusion({ ...good, rootHash: Buffer.alloc(32, 9) }));
  // truncated path
  assert.ok(!verifyInclusion({ ...good, auditPath: path.slice(0, -1) }));
  // extended path
  assert.ok(!verifyInclusion({ ...good, auditPath: [...path, Buffer.alloc(32, 3)] }));
  // flipped sibling
  const flipped = [...path];
  flipped[0] = Buffer.alloc(32, 7);
  assert.ok(!verifyInclusion({ ...good, auditPath: flipped }));
  // out-of-range index
  assert.ok(!verifyInclusion({ ...good, leafIndex: 11 }));
  assert.ok(!verifyInclusion({ ...good, leafIndex: -1 }));
});

test("consistency proofs verify for every 0 < first < second up to 32 leaves", () => {
  const all = syntheticLeafHashes(32);
  const roots: Buffer[] = [];
  for (let n = 1; n <= 32; n++) roots[n] = merkleRootFromLeafHashes(all.slice(0, n));
  for (let second = 2; second <= 32; second++) {
    for (let first = 1; first < second; first++) {
      const path = consistencyPath(first, all.slice(0, second));
      assert.ok(
        verifyConsistency({
          first,
          second,
          firstRoot: roots[first],
          secondRoot: roots[second],
          consistencyPath: path,
        }),
        `consistency (${first}, ${second}) must verify`,
      );
    }
  }
});

test("tampered consistency proofs fail", () => {
  const hashes = syntheticLeafHashes(13);
  const firstRoot = merkleRootFromLeafHashes(hashes.slice(0, 5));
  const secondRoot = merkleRootFromLeafHashes(hashes);
  const path = consistencyPath(5, hashes);
  const good = { first: 5, second: 13, firstRoot, secondRoot, consistencyPath: path };
  assert.ok(verifyConsistency(good));
  // swapped roots
  assert.ok(!verifyConsistency({ ...good, firstRoot: secondRoot, secondRoot: firstRoot }));
  // wrong first size
  assert.ok(!verifyConsistency({ ...good, first: 4 }));
  // truncated path
  assert.ok(!verifyConsistency({ ...good, consistencyPath: path.slice(0, -1) }));
  // corrupted node
  const corrupted = [...path];
  corrupted[0] = Buffer.alloc(32, 8);
  assert.ok(!verifyConsistency({ ...good, consistencyPath: corrupted }));
  // empty path always fails (RFC 9162 §2.1.4.2 step 1)
  assert.ok(!verifyConsistency({ ...good, consistencyPath: [] }));
  // invalid domains
  assert.ok(!verifyConsistency({ ...good, first: 0 }));
  assert.ok(!verifyConsistency({ ...good, first: 13 }));
});

test("generators reject out-of-domain arguments", () => {
  const hashes = syntheticLeafHashes(4);
  assert.throws(() => inclusionPath(4, hashes));
  assert.throws(() => inclusionPath(-1, hashes));
  assert.throws(() => consistencyPath(0, hashes));
  assert.throws(() => consistencyPath(4, hashes));
});

test("prefixed-hex carrier round-trips and JSON verifiers work", () => {
  const hashes = syntheticLeafHashes(6);
  const root = merkleRootFromLeafHashes(hashes);
  const prefixed = toPrefixedHash(root);
  assert.match(prefixed, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(fromPrefixedHash(prefixed), root);
  assert.throws(() => fromPrefixedHash("sha256:XYZ"));

  const path = inclusionPath(2, hashes).map(toPrefixedHash);
  assert.ok(
    verifyInclusionProofJson({
      leafHash: toPrefixedHash(hashes[2]),
      leafIndex: 2,
      treeSize: 6,
      auditPath: path,
      rootHash: prefixed,
    }),
  );
  assert.ok(
    !verifyInclusionProofJson({
      leafHash: toPrefixedHash(hashes[2]),
      leafIndex: 2,
      treeSize: 6,
      auditPath: ["sha256:not-hex"],
      rootHash: prefixed,
    }),
  );
  const cPath = consistencyPath(3, hashes).map(toPrefixedHash);
  assert.ok(
    verifyConsistencyProofJson({
      first: 3,
      second: 6,
      firstRoot: toPrefixedHash(merkleRootFromLeafHashes(hashes.slice(0, 3))),
      secondRoot: prefixed,
      consistencyPath: cPath,
    }),
  );
});
