/**
 * @jiaozi-protocol/tlog-core — jiaozi.tlog.v1 credential lifecycle
 * transparency log core (standards/tlog-v1/DESIGN.md; RFC 9162 / RFC 9943
 * aligned). Pure library: no HTTP layer, no persistence beyond the in-memory
 * reference storage.
 */

export {
  TLOG_SCHEMA,
  TLOG_EVENT_TYPES,
  assertTlogEntryV1,
  buildTlogEntry,
  canonicalEntryJson,
  encodeLeafInput,
  entryLeafHash,
  isTlogEntryV1,
  validateTlogEntryV1,
  type TlogEntryV1,
  type TlogEntryValidationError,
  type TlogEventType,
} from "./entry.js";

export {
  LEAF_HASH_PREFIX,
  NODE_HASH_PREFIX,
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

export {
  STH_SCHEMA,
  buildSthPayload,
  isSignedTreeHeadV1,
  signTreeHead,
  verifySignedTreeHead,
  type SignedTreeHeadV1,
  type SthPayloadV1,
  type SthVerifyFailure,
  type SthVerifyResult,
} from "./sth.js";

export {
  MemoryTlogStorage,
  type StoredTlogEntry,
  type TlogStorage,
} from "./storage.js";

export {
  TransparencyLog,
  type AppendResult,
  type ConsistencyProofJson,
  type InclusionProofJson,
  type TlogSigningKey,
} from "./log.js";
