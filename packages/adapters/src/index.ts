import type { DidDocumentMinimal } from "@jiaozi-protocol/gdid-core";

export type AdapterView = {
  standardId: string;
  adapter: string;
  view: unknown;
};

/** W3C DID Core view — pass-through of stored DID Document subset. */
export function toW3cDidView(document: DidDocumentMinimal | Record<string, unknown>): AdapterView {
  return {
    standardId: "w3c-did-core",
    adapter: "w3c-did",
    view: document,
  };
}

/**
 * did:key view (second Phase-1 adapter).
 * Uses owner publicKeyMultibase when present; otherwise marks unsupported.
 * Spec: https://w3c-ccg.github.io/did-key-spec/
 */
export function toDidKeyView(document: DidDocumentMinimal | Record<string, unknown>): AdapterView {
  const vm = Array.isArray((document as DidDocumentMinimal).verificationMethod)
    ? (document as DidDocumentMinimal).verificationMethod[0]
    : undefined;
  const multibase = vm?.publicKeyMultibase;
  if (!multibase) {
    return {
      standardId: "did-key",
      adapter: "did-key",
      view: {
        unsupported: true,
        reason: "missing publicKeyMultibase",
      },
    };
  }
  // If already z-multibase Ed25519 material, expose did:key:<multibase>
  const didKey = multibase.startsWith("z") ? `did:key:${multibase}` : `did:key:z${multibase}`;
  return {
    standardId: "did-key",
    adapter: "did-key",
    view: {
      id: didKey,
      controller: didKey,
      derivedFrom: (document as DidDocumentMinimal).id,
      verificationMethod: [
        {
          id: `${didKey}#${multibase}`,
          type: "Ed25519VerificationKey2020",
          controller: didKey,
          publicKeyMultibase: multibase.startsWith("z") ? multibase : `z${multibase}`,
        },
      ],
      authentication: [`${didKey}#${multibase}`],
      assertionMethod: [`${didKey}#${multibase}`],
    },
  };
}

export function multiStandardViews(
  document: DidDocumentMinimal | Record<string, unknown>,
): AdapterView[] {
  return [toW3cDidView(document), toDidKeyView(document)];
}

// MCP server trust adapter (工单 #10) — new module, existing exports untouched.
export * from "./mcp.js";
