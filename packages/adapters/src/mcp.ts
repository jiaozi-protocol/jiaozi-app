/**
 * MCP server trust adapter — declarative "credential level → tool access"
 * gating for any MCP server ("凭证的价值 = 持证者的权限差").
 *
 * Protocol-neutral, zero new runtime dependencies: the MCP `tools/call`
 * request is a stable, public JSON-RPC 2.0 shape, so we model it with minimal
 * structural types instead of depending on @modelcontextprotocol/sdk. All
 * trust *semantics* live in the SDK's `requireTrust` (工单 #6) — this module
 * only translates MCP shapes ↔ requireTrust inputs/outputs and matches the
 * policy table; not one line of verdict logic is re-implemented.
 *
 * Credential presentation, two equivalent lanes:
 *  1. `params._meta["jiaozi.io/status"]` — MCP spec (2025-06-18, Schema §
 *     General fields) reserves `_meta` for clients/servers to "attach
 *     additional metadata to their interactions"; key prefix must be
 *     dot-separated labels + "/", so we namespace under our own domain.
 *     Value may be the credential JSON object, or a JSON/base64url string.
 *  2. HTTP transport headers `x-jiaozi-status` / `x-jiaozi-boundary`
 *     (reuses the SDK's presentationFromHeaders verbatim).
 */

import type { TrustLevel } from "@jiaozi-protocol/gdid-core";
import {
  presentationFromHeaders,
  requireTrust,
  TRUST_STATUS_HEADER,
  type RequirableTrustLevel,
  type RequireTrustOptions,
  type TrustChecker,
  type TrustDenyCode,
  type TrustFreshness,
  type TrustPresentation,
} from "@jiaozi-protocol/sdk";

// ---- MCP wire shapes (minimal structural types; JSON-RPC 2.0) --------------

export type McpRequestId = string | number;

/** `tools/call` request, per MCP spec 2025-06-18 (server/tools). */
export type McpToolCallRequest = {
  jsonrpc?: "2.0";
  id?: McpRequestId;
  method?: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    /** MCP-reserved extension slot; our keys are namespaced "jiaozi.io/…". */
    _meta?: Record<string, unknown>;
  };
};

export type McpJsonRpcResponse = {
  jsonrpc: "2.0";
  id: McpRequestId | null;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: Record<string, unknown> };
};

/** `_meta` keys (spec-valid prefix: dot-separated labels + "/"). */
export const TRUST_STATUS_META_KEY = "jiaozi.io/status";
export const TRUST_BOUNDARY_META_KEY = "jiaozi.io/boundary";

/**
 * JSON-RPC error code for a trust denial. Implementation-defined server-error
 * range is -32000…-32099 (JSON-RPC 2.0 §5.1); MCP already claims -32000
 * (connection closed) / -32001 (request timeout) in its official SDKs and
 * -32002 ("Resource not found") in the spec's resources examples, so we take
 * the next free slot.
 */
export const MCP_TRUST_DENIED_CODE = -32003;

/** Unknown tool → spec's own convention (server/tools §Error Handling). */
export const MCP_UNKNOWN_TOOL_CODE = -32602;

// ---- policy table -----------------------------------------------------------

export type McpToolRule = {
  /** Open tier: callable with no credential (e.g. read-only tools). */
  public?: boolean;
  /** Minimum trust level; default "software" (any valid credential). */
  minLevel?: RequirableTrustLevel;
  /** Behaviours this tool exercises, matched against the declared boundary. */
  behaviors?: string[];
};

export type McpPolicyOptions = {
  tools: Record<string, McpToolRule>;
  /** Rule for tools not listed; omitted → unknown tools denied (fail-closed). */
  default?: McpToolRule;
  /** Shared requireTrust wiring: verify passthrough + policy ladder + pins. */
  trust?: Pick<RequireTrustOptions, "verify" | "policy" | "issuerKeys">;
};

type CompiledRule = { rule: McpToolRule; check: TrustChecker };

export type McpToolPolicy = {
  /** Compiled rule lookup; null = tool unknown to the policy (fail-closed). */
  ruleFor(toolName: string): CompiledRule | null;
  /** Identity probe for public tools: any valid credential, no gate. */
  identify: TrustChecker;
};

/**
 * Compile a declarative policy table into per-tool requireTrust checkers.
 * Compilation is eager so requireTrust's build-time fail-closed checks (e.g.
 * "pinned" without issuerKeys) surface at server start, not at first call.
 */
export function defineToolPolicy(options: McpPolicyOptions): McpToolPolicy {
  const shared = options.trust ?? {};
  const compile = (rule: McpToolRule): CompiledRule => ({
    rule,
    check: requireTrust({
      ...shared,
      ...(rule.minLevel ? { minLevel: rule.minLevel } : {}),
      ...(rule.behaviors ? { behaviors: rule.behaviors } : {}),
    }),
  });
  const table = new Map<string, CompiledRule>(
    Object.entries(options.tools).map(([name, rule]) => [name, compile(rule)]),
  );
  const fallback = options.default ? compile(options.default) : null;
  return {
    ruleFor: (toolName) => table.get(toolName) ?? fallback,
    identify: requireTrust({ ...shared }),
  };
}

// ---- presentation extraction ------------------------------------------------

/**
 * Parse a `_meta` value: pass JSON objects through; delegate string decoding
 * (raw JSON or base64/base64url) to the SDK's header parser so both lanes
 * share one implementation.
 */
function parseFlexible(value: unknown): unknown {
  if (value !== null && typeof value === "object") return value;
  if (typeof value === "string") {
    return presentationFromHeaders({ [TRUST_STATUS_HEADER]: value }).statusCredential;
  }
  return undefined;
}

/**
 * Extract a trust presentation from an MCP `tools/call` request. Field-wise
 * precedence: `params._meta` first, then (HTTP transports) the
 * `x-jiaozi-status` / `x-jiaozi-boundary` headers.
 */
export function presentationFromMcpRequest(
  request: McpToolCallRequest,
  headers?: Record<string, string | string[] | undefined>,
): TrustPresentation {
  const meta = request.params?._meta;
  const fromHeaders = headers ? presentationFromHeaders(headers) : {};
  const presentation: TrustPresentation = {};

  const status = parseFlexible(meta?.[TRUST_STATUS_META_KEY]) ?? fromHeaders.statusCredential;
  if (status !== undefined) presentation.statusCredential = status;

  const boundary = parseFlexible(meta?.[TRUST_BOUNDARY_META_KEY]) ?? fromHeaders.behaviorBoundary;
  if (boundary !== undefined && typeof boundary === "object") {
    presentation.behaviorBoundary = boundary as TrustPresentation["behaviorBoundary"];
  }
  return presentation;
}

// ---- gate -------------------------------------------------------------------

export type McpDenyCode = TrustDenyCode | "unknown_tool";

export type McpGateDecision =
  | {
      allowed: true;
      toolName: string;
      /** "public" = open tier; "gated" = passed a requireTrust gate. */
      tier: "public" | "gated";
      trustLevel: TrustLevel | null;
      certId?: string;
      freshness?: TrustFreshness;
    }
  | {
      allowed: false;
      toolName: string;
      reasonCode: McpDenyCode;
      /** Bilingual, human-readable: "中文说明 / English explanation" */
      reason: string;
      trustLevel: TrustLevel | null;
      certId?: string;
    };

/**
 * Gate one tool call against the policy. Pure translation: requireTrust's
 * verdict is passed through untouched; the only adapter-level deny is
 * "unknown_tool" (tool absent from the table and no default — fail-closed).
 */
export function gateToolCall(
  policy: McpToolPolicy,
  call: { toolName: string; presentation?: TrustPresentation | null },
): McpGateDecision {
  const { toolName, presentation } = call;
  const compiled = policy.ruleFor(toolName);
  if (!compiled) {
    return {
      allowed: false,
      toolName,
      reasonCode: "unknown_tool",
      reason: `工具 "${toolName}" 未在策略表中声明且无 default 规则,按未知工具拒绝 / Tool "${toolName}" is not declared in the policy table and no default rule exists; denied as unknown tool (fail-closed)`,
      trustLevel: null,
    };
  }

  if (compiled.rule.public) {
    // Open tier never denies; a valid credential still identifies the caller.
    const id = presentation?.statusCredential ? policy.identify(presentation) : null;
    return {
      allowed: true,
      toolName,
      tier: "public",
      trustLevel: id?.allowed ? id.trustLevel : null,
      ...(id?.allowed ? { certId: id.certId, freshness: id.freshness } : {}),
    };
  }

  const decision = compiled.check(presentation);
  if (decision.allowed) {
    return {
      allowed: true,
      toolName,
      tier: "gated",
      trustLevel: decision.trustLevel,
      certId: decision.certId,
      freshness: decision.freshness,
    };
  }
  return {
    allowed: false,
    toolName,
    reasonCode: decision.reasonCode,
    reason: decision.reason,
    trustLevel: decision.trustLevel,
    ...(decision.certId ? { certId: decision.certId } : {}),
  };
}

// ---- JSON-RPC translation ---------------------------------------------------

/** Build the MCP-conformant JSON-RPC error response for a denial. */
export function toolCallError(
  denied: Extract<McpGateDecision, { allowed: false }>,
  id: McpRequestId | null | undefined,
): McpJsonRpcResponse {
  if (denied.reasonCode === "unknown_tool") {
    return {
      jsonrpc: "2.0",
      id: id ?? null,
      error: {
        code: MCP_UNKNOWN_TOOL_CODE,
        message: `Unknown tool: ${denied.toolName}`,
        data: { reasonCode: denied.reasonCode, reason: denied.reason },
      },
    };
  }
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code: MCP_TRUST_DENIED_CODE,
      message: denied.reason,
      data: {
        reasonCode: denied.reasonCode,
        tool: denied.toolName,
        trustLevel: denied.trustLevel,
        ...(denied.certId ? { certId: denied.certId } : {}),
      },
    },
  };
}

// ---- tools/call wrapper -----------------------------------------------------

export type McpToolContext = {
  trust: Extract<McpGateDecision, { allowed: true }>;
  request: McpToolCallRequest;
};

export type McpToolHandler = (
  args: Record<string, unknown>,
  context: McpToolContext,
) => unknown;

export type McpToolHandlers = Record<string, McpToolHandler>;

function normalizeResult(out: unknown): Record<string, unknown> {
  if (out !== null && typeof out === "object" && Array.isArray((out as { content?: unknown }).content)) {
    return out as Record<string, unknown>;
  }
  const text = typeof out === "string" ? out : JSON.stringify(out ?? null);
  return { content: [{ type: "text", text }] };
}

/**
 * Wrap plain tool handlers into a gated MCP `tools/call` dispatcher.
 * Denials come back as JSON-RPC errors (protocol errors, per spec);
 * handler exceptions come back as tool-execution errors (`isError: true`
 * results, per spec) — the transport connection stays healthy either way.
 */
export function wrapToolHandler(
  policyOrOptions: McpToolPolicy | McpPolicyOptions,
  handlers: McpToolHandlers,
): (
  request: McpToolCallRequest,
  transport?: { headers?: Record<string, string | string[] | undefined> },
) => Promise<McpJsonRpcResponse> {
  const policy = "ruleFor" in policyOrOptions ? policyOrOptions : defineToolPolicy(policyOrOptions);

  return async (request, transport) => {
    const id = request.id ?? null;
    const toolName = request.params?.name;
    if (typeof toolName !== "string" || toolName.length === 0) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: MCP_UNKNOWN_TOOL_CODE, message: "Invalid params: missing tool name" },
      };
    }

    const handler = handlers[toolName];
    if (!handler) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: MCP_UNKNOWN_TOOL_CODE, message: `Unknown tool: ${toolName}` },
      };
    }

    const presentation = presentationFromMcpRequest(request, transport?.headers);
    const decision = gateToolCall(policy, { toolName, presentation });
    if (!decision.allowed) return toolCallError(decision, id);

    try {
      const out = await handler(request.params?.arguments ?? {}, { trust: decision, request });
      return { jsonrpc: "2.0", id, result: normalizeResult(out) };
    } catch (err) {
      // Tool execution error, per spec: reported inside the result.
      const message = err instanceof Error ? err.message : String(err);
      return {
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: `Tool execution failed: ${message}` }], isError: true },
      };
    }
  };
}
