/**
 * LangChain JS + Jiaozi GDID demo
 *
 *   npm run demo        # no LLM
 *   npm run demo:llm    # needs @langchain/* + OPENAI_API_KEY
 */
import {
  bootstrapAgent,
  requireVerified,
  verifyPeerToolHandler,
  verifyPeerToolSpec,
} from "./jiaoziLangChain.js";

async function runOffline() {
  console.log("=== LangChain JS × Jiaozi (offline / no LLM) ===");
  const me = await bootstrapAgent("LangChainJsAgent");
  console.log("bootstrapped", { certId: me.certId, did: me.did });

  const peer = await bootstrapAgent("LangChainJsPeer");
  const checked = await requireVerified(peer.certId);
  console.log("verified peer", {
    certId: checked.certId,
    trustLevel: checked.trustLevel,
    ok: checked.ok,
  });

  const toolOut = await verifyPeerToolHandler({ didOrCertId: peer.certId });
  console.log("tool handler", toolOut);
  console.log("tool spec:", verifyPeerToolSpec.name);
  console.log("OK");
}

async function runWithLangChain() {
  const { DynamicStructuredTool } = await import("@langchain/core/tools");
  const { z } = await import("zod");
  const { ChatOpenAI } = await import("@langchain/openai");
  const { AgentExecutor, createToolCallingAgent } = await import("langchain/agents");
  const { ChatPromptTemplate } = await import("@langchain/core/prompts");

  const me = await bootstrapAgent("LangChainJsLlmAgent");
  console.log("agent cert", me.certId);

  const tool = new DynamicStructuredTool({
    name: verifyPeerToolSpec.name,
    description: verifyPeerToolSpec.description,
    schema: z.object({
      didOrCertId: z.string().describe("Peer JIAOZI-… credential or DID"),
    }),
    func: async ({ didOrCertId }) => verifyPeerToolHandler({ didOrCertId }),
  });

  const llm = new ChatOpenAI({ model: "gpt-4o-mini", temperature: 0 });
  const prompt = ChatPromptTemplate.fromMessages([
    [
      "system",
      "You are a secure agent. Before collaborating, call jiaozi_verify_peer on the peer certId.",
    ],
    ["human", "{input}"],
    ["placeholder", "{agent_scratchpad}"],
  ]);
  const agent = await createToolCallingAgent({ llm, tools: [tool], prompt });
  const executor = new AgentExecutor({ agent, tools: [tool] });
  const peer = await bootstrapAgent("LangChainJsLlmPeer");
  const result = await executor.invoke({
    input: `Verify peer certificate ${peer.certId} then say ready.`,
  });
  console.log(result.output);
}

const mode = process.argv.includes("--llm") ? "llm" : "offline";
const runner = mode === "llm" ? runWithLangChain : runOffline;
runner().catch((err) => {
  console.error(err);
  if (mode === "llm") {
    console.error("Hint: npm install in examples/langchain-js && set OPENAI_API_KEY");
  }
  process.exit(1);
});
