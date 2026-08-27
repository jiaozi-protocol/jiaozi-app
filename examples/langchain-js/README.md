# LangChain (TypeScript) × 饺子认证

## 做什么

1. Agent 启动时 `register` + `attest`，获得 `certId` / `did`
2. 提供 LangChain Tool `jiaozi_verify_peer`：调用前校验对方证书
3. 默认 **offline** 演示不调用 OpenAI

## 运行

```bash
# 仓库根：确保 API 已起
cd examples/langchain-js
# 复用根 node_modules 亦可直接：
node --import tsx --tsconfig ../../tsconfig.base.json src/run.ts
```

或在本目录：

```bash
npm install
npm run demo
```

带 LLM：

```bash
npm install @langchain/core @langchain/openai langchain zod
export OPENAI_API_KEY=sk-...
npm run demo:llm
```

## 接入你自己的 Agent

```ts
import { bootstrapAgent, verifyPeerToolHandler, verifyPeerToolSpec } from "./jiaoziLangChain.js";
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

const identity = await bootstrapAgent("MyLangChainAgent");
const tool = new DynamicStructuredTool({
  name: verifyPeerToolSpec.name,
  description: verifyPeerToolSpec.description,
  schema: z.object({ didOrCertId: z.string() }),
  func: async (input) => verifyPeerToolHandler(input),
});
// 把 tool 放进 AgentExecutor.tools
```
