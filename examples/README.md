# 框架集成示例（一期）

演示如何把饺子认证 GDID 嵌进常见 Agent 框架。  
**默认不调用付费 LLM**：只打通「注册 / 体检发证 / 查验」；接入模型时按各目录 README 打开。

| 示例 | 路径 | 说明 |
|------|------|------|
| LangChain (TypeScript) | [`langchain-js/`](langchain-js/) | Tool：校验对方 Agent 证书后再执行动作 |
| LangChain (Python) | [`langchain-py/`](langchain-py/) | 同上 + 启动时 attest |
| CrewAI | [`crewai/`](crewai/) | Crew 启动注册/发证；Tool 校验同伴身份 |

## 前置

1. 本地 API 已运行（`http://127.0.0.1:3000` / `3001`）
2. `JIAOZI_API_KEY`（默认 `dev-key-change-me`）

```bash
# 仓库根目录
npm run demo:frameworks:setup   # 一次：Python venv + httpx
npm run demo:frameworks         # SDK 冒烟（无 LangChain/CrewAI）
npm run demo:langchain-js
npm run demo:langchain-py
npm run demo:crewai
```

## 设计约定

- **启动时**：`register`（可选）+ `attest`（本地摘要）→ 拿到 `certId` / `did`
- **调用前**：对目标 Agent 的 `certId`/`did` 做 `verify`；`ok !== true` 则拒绝
- **私钥 / seed**：只留在本地进程，不上送平台
