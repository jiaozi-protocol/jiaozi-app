# CrewAI × 饺子认证

## Offline（推荐，无 LLM）

两个 Crew「角色」各自 `register` + `attest`，再互相 `verify`：

```bash
cd examples/crewai
python run.py
```

## 完整 Crew（需 LLM）

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
python run.py --crew
```

## 接入模式

1. **启动**：`bootstrap_agent("CrewRoleName")` → 把 `certId` 写入 Agent `backstory` / 元数据  
2. **Tool**：`as_crewai_tool()` → `jiaozi_verify_peer`  
3. **任务描述**：要求先 verify 同伴证书再协作  

私钥不上送；只交换 `certId` / `did`。
