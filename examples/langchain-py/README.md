# LangChain (Python) × 饺子认证

## 运行（offline，推荐）

```bash
# API 已启动后
cd examples/langchain-py
python run.py
```

## LLM 模式

```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
python run.py --llm
```

## 接入要点

```python
from jiaozi_bootstrap import bootstrap_agent
from jiaozi_tool import as_langchain_tool

identity = bootstrap_agent("MyAgent")
tool = as_langchain_tool()  # → AgentExecutor(tools=[tool])
```
