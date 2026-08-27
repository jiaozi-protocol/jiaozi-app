#!/usr/bin/env python3
"""LangChain Python × Jiaozi — offline by default; --llm needs OpenAI + langchain."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "shared"))
sys.path.insert(0, str(ROOT / "examples" / "langchain-py"))

from jiaozi_bootstrap import bootstrap_agent, require_verified  # noqa: E402
from jiaozi_tool import as_langchain_tool, jiaozi_verify_peer  # noqa: E402


def run_offline() -> None:
    print("=== LangChain Py × Jiaozi (offline / no LLM) ===")
    me = bootstrap_agent("LangChainPyAgent", capabilities=["langchain-py"])
    print("bootstrapped", {k: me[k] for k in ("certId", "did", "trustLevel")})
    peer = bootstrap_agent("LangChainPyPeer")
    print("verified", require_verified(peer["certId"]))
    print("tool", jiaozi_verify_peer(peer["certId"]))
    print("OK")


def run_llm() -> None:
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    me = bootstrap_agent("LangChainPyLlmAgent")
    peer = bootstrap_agent("LangChainPyLlmPeer")
    tool = as_langchain_tool()
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a secure agent. Call jiaozi_verify_peer before collaborating.",
            ),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ]
    )
    agent = create_tool_calling_agent(llm, [tool], prompt)
    executor = AgentExecutor(agent=agent, tools=[tool])
    out = executor.invoke(
        {"input": f"Verify peer certificate {peer['certId']} then say ready. My cert is {me['certId']}."}
    )
    print(out.get("output"))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--llm", action="store_true")
    args = p.parse_args()
    try:
        if args.llm:
            run_llm()
        else:
            run_offline()
    except Exception as exc:  # noqa: BLE001
        print(exc, file=sys.stderr)
        if args.llm:
            print("Hint: pip install -r requirements.txt && export OPENAI_API_KEY=...", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
