#!/usr/bin/env python3
"""CrewAI × Jiaozi GDID demo — offline by default."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "shared"))
sys.path.insert(0, str(ROOT / "examples" / "crewai"))

from jiaozi_bootstrap import bootstrap_agent, require_verified  # noqa: E402
from jiaozi_tools import verify_peer_cert  # noqa: E402


def run_offline() -> None:
    print("=== CrewAI × Jiaozi (offline / no LLM) ===")
    researcher = bootstrap_agent("CrewResearcher", capabilities=["research"])
    writer = bootstrap_agent("CrewWriter", capabilities=["write"])
    print("researcher", researcher["certId"])
    print("writer", writer["certId"])
    # Mutual verification before "crew" work
    print("researcher verifies writer:", verify_peer_cert(writer["certId"]))
    print("writer verifies researcher:", verify_peer_cert(researcher["certId"]))
    print("require_verified ok", require_verified(researcher["did"])["ok"])
    print("OK — wire these certIds into CrewAI agents' metadata / tools")


def run_crew() -> None:
    from crewai import Agent, Crew, Process, Task

    from jiaozi_tools import as_crewai_tool

    researcher_id = bootstrap_agent("CrewResearcherLlm")
    writer_id = bootstrap_agent("CrewWriterLlm")
    verify_tool = as_crewai_tool()

    researcher = Agent(
        role="Certified Researcher",
        goal="Research only after verifying collaborator GDID",
        backstory=f"My cert is {researcher_id['certId']}. I never trust unverified agents.",
        tools=[verify_tool],
        verbose=True,
    )
    writer = Agent(
        role="Certified Writer",
        goal="Write brief after verifying researcher identity",
        backstory=f"My cert is {writer_id['certId']}.",
        tools=[verify_tool],
        verbose=True,
    )
    t1 = Task(
        description=(
            f"Verify peer certificate {writer_id['certId']} using jiaozi_verify_peer, "
            "then list 3 bullet insights about agent identity."
        ),
        expected_output="Verification result plus 3 bullets",
        agent=researcher,
    )
    t2 = Task(
        description=(
            f"Verify researcher certificate {researcher_id['certId']}, "
            "then turn their bullets into a short paragraph."
        ),
        expected_output="A short paragraph",
        agent=writer,
        context=[t1],
    )
    crew = Crew(agents=[researcher, writer], tasks=[t1, t2], process=Process.sequential)
    print(crew.kickoff())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--crew", action="store_true", help="Run full CrewAI with LLM")
    args = p.parse_args()
    try:
        if args.crew:
            run_crew()
        else:
            run_offline()
    except Exception as exc:  # noqa: BLE001
        print(exc, file=sys.stderr)
        if args.crew:
            print("Hint: pip install -r requirements.txt && export OPENAI_API_KEY=...", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
