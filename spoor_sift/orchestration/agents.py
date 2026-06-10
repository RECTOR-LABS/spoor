"""Specialist agents. The triage agent reasons over the audited memory tools.

The prompt encodes the senior-analyst triage sequence *and* explicitly licenses
self-correction: on a tool failure, reason about the cause and retry rather than
give up. That behavior is emergent (the model decides), surfaced by LangGraph
returning a failed tool call to the model as an error message.
"""

from __future__ import annotations

from pathlib import Path

from langgraph.prebuilt import create_react_agent

from spoor_sift.audit import AuditLog
from spoor_sift.model import build_chat_model
from spoor_sift.orchestration.tools import build_tools

TRIAGE_PROMPT = (
    "You are a senior DFIR memory-forensics triage analyst working a Windows memory image.\n"
    "Work the standard triage sequence: list processes (vol_pslist), check the process tree for "
    "anomalous parent/child links (vol_pstree), look for C2 in network connections (vol_netscan), "
    "find injected code (vol_malfind), and inspect launch arguments (vol_cmdline).\n"
    "IMPORTANT: if a tool call FAILS, do not give up — reason about the likely cause, adjust your "
    "approach or arguments, and retry. Persist until you have usable output or have exhausted "
    "sensible options.\n"
    "In your final answer, clearly separate CONFIRMED findings (each backed by specific tool output) "
    "from INFERENCES, and name the suspicious processes / PIDs you found."
)


def build_triage_agent(*, runner, audit: AuditLog, evidence_root: Path | str, model=None):
    """Build the triage specialist: a react agent over the audited memory tools."""
    model = model or build_chat_model("specialist")
    tools = build_tools(runner=runner, audit=audit, evidence_root=evidence_root)
    return create_react_agent(model, tools, prompt=TRIAGE_PROMPT)
