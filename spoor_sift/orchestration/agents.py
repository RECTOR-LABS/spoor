"""Specialist agents. Each owns one phase of the senior-analyst playbook.

The prompts encode the SANS-published triage sequencing *and* explicitly license
self-correction: on a tool failure, reason about the cause and retry rather than
give up. That behavior is emergent (the model decides), surfaced by LangGraph
returning a failed tool call to the model as an error message.

Every agent carries a ``name`` (the supervisor routes by it) and shares the
``CaseState`` schema, so state written by one agent is visible to the next.
"""

from __future__ import annotations

from pathlib import Path

from langgraph.prebuilt import create_react_agent

from spoor_sift.audit import AuditLog
from spoor_sift.model import build_chat_model
from spoor_sift.orchestration.report import build_submit_report_tool
from spoor_sift.orchestration.state import CaseState
from spoor_sift.orchestration.tools import build_tools

TRIAGE_PROMPT = (
    "You are a senior DFIR memory-forensics triage analyst working a Windows memory image.\n"
    "Work the standard triage sequence: list processes (vol_pslist), check the process tree for "
    "anomalous parent/child links (vol_pstree), look for C2 in network connections (vol_netscan), "
    "find injected code (vol_malfind), and inspect launch arguments (vol_cmdline).\n"
    "IMPORTANT: if a tool call FAILS, do not give up — reason about the likely cause, adjust your "
    "approach or arguments, and retry. Persist until you have usable output or have exhausted "
    "sensible options.\n"
    "In your final answer, clearly separate CONFIRMED findings (each backed by specific tool output, "
    "citing its tool_call_id) from INFERENCES, and name the suspicious processes / PIDs you found."
)

IOC_PROMPT = (
    "You are a DFIR indicator-extraction and correlation analyst working a Windows memory image.\n"
    "Mine the artifacts for indicators of compromise and cross-reference them into a causal chain: "
    "map network endpoints to owning processes (vol_netscan + vol_pslist), tie injected code regions "
    "to PIDs (vol_malfind), and recover staging paths or download URLs from launch arguments "
    "(vol_cmdline). An indicator that appears in two independent artifacts is signal, not noise.\n"
    "IMPORTANT: if a tool call FAILS, reason about the cause, adjust, and retry before moving on.\n"
    "In your final answer, list each IOC with its type (ip/domain/url/hash/path/process/registry), "
    "the tool_call_id of the output it came from, and which artifacts corroborate it."
)

REPORTER_PROMPT = (
    "You are the case reporter for a DFIR investigation. Your job is to compile the final "
    "incident report from the investigation conversation above — you do not run evidence tools.\n"
    "Rules of evidence:\n"
    "1. A finding is 'confirmed' ONLY if you can cite the tool_call_id (64-hex) shown in the tool "
    "output that backs it. Everything else — however plausible — is 'inferred'.\n"
    "2. Never invent or guess a tool_call_id. A fabricated citation is worse than an inference.\n"
    "3. You MUST call submit_report exactly once with the full report. The tool verifies every "
    "citation against the tamper-evident audit log and DOWNGRADES anything unverifiable.\n"
    "4. Your final answer must present the ENFORCED report the tool returns — including any "
    "downgrades it applied — never your pre-enforcement draft."
)

# The IOC agent correlates across artifacts; pstree stays with triage.
_IOC_TOOL_NAMES = frozenset({"vol_pslist", "vol_netscan", "vol_malfind", "vol_cmdline"})


def build_triage_agent(*, runner, audit: AuditLog, evidence_root: Path | str, model=None):
    """Build the triage specialist: a react agent over the audited memory tools."""
    model = model or build_chat_model("specialist")
    tools = build_tools(runner=runner, audit=audit, evidence_root=evidence_root)
    return create_react_agent(
        model, tools, prompt=TRIAGE_PROMPT, name="triage", state_schema=CaseState
    )


def build_ioc_agent(*, runner, audit: AuditLog, evidence_root: Path | str, model=None):
    """Build the IOC/correlation specialist over the artifact-mining subset."""
    model = model or build_chat_model("specialist")
    tools = [
        t
        for t in build_tools(runner=runner, audit=audit, evidence_root=evidence_root)
        if t.name in _IOC_TOOL_NAMES
    ]
    return create_react_agent(
        model, tools, prompt=IOC_PROMPT, name="ioc_correlation", state_schema=CaseState
    )


def build_reporter_agent(*, audit: AuditLog, model=None):
    """Build the reporter: no evidence tools, one exit — the enforcing submit_report."""
    model = model or build_chat_model("specialist")
    return create_react_agent(
        model,
        [build_submit_report_tool(audit)],
        prompt=REPORTER_PROMPT,
        name="reporter",
        state_schema=CaseState,
    )
