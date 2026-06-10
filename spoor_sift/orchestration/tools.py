"""Adapt the tested SIFT core tools into LangChain tools for the agents.

The runner / audit / evidence-root are bound at build time, so the agent calls a
simple ``tool(memory_image=...)`` while every call still flows through the
path-jailed, audited core. A tool that fails raises — LangGraph surfaces that to
the model as an error message, which is what enables emergent self-correction.
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.tools import BaseTool, StructuredTool

from spoor_sift.audit import AuditLog
from spoor_sift.runner import ToolRunner
from spoor_sift.tools import memory
from spoor_sift.tools.base import ToolExecutionError, ToolOutputError

_MEMORY_TOOLS: dict[str, tuple] = {
    "vol_pslist": (memory.vol_pslist, "List processes from a Windows memory image (Volatility 3 windows.pslist)."),
    "vol_pstree": (memory.vol_pstree, "Process tree with parent/child links — spot anomalous parents (windows.pstree)."),
    "vol_netscan": (memory.vol_netscan, "Network connections/sockets from memory — find C2 (windows.netscan)."),
    "vol_malfind": (memory.vol_malfind, "Injected / hidden executable code regions (windows.malfind)."),
    "vol_cmdline": (memory.vol_cmdline, "Process command-line arguments — inspect launch args (windows.cmdline)."),
}


def _make_tool(name, core_fn, description, runner, audit, evidence_root) -> BaseTool:
    def _call(memory_image: str) -> dict:
        try:
            return core_fn(memory_image, runner=runner, audit=audit, evidence_root=evidence_root)
        except (ToolExecutionError, ToolOutputError) as exc:
            # Return the failure as data so the agent can reason and retry (the call
            # is already recorded in the audit log) — never crash the graph.
            return {
                "error": str(exc),
                "tool_call_id": getattr(exc, "tool_call_id", None),
                "hint": "The call failed and was recorded in the audit log. Reason about the "
                        "cause and retry — adjust arguments or try a related tool.",
            }

    return StructuredTool.from_function(func=_call, name=name, description=description)


def build_tools(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> list[BaseTool]:
    """Build the LangChain tool set, each bound to the injected dependencies."""
    return [
        _make_tool(name, core_fn, description, runner, audit, evidence_root)
        for name, (core_fn, description) in _MEMORY_TOOLS.items()
    ]
