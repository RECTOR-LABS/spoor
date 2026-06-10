"""The ``spoor-sift`` MCP server.

Exposes read-only SIFT forensic tools over stdio. Each MCP tool is a thin async
wrapper that delegates to the tested core in ``spoor_sift.tools``, wired to one
``SubprocessRunner`` + ``AuditLog`` + evidence root. The blocking subprocess work
is offloaded with ``asyncio.to_thread`` so the event loop stays responsive.

Run:    uv run spoor-sift          (or)   python -m spoor_sift.server
Config: EVIDENCE_ROOT (required), SPOOR_AUDIT_PATH, SPOOR_TOOL_TIMEOUT (env).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Callable

from mcp.server.fastmcp import FastMCP

from spoor_sift.audit import AuditLog
from spoor_sift.runner import SubprocessRunner, ToolRunner
from spoor_sift.tools import memory

# Memory-forensics tools: name -> (core function, MCP description for tool selection).
_MEMORY_TOOLS: dict[str, tuple[Callable, str]] = {
    "vol_pslist": (memory.vol_pslist, "List processes from a Windows memory image (Volatility 3 windows.pslist)."),
    "vol_pstree": (memory.vol_pstree, "Process tree with parent/child links — spot anomalous parents (windows.pstree)."),
    "vol_netscan": (memory.vol_netscan, "Network connections/sockets from memory — find C2 (windows.netscan)."),
    "vol_malfind": (memory.vol_malfind, "Injected / hidden executable code regions (windows.malfind)."),
    "vol_cmdline": (memory.vol_cmdline, "Process command-line arguments — inspect launch args (windows.cmdline)."),
}


def _register_memory_tool(
    mcp: FastMCP,
    name: str,
    core_fn: Callable,
    description: str,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path,
) -> None:
    # A dedicated function per tool keeps the closure binding correct in the loop.
    @mcp.tool(name=name, description=description)
    async def _tool(memory_image: str) -> dict:
        return await asyncio.to_thread(
            core_fn, memory_image, runner=runner, audit=audit, evidence_root=evidence_root
        )


def build_server(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> FastMCP:
    """Build the MCP server with its dependencies injected (testable + embeddable)."""
    evidence_root = Path(evidence_root)
    mcp = FastMCP("spoor-sift")
    for name, (core_fn, description) in _MEMORY_TOOLS.items():
        _register_memory_tool(mcp, name, core_fn, description, runner, audit, evidence_root)
    return mcp


def build_server_from_env() -> FastMCP:
    """Build the server from environment configuration (the production path)."""
    root = os.environ.get("EVIDENCE_ROOT")
    if not root:
        raise RuntimeError(
            "EVIDENCE_ROOT is not set; point it at the read-only evidence directory"
        )
    audit_path = os.environ.get("SPOOR_AUDIT_PATH", "runs/audit.jsonl")
    timeout = float(os.environ.get("SPOOR_TOOL_TIMEOUT", "300"))
    return build_server(
        runner=SubprocessRunner(timeout=timeout),
        audit=AuditLog(audit_path),
        evidence_root=Path(root),
    )


def main() -> None:
    build_server_from_env().run(transport="stdio")


if __name__ == "__main__":
    main()
