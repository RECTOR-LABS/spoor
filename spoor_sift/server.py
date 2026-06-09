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

from mcp.server.fastmcp import FastMCP

from spoor_sift.audit import AuditLog
from spoor_sift.runner import SubprocessRunner, ToolRunner
from spoor_sift.tools import memory


def build_server(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> FastMCP:
    """Build the MCP server with its dependencies injected (testable + embeddable)."""
    evidence_root = Path(evidence_root)
    mcp = FastMCP("spoor-sift")

    @mcp.tool()
    async def vol_pslist(memory_image: str) -> dict:
        """List processes from a Windows memory image (Volatility 3 windows.pslist).

        Args:
            memory_image: Path to the memory capture, within the read-only
                evidence root. Paths outside the root are rejected.
        """
        return await asyncio.to_thread(
            memory.vol_pslist,
            memory_image,
            runner=runner,
            audit=audit,
            evidence_root=evidence_root,
        )

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
