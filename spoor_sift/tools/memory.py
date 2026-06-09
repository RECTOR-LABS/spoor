"""Memory-forensics tools (Volatility 3), returning structured JSON.

Volatility is invoked with its JSON renderer (``-r json``, before the plugin name)
so output is parsed objects, not a wall of stdout. Each tool normalizes Volatility's
verbose column names into a stable schema the agent reasons over.
"""

from __future__ import annotations

from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import resolve_in_root
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run, parse_json_output


def _normalize_process(row: dict) -> dict:
    return {
        "pid": row.get("PID"),
        "ppid": row.get("PPID"),
        "name": row.get("ImageFileName"),
        "threads": row.get("Threads"),
        "handles": row.get("Handles"),
        "session_id": row.get("SessionId"),
        "wow64": row.get("Wow64"),
        "offset": row.get("Offset(V)"),
        "create_time": row.get("CreateTime"),
        "exit_time": row.get("ExitTime"),
    }


def vol_pslist(
    memory_image: str,
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> dict:
    """List processes from a Windows memory image (Volatility 3 ``windows.pslist``).

    The image path is jailed to the evidence root; Volatility runs read-only with
    the JSON renderer; output is parsed into a normalized process schema. The
    returned ``tool_call_id`` is the audit record's hash — the citation a finding
    uses to prove which execution produced it.
    """
    image = resolve_in_root(evidence_root, memory_image)
    args = ["-f", str(image), "-r", "json", "windows.pslist"]
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="vol",
        args=args,
        tool="vol_pslist",
        audit_args={"memory_image": str(image)},
    )
    rows = parse_json_output(result.stdout, tool="vol_pslist", tool_call_id=record.tool_call_id)
    processes = [_normalize_process(row) for row in rows]
    return {
        "tool": "vol_pslist",
        "tool_call_id": record.tool_call_id,
        "process_count": len(processes),
        "processes": processes,
    }
