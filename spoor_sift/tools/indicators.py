"""Indicator tools: cryptographic hashing and YARA signature scanning.

``hash_file`` runs in-process (hashlib) — no subprocess, no output parsing, the
most trustworthy primitive in the box — and still appends an audit record, so
every digest is traceable like any other tool call. ``yara_scan`` runs the
allow-listed ``yara`` binary; rules live in the writable workspace, targets in
the read-only evidence tree — each jailed to its own root.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import PathJailError, resolve_in_root
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run


def _resolve_readable(
    path: str | Path,
    *,
    evidence_root: Path | str,
    workspace_root: Path | str | None,
) -> Path:
    """Resolve a READ-ONLY target in the evidence root, else the workspace.

    The IOC chain extracts suspect files into the workspace (icat) and then
    fingerprints/scans them — so read-only targets may live in either jail.
    """
    try:
        return resolve_in_root(evidence_root, path)
    except PathJailError:
        if workspace_root is None:
            raise
    try:
        return resolve_in_root(workspace_root, path)
    except PathJailError:
        raise PathJailError(
            f"path escapes both jails: {str(path)!r} is in neither the evidence root "
            f"({Path(evidence_root).resolve()}) nor the workspace ({Path(workspace_root).resolve()})"
        ) from None


def hash_file(
    path: str,
    *,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str | None = None,
) -> dict:
    """MD5 + SHA-256 of an evidence file or extracted artifact (in-process, audited)."""
    target = _resolve_readable(path, evidence_root=evidence_root, workspace_root=workspace_root)
    body = target.read_bytes()
    digests = {
        "path": str(target),
        "size": len(body),
        "md5": hashlib.md5(body).hexdigest(),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    record = audit.append(
        tool="hash_file",
        args={"path": str(target)},
        exit_code=0,
        stdout=json.dumps(digests, sort_keys=True),
    )
    return {"tool": "hash_file", "tool_call_id": record.tool_call_id, **digests}


def yara_scan(
    rules_path: str,
    target: str,
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str,
) -> dict:
    """Scan an evidence file/dir — or an extracted artifact — with workspace rules."""
    rules = resolve_in_root(workspace_root, rules_path)
    scan_target = _resolve_readable(target, evidence_root=evidence_root, workspace_root=workspace_root)
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="yara",
        args=["-r", str(rules), str(scan_target)],
        tool="yara_scan",
        audit_args={"rules": str(rules), "target": str(scan_target)},
    )
    matches = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rule, _, matched_path = line.partition(" ")
        matches.append({"rule": rule, "path": matched_path})
    return {
        "tool": "yara_scan",
        "tool_call_id": record.tool_call_id,
        "match_count": len(matches),
        "matches": matches,
    }
