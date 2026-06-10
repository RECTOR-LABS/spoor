"""IOC tools: hash_file (in-process, no binary) and yara_scan."""

import hashlib
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import PathJailError
from spoor_sift.runner import ToolResult
from spoor_sift.tools.indicators import hash_file, yara_scan


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


@pytest.fixture
def roots(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir(), workspace.mkdir()
    (evidence / "coreupdate.exe").write_bytes(b"MZ\x90\x00fake-malware-body")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return evidence, workspace, audit


# --- hash_file ---------------------------------------------------------------

def test_hash_file_computes_real_digests_in_process(roots):
    evidence, _, audit = roots
    body = (evidence / "coreupdate.exe").read_bytes()

    result = hash_file("coreupdate.exe", audit=audit, evidence_root=evidence)

    assert result["md5"] == hashlib.md5(body).hexdigest()
    assert result["sha256"] == hashlib.sha256(body).hexdigest()
    assert result["size"] == len(body)
    assert len(result["tool_call_id"]) == 64
    # audited with the digests sealed into the record's stdout hash
    record = audit.records()[-1]
    assert record.tool == "hash_file"
    assert record.exit_code == 0
    assert audit.verify().ok


def test_hash_file_respects_the_path_jail(roots):
    evidence, _, audit = roots
    with pytest.raises(PathJailError):
        hash_file("../workspace/escape.bin", audit=audit, evidence_root=evidence)
    assert audit.records() == []  # nothing executed, nothing recorded


# --- yara_scan ---------------------------------------------------------------

def test_yara_scan_parses_matches_and_audits(roots):
    evidence, workspace, audit = roots
    rules = workspace / "evil.yar"
    rules.write_text('rule SuspiciousPE { strings: $mz = "MZ" condition: $mz }')
    runner = FakeRunner(
        ToolResult(0, f"SuspiciousPE {evidence / 'coreupdate.exe'}\n", "")
    )

    result = yara_scan(
        "evil.yar",
        "coreupdate.exe",
        runner=runner,
        audit=audit,
        evidence_root=evidence,
        workspace_root=workspace,
    )

    assert result["match_count"] == 1
    assert result["matches"][0]["rule"] == "SuspiciousPE"
    assert result["matches"][0]["path"].endswith("coreupdate.exe")
    binary, args = runner.calls[0]
    assert binary == "yara"
    assert args[0] == "-r"
    assert args[-1].endswith("coreupdate.exe")
    assert audit.records()[-1].tool == "yara_scan"
    assert audit.verify().ok


def test_yara_scan_no_matches_is_a_clean_empty_result(roots):
    evidence, workspace, audit = roots
    (workspace / "evil.yar").write_text("rule X { condition: false }")
    runner = FakeRunner(ToolResult(0, "", ""))

    result = yara_scan(
        "evil.yar", "coreupdate.exe",
        runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
    )

    assert result["match_count"] == 0
    assert result["matches"] == []


def test_yara_rules_must_live_in_the_workspace(roots):
    evidence, workspace, audit = roots
    (evidence / "evil.yar").write_text("rule X { condition: true }")
    with pytest.raises(PathJailError):
        yara_scan(
            "../evidence/evil.yar", "coreupdate.exe",
            runner=FakeRunner(ToolResult(0, "", "")),
            audit=audit, evidence_root=evidence, workspace_root=workspace,
        )
