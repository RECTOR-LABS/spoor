import hashlib
import json
from pathlib import Path

from spoor_sift.audit import AuditLog, GENESIS


def _clock():
    return "2026-06-09T12:00:00+00:00"


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_appends_form_a_hash_chain(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl", clock=_clock)

    r0 = log.append(
        tool="vol_pslist",
        args={"image": "/cases/c1/mem.raw"},
        exit_code=0,
        stdout='{"rows": []}',
    )
    r1 = log.append(
        tool="vol_netscan",
        args={"image": "/cases/c1/mem.raw"},
        exit_code=0,
        stdout='{"conns": 3}',
    )

    # genesis + monotonic sequence
    assert r0.seq == 0
    assert r0.prev_hash == GENESIS
    assert r1.seq == 1

    # output integrity: each record fingerprints its own tool stdout
    assert r0.stdout_sha256 == _sha256('{"rows": []}')
    assert r1.stdout_sha256 == _sha256('{"conns": 3}')

    # chain linkage: each record points back at the previous record's hash
    assert r1.prev_hash == r0.hash
    assert len(r0.hash) == 64 and len(r1.hash) == 64
    assert r0.hash != r1.hash


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _log_with_three(tmp_path: Path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", clock=_clock)
    log.append(tool="a", args={}, exit_code=0, stdout="x")
    log.append(tool="b", args={"k": 1}, exit_code=0, stdout="y")
    log.append(tool="c", args={}, exit_code=0, stdout="z")
    return log


def test_verify_ok_for_intact_log(tmp_path: Path):
    log = _log_with_three(tmp_path)
    result = log.verify()
    assert result.ok is True
    assert result.broken_seq is None


def test_verify_detects_tampered_field(tmp_path: Path):
    log = _log_with_three(tmp_path)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["exit_code"] = 99  # mutate content without recomputing the chain hash
    lines[1] = json.dumps(rec)
    _rewrite(path, lines)

    result = log.verify()
    assert result.ok is False
    assert result.broken_seq == 1


def test_verify_detects_deleted_record(tmp_path: Path):
    log = _log_with_three(tmp_path)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # excise the middle record
    _rewrite(path, lines)

    result = log.verify()
    assert result.ok is False
