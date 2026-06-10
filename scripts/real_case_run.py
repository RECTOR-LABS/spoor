"""REAL-evidence run: the multi-agent graph against the actual Case 001 memory image.

No canned data anywhere — SubprocessRunner drives the real Volatility 3 binary
against the real 2.1GB DC01 capture (citadeldc01.mem), and the result is scored
against the verified answer-key subset for a REAL accuracy number. Evidence
integrity is proven by SHA-256 before and after the run (read-only operation).

Prereqs:  uv sync --extra forensics   (Volatility 3)
          evidence/case001/citadeldc01.mem  (see datasets/README.md — verify MD5)
Run:      uv run python scripts/real_case_run.py
Env:      SPOOR_OPENROUTER_API_KEY (./.env), optional SPOOR_MODEL / SPOOR_LEAD_MODEL.

Artifacts: runs/<stamp>-case001-real/ (audit log, enforced report, findings,
transcript, tokens, meta) + accuracy_report.md at the repo root (submission #6).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from langchain_core.messages import HumanMessage

from spoor_sift.accuracy import score
from spoor_sift.audit import AuditLog
from spoor_sift.model import build_chat_model, load_env
from spoor_sift.orchestration.supervisor import build_case_graph
from spoor_sift.runner import SubprocessRunner

EVIDENCE_ROOT = REPO / "evidence" / "case001"
IMAGE = EVIDENCE_ROOT / "citadeldc01.mem"
GROUND_TRUTH = REPO / "datasets" / "case001_ground_truth_dc01_memory.json"

_FILE_TOKEN = re.compile(r"^[\w.\-\\/:$ ]+$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _summarize_tokens(messages) -> dict:
    seen: set[str] = set()
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    by_model: dict[str, dict] = {}
    for msg in messages:
        usage = getattr(msg, "usage_metadata", None)
        if not usage or not msg.id or msg.id in seen:
            continue
        seen.add(msg.id)
        model = (getattr(msg, "response_metadata", None) or {}).get("model_name", "unknown")
        bucket = by_model.setdefault(model, {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "llm_calls": 0})
        bucket["llm_calls"] += 1
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            totals[key] += usage.get(key, 0)
            bucket[key] += usage.get(key, 0)
    return {"totals": totals, "by_model": by_model}


def _transcript(messages) -> str:
    lines = ["# Real Case 001 run — transcript\n"]
    for msg in messages:
        who = msg.type + (f" [{msg.name}]" if getattr(msg, "name", None) else "")
        lines.append(f"## {who}")
        for call in getattr(msg, "tool_calls", None) or []:
            lines.append(f"- tool_call → `{call['name']}` args={json.dumps(call['args'])[:200]}")
        content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        if content:
            lines.append("```\n" + content[:2000] + ("\n… [truncated]" if len(content) > 2000 else "") + "\n```")
        lines.append("")
    return "\n".join(lines)


def _findings_from_iocs(report: dict, audit: AuditLog) -> tuple[list[dict], list[dict]]:
    """Deterministically map report IOCs to gradeable findings.

    Scoring contract: an IOC is a CONFIRMED finding iff it cites a tool_call_id
    that exists in the verified audit chain — the same standard the reporter is
    held to. ip → ip (port stripped); path/process → file when the value is a
    clean file token. Everything else is reported as unscored, not dropped
    silently.
    """
    chain_ok = audit.verify().ok
    known = {r.tool_call_id for r in audit.records()} if chain_ok else set()

    findings: list[dict] = []
    unscored: list[dict] = []
    for ioc in report.get("iocs", []):
        cited = ioc.get("tool_call_id")
        status = "confirmed" if cited in known else "inferred"
        value = str(ioc.get("value", "")).strip()
        kind = ioc.get("type")
        if kind == "ip":
            ip = value.split(":")[0].strip()
            findings.append({"category": "ip", "value": ip, "status": status, "tool_call_id": cited})
        elif kind in ("path", "process") and _FILE_TOKEN.match(value):
            token = value.split()[0] if kind == "process" else value
            findings.append({"category": "file", "value": token, "status": status, "tool_call_id": cited})
        else:
            unscored.append(ioc)
    return findings, unscored


def _accuracy_markdown(*, result, findings, unscored, ground_truth: dict,
                       pre_hash: str, post_hash: str, run_dir: Path, meta: dict) -> str:
    integrity = "INTACT — byte-identical before and after the run (read-only operation proven)" \
        if pre_hash == post_hash else "VIOLATED — hashes differ (investigate immediately)"
    tp = "\n".join(f"- `{f['category']}` **{f['value']}**" for f in result.true_positives) or "- (none)"
    fp = "\n".join(f"- `{f['category']}` **{f['value']}**" for f in result.false_positives) or "- (none)"
    fn = "\n".join(f"- `{f['category']}` **{f['value']}**" for f in result.false_negatives) or "- (none)"
    uns = "\n".join(f"- `{i.get('type')}` {i.get('value')}" for i in unscored) or "- (none)"
    return f"""# Spoor — Accuracy Report (real evidence)

**Case:** DFIR Madness Case 001 "The Stolen Szechuan Sauce" — DC01 memory image
**Run:** `{run_dir.name}` · {meta["finished_utc"]}
**Models:** lead `{meta["lead_model"]}` · specialists `{meta["specialist_model"]}`
**Scored against:** `{GROUND_TRUTH.relative_to(REPO)}` (memory-visible subset of the
verified v1.0 answer key — see datasets/README.md for the scoping rationale)

## Evidence integrity
| | SHA-256 |
|---|---|
| `citadeldc01.mem` before run | `{pre_hash}` |
| `citadeldc01.mem` after run | `{post_hash}` |

**Verdict: {integrity}.** Guardrails enforce this architecturally (read-only
path-jail, no-shell allow-listed exec); the hashes prove it empirically.

## Scores (confirmed findings vs. answer key)
| Metric | Value |
|---|---|
| Precision | **{result.precision:.3f}** |
| Recall | **{result.recall:.3f}** |
| F1 | **{result.f1:.3f}** |
| Hallucination rate | **{result.hallucination_rate:.3f}** |
| Confirmed / total findings | {result.total_confirmed} / {result.total_findings} |
| Ground-truth items | {result.total_ground_truth} |

A finding counts as *confirmed* only when it cites a `tool_call_id` present in
the verified hash-chained audit log — the same contract the reporter agent is
held to in code. The hallucination rate is the share of confirmed findings with
no such citation.

### True positives
{tp}

### False positives
{fp}

### False negatives (missed ground truth)
{fn}

### Reported but unscored IOC types (registry keys, URLs, hashes, narrative entries)
{uns}

## Reproduce
```bash
uv sync --extra forensics
# fetch + verify evidence per datasets/README.md, then:
uv run python scripts/real_case_run.py
uv run spoor accuracy-report {run_dir.relative_to(REPO)}/findings.json {GROUND_TRUTH.relative_to(REPO)}
uv run spoor verify-audit {run_dir.relative_to(REPO)}/audit.jsonl
```
"""


def main() -> int:
    load_env()
    if not IMAGE.exists():
        print(f"FAILED: {IMAGE} not found — fetch + verify per datasets/README.md", file=sys.stderr)
        return 1

    stamp = datetime.now(timezone.utc)
    run_dir = REPO / "runs" / f"{stamp:%Y-%m-%d-%H%M%S}-case001-real"
    workspace_root = run_dir / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    print("hashing evidence (pre-run)…")
    pre_hash = _sha256_file(IMAGE)
    print(f"  {pre_hash}")

    audit = AuditLog(run_dir / "audit.jsonl")
    runner = SubprocessRunner(timeout=900.0)
    specialist = build_chat_model("specialist")
    lead = build_chat_model("lead")
    graph = build_case_graph(
        runner=runner,
        audit=audit,
        evidence_root=EVIDENCE_ROOT,
        workspace_root=workspace_root,
        lead_model=lead,
        triage_model=specialist,
        timeline_model=specialist,
        ioc_model=specialist,
        reporter_model=specialist,
    )

    thread_id = f"case001-real-{stamp:%Y%m%dT%H%M%SZ}"
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 100}
    brief = (
        "REAL EVIDENCE CASE. Investigate host DC01 (10.42.85.10), a Windows Server 2012 R2 "
        "domain controller suspected of compromise. Available evidence: the memory image "
        "'citadeldc01.mem' (2.1GB RAM capture). This is a MEMORY-ONLY case — there is no disk "
        "image, registry hive file, or timeline source in evidence, so do not attempt disk or "
        "timeline phases. Determine whether the host is compromised, the intrusion vector if "
        "visible, what malicious code is running, command-and-control endpoints, and indicators "
        "of compromise — strictly from what the memory shows. Be precise about process names "
        "exactly as the evidence reports them. Work the case to completion and deliver the "
        "final report through the reporter."
    )

    print(f"thread: {thread_id}")
    print(f"lead model: {getattr(lead, 'model_name', getattr(lead, 'model', '?'))}")
    print(f"specialist model: {getattr(specialist, 'model_name', getattr(specialist, 'model', '?'))}\n")

    def _stream(inputs) -> dict | None:
        state = None
        for mode, chunk in graph.stream(inputs, config, stream_mode=["updates", "values"]):
            if mode == "updates":
                for node, update in chunk.items():
                    messages = (update or {}).get("messages", [])
                    last = messages[-1] if messages else None
                    calls = [c["name"] for c in (getattr(last, "tool_calls", None) or [])]
                    if calls:
                        print(f"▶ {node}  → {', '.join(calls)}", flush=True)
                    else:
                        head = (getattr(last, "content", "") or "")[:110]
                        print(f"▶ {node}  {head!r}", flush=True)
            else:
                state = chunk
        return state

    final_state = _stream({"messages": [HumanMessage(brief)], "evidence": {"memory_image": "citadeldc01.mem"}})

    gate_engagements = 0
    while (not final_state or not final_state.get("report")) and gate_engagements < 2:
        gate_engagements += 1
        print(f"\n⛔ completeness gate: no enforced report — re-engaging supervisor (attempt {gate_engagements})", flush=True)
        final_state = _stream(
            {"messages": [HumanMessage(
                "PROTOCOL VIOLATION: the case ended without the reporter's enforced report. "
                "Transfer to the reporter NOW so it can compile and submit the report via "
                "submit_report. The case is not complete until then."
            )]}
        )

    print("\nhashing evidence (post-run)…")
    post_hash = _sha256_file(IMAGE)
    print(f"  {post_hash}")

    report = (final_state or {}).get("report")
    chain = audit.verify()
    messages = (final_state or {}).get("messages", [])
    tokens = _summarize_tokens(messages)
    meta = {
        "thread_id": thread_id,
        "started_utc": stamp.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "lead_model": getattr(lead, "model_name", getattr(lead, "model", None)),
        "specialist_model": getattr(specialist, "model_name", getattr(specialist, "model", None)),
        "message_count": len(messages),
        "completeness_gate_engagements": gate_engagements,
        "audit_records": len(audit.records()),
        "audit_chain_ok": chain.ok,
        "evidence_sha256_pre": pre_hash,
        "evidence_sha256_post": post_hash,
        "evidence_integrity_ok": pre_hash == post_hash,
        "scenario": "REAL evidence — DC01 memory image, real Volatility 3 via SubprocessRunner",
    }

    (run_dir / "transcript.md").write_text(_transcript(messages))
    (run_dir / "token_usage.json").write_text(json.dumps(tokens, indent=2))
    (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2))
    if not report:
        print(f"\nFAILED: no enforced report after {gate_engagements} gate engagement(s); "
              f"see {run_dir.relative_to(REPO)}/transcript.md", file=sys.stderr)
        return 1
    (run_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))

    findings, unscored = _findings_from_iocs(report, audit)
    (run_dir / "findings.json").write_text(json.dumps({"findings": findings}, indent=2))
    ground_truth = json.loads(GROUND_TRUTH.read_text())
    result = score(findings, ground_truth)
    accuracy_md = _accuracy_markdown(
        result=result, findings=findings, unscored=unscored, ground_truth=ground_truth,
        pre_hash=pre_hash, post_hash=post_hash, run_dir=run_dir, meta=meta,
    )
    (run_dir / "accuracy_report.md").write_text(accuracy_md)
    (REPO / "accuracy_report.md").write_text(accuracy_md)

    enforcement = report["enforcement"]
    print("\n── REAL RUN RESULT ──")
    print(f"enforcement: {enforcement}")
    print(f"audit chain: {'OK' if chain.ok else 'BROKEN'} ({len(audit.records())} records)")
    print(f"evidence integrity: {'INTACT' if pre_hash == post_hash else 'VIOLATED'}")
    print(f"accuracy: precision={result.precision:.3f} recall={result.recall:.3f} "
          f"f1={result.f1:.3f} hallucination_rate={result.hallucination_rate:.3f}")
    print(f"scored findings: {len(findings)} (unscored IOC entries: {len(unscored)})")
    print(f"tokens: {tokens['totals']}")
    print(f"\nartifacts: {run_dir.relative_to(REPO)}/  +  accuracy_report.md (repo root)")
    return 0 if (chain.ok and pre_hash == post_hash) else 1


if __name__ == "__main__":
    raise SystemExit(main())
