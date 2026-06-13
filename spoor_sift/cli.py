"""The ``spoor`` command line — surfaces Spoor's trust differentiators as runnable demos.

    spoor verify-audit <audit.jsonl>        prove the audit chain is intact / show a break
    spoor demo-guardrails                   attempt 4 bypasses live; each is rejected in code
    spoor accuracy-report <findings> <gt>   score findings vs an answer key (P/R/F1 + hallucinations)
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from spoor_sift.accuracy import score
from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import (
    BinaryNotAllowedError,
    PathJailError,
    resolve_binary,
    resolve_in_root,
)


def cmd_verify_audit(path: str) -> int:
    log = AuditLog(path)
    count = sum(1 for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip())
    result = log.verify()
    if result.ok:
        print(f"audit chain intact: {count} record(s) verified, hash chain unbroken")
        return 0
    print(f"AUDIT CHAIN BROKEN at seq {result.broken_seq}: {result.reason}")
    return 1


def cmd_demo_guardrails() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "evidence"
        root.mkdir()
        (root / "mem.raw").write_bytes(b"evidence")
        outside = Path(tmp) / "secret.txt"
        outside.write_text("top secret")
        (root / "escape").symlink_to(outside)

        attempts = [
            ("path traversal '../../etc/passwd'", lambda: resolve_in_root(root, "../../etc/passwd"), PathJailError),
            ("absolute path escape '/etc/passwd'", lambda: resolve_in_root(root, "/etc/passwd"), PathJailError),
            ("symlink escape 'escape' -> /tmp", lambda: resolve_in_root(root, "escape"), PathJailError),
            ("non-allow-listed binary 'rm'", lambda: resolve_binary("rm", which=lambda n: "/bin/rm"), BinaryNotAllowedError),
        ]
        all_blocked = True
        print("Guardrail bypass attempts (each must be rejected in code):")
        for label, attempt, expected in attempts:
            try:
                attempt()
                print(f"  [LEAKED!] {label} was NOT blocked")
                all_blocked = False
            except expected:
                print(f"  [BLOCKED] {label}")

        try:
            resolve_in_root(root, "mem.raw")
            print("  [OK]      legitimate in-jail path 'mem.raw' allowed")
        except PathJailError:
            print("  [FAIL]    legitimate in-jail path was wrongly blocked")
            all_blocked = False

        return 0 if all_blocked else 1


def cmd_accuracy_report(findings_path: str, ground_truth_path: str) -> int:
    raw = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    findings = raw["findings"] if isinstance(raw, dict) and "findings" in raw else raw
    ground_truth = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    r = score(findings, ground_truth)
    print("Spoor accuracy report")
    print(f"  precision           : {r.precision:.3f}")
    print(f"  recall              : {r.recall:.3f}")
    print(f"  f1                  : {r.f1:.3f}")
    print(f"  hallucination_rate  : {r.hallucination_rate:.3f}")
    print(f"  confirmed findings  : {r.total_confirmed}/{r.total_findings}")
    print(f"  ground-truth items  : {r.total_ground_truth}")
    print(f"  true / false pos    : {len(r.true_positives)} / {len(r.false_positives)}")
    print(f"  false negatives     : {len(r.false_negatives)}")
    return 0


def render_report(report: dict) -> str:
    """Render a run's report.json for a terminal demo: summary, confirmed
    findings (each audit-cited), and indicators. Inferred claims are omitted
    from the confirmed section — the same confirmed-vs-inferred contract score()
    enforces."""
    lines: list[str] = []
    summary = str(report.get("executive_summary", "")).strip()
    if summary:
        lines += ["EXECUTIVE SUMMARY", summary, ""]
    findings = report.get("findings", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    lines.append(f"CONFIRMED FINDINGS — {len(confirmed)}/{len(findings)} (each cites a verified tool_call_id)")
    for f in confirmed[:6]:
        claim = " ".join(str(f.get("claim", "")).split())
        lines.append(f"  [+] {claim[:140]}")
    iocs = report.get("iocs", [])
    if iocs:
        lines += ["", f"INDICATORS — {len(iocs)}"]
        for i in iocs[:8]:
            lines.append(f"  - [{i.get('type')}] {' '.join(str(i.get('value', '')).split())[:90]}")
    return "\n".join(lines)


def cmd_show_report(run_dir: str) -> int:
    path = Path(run_dir)
    report_path = path if path.suffix == ".json" else path / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    print(render_report(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spoor", description="Spoor DFIR agent — trust toolbelt")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("verify-audit", help="verify a hash-chained audit log")
    p_audit.add_argument("audit_path")

    sub.add_parser("demo-guardrails", help="attempt guardrail bypasses; show each rejected")

    p_acc = sub.add_parser("accuracy-report", help="score findings vs a ground-truth answer key")
    p_acc.add_argument("findings_path")
    p_acc.add_argument("ground_truth_path")

    p_show = sub.add_parser("show-report", help="render a run's report.json for a demo")
    p_show.add_argument("run_dir", help="a runs/<stamp>/ dir or a report.json path")

    args = parser.parse_args(argv)
    if args.command == "verify-audit":
        return cmd_verify_audit(args.audit_path)
    if args.command == "demo-guardrails":
        return cmd_demo_guardrails()
    if args.command == "accuracy-report":
        return cmd_accuracy_report(args.findings_path, args.ground_truth_path)
    if args.command == "show-report":
        return cmd_show_report(args.run_dir)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
