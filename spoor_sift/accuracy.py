"""Honest accuracy scoring: Spoor's findings vs. a dataset answer key.

Scores only **confirmed** findings for precision/recall/F1 — *inferred* findings
are reported but never penalized, which rewards the confirmed-vs-inferred contract.
``hallucination_rate`` is the share of confirmed findings with no ``tool_call_id``
citation: a confirmed claim with nothing backing it. This directly answers the
hackathon author's stated #1 concern (hallucination) and criterion #2 (IR Accuracy).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AccuracyReport:
    true_positives: list
    false_positives: list
    false_negatives: list
    precision: float
    recall: float
    f1: float
    hallucination_rate: float
    total_findings: int
    total_confirmed: int
    total_ground_truth: int


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _ground_truth_items(ground_truth: dict) -> list[dict]:
    """Flatten the answer key into unique items, each with the normalized keys it matches."""
    items: list[dict] = []
    iocs = ground_truth.get("iocs", {})
    for ip in iocs.get("ips", []):
        value = ip["value"]
        items.append({"category": "ip", "value": value, "keys": {("ip", value.strip().lower())}})
    for f in iocs.get("files", []):
        value = f.get("path") or f.get("name")
        items.append(
            {
                "category": "file",
                "value": value,
                "keys": {("file", value.strip().lower()), ("file", _basename(value))},
            }
        )
    return items


def _finding_matches(finding: dict, key_to_item: dict) -> int | None:
    category = finding.get("category")
    value = str(finding.get("value", "")).strip().lower()
    idx = key_to_item.get((category, value))
    if idx is None and category == "file":
        idx = key_to_item.get((category, _basename(str(finding.get("value", "")))))
    return idx


def score(findings: list[dict], ground_truth: dict) -> AccuracyReport:
    gt_items = _ground_truth_items(ground_truth)
    key_to_item = {key: i for i, item in enumerate(gt_items) for key in item["keys"]}

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    matched: set[int] = set()
    true_positives: list = []
    false_positives: list = []
    for finding in confirmed:
        idx = _finding_matches(finding, key_to_item)
        if idx is None:
            false_positives.append(finding)
        else:
            true_positives.append(finding)
            matched.add(idx)

    false_negatives = [
        {"category": item["category"], "value": item["value"]}
        for i, item in enumerate(gt_items)
        if i not in matched
    ]

    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    uncited = [f for f in confirmed if not f.get("tool_call_id")]
    hallucination_rate = len(uncited) / len(confirmed) if confirmed else 0.0

    return AccuracyReport(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        hallucination_rate=hallucination_rate,
        total_findings=len(findings),
        total_confirmed=len(confirmed),
        total_ground_truth=len(gt_items),
    )
