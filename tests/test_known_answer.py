"""
test_known_answer.py
----------------------
The methodology used across the whole Phantom Security toolkit: generate
precisely-labeled synthetic examples, run them through the real pipeline,
and assert exact recall / zero false positives programmatically. No manual
eyeballing of a handful of examples.

Run directly for a human-readable report:
    python3 -m tests.test_known_answer

Run under pytest for CI-style pass/fail:
    pytest tests/test_known_answer.py -v
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.pipeline import ScanPipeline
from tests.test_data_generator import generate_dataset, level_at_least, LEVEL_ORDER

# Hard requirement: not one safe example may score above LOW (24).
# ("Zero false positives" -- a false SAFE-classified-as-scam breaks user trust
# in the product faster than a missed scam does.)
MAX_SAFE_LEVEL = "LOW"

# Target recall on the scam set. Reported honestly either way; not silently
# lowered to make a run "pass" -- see report footer if this isn't met.
TARGET_RECALL = 0.90


def run_suite(verbose: bool = True) -> dict:
    pipeline = ScanPipeline()
    dataset = generate_dataset()

    results = []
    for ex in dataset:
        scan = pipeline.scan_text(ex.text)
        level = scan.risk["risk_level"]
        score = scan.risk["total_score"]

        if ex.label == "safe":
            passed = level_at_least(MAX_SAFE_LEVEL, level)  # actual must be <= MAX_SAFE_LEVEL
            passed = LEVEL_ORDER.index(level) <= LEVEL_ORDER.index(MAX_SAFE_LEVEL)
        else:
            passed = level_at_least(level, ex.min_expected_level)

        results.append({
            "text_preview": ex.text[:60] + ("..." if len(ex.text) > 60 else ""),
            "label": ex.label,
            "category": ex.category,
            "lang": ex.lang,
            "expected_min_level": ex.min_expected_level,
            "actual_level": level,
            "actual_score": score,
            "passed": passed,
        })

    safe_results = [r for r in results if r["label"] == "safe"]
    scam_results = [r for r in results if r["label"] == "scam"]

    false_positives = [r for r in safe_results if not r["passed"]]
    missed_scams = [r for r in scam_results if not r["passed"]]

    recall = (len(scam_results) - len(missed_scams)) / len(scam_results) if scam_results else 1.0
    false_positive_rate = len(false_positives) / len(safe_results) if safe_results else 0.0

    summary = {
        "total_examples": len(results),
        "scam_examples": len(scam_results),
        "safe_examples": len(safe_results),
        "recall": round(recall, 3),
        "target_recall": TARGET_RECALL,
        "recall_target_met": recall >= TARGET_RECALL,
        "false_positive_count": len(false_positives),
        "false_positive_rate": round(false_positive_rate, 3),
        "zero_false_positives": len(false_positives) == 0,
        "missed_scams": missed_scams,
        "false_positives": false_positives,
        "all_results": results,
    }

    if verbose:
        _print_report(summary)

    return summary


def _print_report(summary: dict) -> None:
    print("=" * 78)
    print("PHANTOMGUARD AI -- KNOWN-ANSWER TEST REPORT")
    print("=" * 78)
    print(f"Dataset:  {summary['total_examples']} examples "
          f"({summary['scam_examples']} scam, {summary['safe_examples']} safe)")
    print()
    print(f"Recall on scam set:      {summary['recall']*100:.1f}%  "
          f"(target {summary['target_recall']*100:.0f}%) "
          f"{'PASS' if summary['recall_target_met'] else 'BELOW TARGET'}")
    print(f"False positive rate:     {summary['false_positive_rate']*100:.1f}%  "
          f"(target 0.0%) "
          f"{'PASS' if summary['zero_false_positives'] else 'FAIL'}")
    print()

    if summary["false_positives"]:
        print("-- FALSE POSITIVES (safe examples scored too high) --")
        for r in summary["false_positives"]:
            print(f"  [{r['actual_score']:3}/{r['actual_level']:10}] {r['text_preview']}")
        print()

    if summary["missed_scams"]:
        print(f"-- MISSED / UNDER-SCORED SCAMS ({len(summary['missed_scams'])}) --")
        for r in summary["missed_scams"]:
            print(f"  [{r['actual_score']:3}/{r['actual_level']:10} "
                  f"expected>={r['expected_min_level']:10}] ({r['category']}, {r['lang']}) {r['text_preview']}")
        print()

    print("-- PER-CATEGORY BREAKDOWN --")
    cats = sorted({r["category"] for r in summary["all_results"] if r["label"] == "scam"})
    for cat in cats:
        cat_results = [r for r in summary["all_results"] if r["category"] == cat]
        cat_pass = sum(1 for r in cat_results if r["passed"])
        print(f"  {cat:28} {cat_pass}/{len(cat_results)} passed")
    print("=" * 78)


# --------------------------------------------------------------- pytest ---

def test_zero_false_positives():
    summary = run_suite(verbose=False)
    assert summary["zero_false_positives"], (
        f"{summary['false_positive_count']} safe example(s) scored above {MAX_SAFE_LEVEL}: "
        f"{[r['text_preview'] for r in summary['false_positives']]}"
    )


def test_recall_target():
    summary = run_suite(verbose=False)
    assert summary["recall"] >= TARGET_RECALL, (
        f"Recall {summary['recall']*100:.1f}% below target {TARGET_RECALL*100:.0f}%. "
        f"Missed: {[r['text_preview'] for r in summary['missed_scams']]}"
    )


if __name__ == "__main__":
    run_suite(verbose=True)
