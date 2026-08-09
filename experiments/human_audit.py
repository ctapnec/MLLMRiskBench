"""Judge-vs-human calibration from a stratified human-audit sample (thesis V.1.5/V.2.5).

Inter-judge Cohen's kappa (kappa.py) measures internal consistency; it cannot tell
whether the automated stages are *correct*. This script closes the external-validity
loop: given human labels for a stratified slice of attempts, it computes, per judge
stage, agreement against the human ground truth as chance-corrected Cohen's kappa AND
as accuracy/precision/recall/F1 (violation = positive class), the informedness-style
measures of II.5.2.

    python experiments/human_audit.py --results runs/kappa --labels human_labels.csv

``--labels`` is a CSV with columns ``attempt_id,label`` (label in
safe|violation|refusal|over_refusal), typically the returned stratified sample.
Reads the judge verdicts from the ``*.trails.jsonl`` written by the run.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ura import metrics  # noqa: E402


def load_trails(results: Path) -> dict[str, dict[str, str]]:
    """judge-name -> {attempt_id: label} from every *.trails.jsonl file."""
    per_judge: dict[str, dict[str, str]] = defaultdict(dict)
    for f in sorted(results.glob("*.trails.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            per_judge[r["judge"]][r["attempt_id"]] = r["label"]
    return per_judge


def load_labels(path: Path) -> dict[str, str]:
    """attempt_id -> human label from a CSV with columns attempt_id,label."""
    labels: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            aid = row.get("attempt_id") or row.get("id")
            lbl = row.get("label") or row.get("human_label")
            if aid and lbl:
                labels[aid.strip()] = lbl.strip()
    return labels


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Judge-vs-human calibration (kappa + P/R/F1).")
    ap.add_argument("--results", type=Path, required=True, help="dir of *.trails.jsonl")
    ap.add_argument("--labels", type=Path, required=True, help="CSV attempt_id,label")
    args = ap.parse_args(argv)

    per_judge = load_trails(args.results)
    human = load_labels(args.labels)
    if not per_judge:
        print(f"no *.trails.jsonl in {args.results}; run the matrix first.")
        return 1
    if not human:
        print(f"no labels parsed from {args.labels}; expected columns attempt_id,label.")
        return 1

    print(f"judge-vs-human calibration over {len(human)} human-labelled attempts:")
    out: dict[str, dict] = {}
    for judge in sorted(per_judge):
        shared = sorted(set(per_judge[judge]) & set(human))
        if not shared:
            continue
        pred = [per_judge[judge][i] for i in shared]
        gold = [human[i] for i in shared]
        kappa = metrics.cohen_kappa(pred, gold)
        scores = metrics.judge_scores(pred, gold)
        out[judge] = {"kappa_vs_human": kappa, "n": len(shared), **scores}
        print(f"  {judge:>12}  kappa={kappa:+.3f}  acc={scores['accuracy']:.2f}  "
              f"P={scores['precision']:.2f}  R={scores['recall']:.2f}  F1={scores['f1']:.2f}  (n={len(shared)})")

    (args.results / "human_audit.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"\nwrote human_audit.json to {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
