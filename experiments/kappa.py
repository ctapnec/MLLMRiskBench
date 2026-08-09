"""Inter-judge agreement (Cohen's κ) from exported judge trails (thesis V.2.5).

The judge cascade records every stage's verdict; ``Runner.save_trails`` writes
them as ``*.trails.jsonl``. This script computes Cohen's κ between each pair of
judge stages over the attempts they both scored - the measurement-validity number
that II.5.2 argues the whole field's results depend on. Low κ in a category is a
signal to prefer the graded StrongREJECT score over binary ASR there.

    python experiments/kappa.py --results runs/main
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ura import metrics  # noqa: E402


def load_trails(results: Path) -> dict[str, dict[str, str]]:
    """judge-name -> {attempt_id: label} from every *.trails.jsonl file."""
    per_judge: dict[str, dict[str, str]] = defaultdict(dict)
    for f in sorted(results.glob("*.trails.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            per_judge[r["judge"]][r["attempt_id"]] = r["label"]
    return per_judge


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Inter-judge Cohen's kappa.")
    ap.add_argument("--results", type=Path, required=True)
    args = ap.parse_args(argv)

    per_judge = load_trails(args.results)
    judges = sorted(per_judge)
    if len(judges) < 2:
        print(f"need >=2 judge stages with trails in {args.results}; found {judges}. "
              f"Re-run the matrix with a multi-stage cascade (e.g. --judges rules,guardrail,llm).")
        return 1

    print("Cohen's kappa between judge stages (over jointly-scored attempts):")
    results = {}
    for a, b in combinations(judges, 2):
        shared = sorted(set(per_judge[a]) & set(per_judge[b]))
        if not shared:
            continue
        la = [per_judge[a][i] for i in shared]
        lb = [per_judge[b][i] for i in shared]
        k = metrics.cohen_kappa(la, lb)
        results[f"{a}|{b}"] = {"kappa": k, "n": len(shared)}
        agree = "strong" if k >= 0.8 else "moderate" if k >= 0.6 else "weak"
        print(f"  {a:>10} vs {b:<10}  kappa = {k:+.3f}  (n={len(shared)}, {agree})")

    (args.results / "judge_kappa.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"\nwrote judge_kappa.json to {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
