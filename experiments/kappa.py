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


def load_trails(results: Path) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Return ``(per_judge, category)`` from every ``*.trails.jsonl`` file.

    ``per_judge[judge][attempt_id] = label``; ``category[attempt_id] = risk_category``
    (from the trail row) so agreement can be reported per category, not just pooled.
    """
    per_judge: dict[str, dict[str, str]] = defaultdict(dict)
    category: dict[str, str] = {}
    for f in sorted(results.glob("*.trails.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            per_judge[r["judge"]][r["attempt_id"]] = r["label"]
            category[r["attempt_id"]] = r.get("risk_category", "unknown")
    return per_judge, category


def _kappa(labels_a: list[str], labels_b: list[str]) -> float:
    """Cohen's kappa, treating a degenerate single-label agreement as perfect."""
    return metrics.cohen_kappa(labels_a, labels_b)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Inter-judge Cohen's kappa (pooled + per category).")
    ap.add_argument("--results", type=Path, required=True)
    args = ap.parse_args(argv)

    per_judge, category = load_trails(args.results)
    judges = sorted(per_judge)
    if len(judges) < 2:
        print(f"need >=2 judge stages with trails in {args.results}; found {judges}. "
              f"Re-run the matrix with a multi-stage cascade (e.g. --judges rules,guardrail,llm).")
        return 1

    print("Cohen's kappa between judge stages (over jointly-scored attempts):")
    results: dict[str, dict] = {}
    for a, b in combinations(judges, 2):
        shared = sorted(set(per_judge[a]) & set(per_judge[b]))
        if not shared:
            continue
        la = [per_judge[a][i] for i in shared]
        lb = [per_judge[b][i] for i in shared]
        k = _kappa(la, lb)
        agree = "strong" if k >= 0.8 else "moderate" if k >= 0.6 else "weak"
        print(f"  {a:>12} vs {b:<12}  kappa = {k:+.3f}  (n={len(shared)}, {agree})")

        # Per-category kappa: the discount factor a reader applies before trusting a
        # given risk column (V.2.2/V.2.3/V.2.5).
        by_category: dict[str, dict] = {}
        cats = sorted({category.get(i, "unknown") for i in shared})
        for cat in cats:
            ids = [i for i in shared if category.get(i, "unknown") == cat]
            if not ids:
                continue
            kc = _kappa([per_judge[a][i] for i in ids], [per_judge[b][i] for i in ids])
            by_category[cat] = {"kappa": kc, "n": len(ids)}
            print(f"        - {cat:<26} kappa = {kc:+.3f}  (n={len(ids)})")

        results[f"{a}|{b}"] = {
            "pooled": {"kappa": k, "n": len(shared)},
            "by_category": by_category,
        }

    (args.results / "judge_kappa.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"\nwrote judge_kappa.json (pooled + per-category) to {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
