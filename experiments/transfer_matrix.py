"""Attack-transferability matrix from a runs directory (thesis V.2.4, RQ4).

For every ordered model pair (A, B), computes the attack-success rate on B
restricted to the attempts that succeeded on A - i.e. how well vulnerabilities
transfer. Attempts are model-independent (the same attacker+seed on the same
datapoint yields the same attempt id across model cells), so judgments key on
``attempt_id`` across cells.

    python experiments/transfer_matrix.py --results runs/main

Reads the raw judgment JSONL (``*.jsonl``, skipping ``*.results.jsonl`` and
``*.trails.jsonl``); writes ``transfer_matrix.json`` and, if matplotlib is
present, a sequential-blue heatmap.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ura import metrics  # noqa: E402


def load(results: Path) -> dict[str, dict[str, str]]:
    """model -> {attempt_id: label} from the raw judgment JSONL files."""
    per_model: dict[str, dict[str, str]] = defaultdict(dict)
    for f in sorted(results.glob("*.jsonl")):
        if f.name.endswith((".results.jsonl", ".trails.jsonl")):
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            model = (r.get("raw") or {}).get("model") or (r.get("raw") or {}).get("target")
            if not model:
                continue
            per_model[model][r["attempt_id"]] = r["label"]
    return per_model


def build_matrix(per_model: dict[str, dict[str, str]]) -> dict:
    models = sorted(per_model)
    matrix: dict[str, dict[str, float]] = {}
    for a in models:
        src_success = {aid for aid, lbl in per_model[a].items() if lbl == "violation"}
        row: dict[str, float] = {}
        for b in models:
            if a == b:
                row[b] = float("nan")
                continue
            # metrics.transferability needs Judgment objects; emulate with labels.
            ids = [aid for aid in src_success if aid in per_model[b]]
            if not ids:
                row[b] = 0.0
                continue
            row[b] = sum(1 for aid in ids if per_model[b][aid] == "violation") / len(ids)
        matrix[a] = row
    return {"models": models, "matrix": matrix}


def _heatmap(result: dict, out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return
    models = result["models"]
    m = result["matrix"]
    grid = [[m[a][b] if b in m[a] else 0.0 for b in models] for a in models]
    fig, ax = plt.subplots(figsize=(1.2 + 0.7 * len(models), 1.0 + 0.7 * len(models)))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(models))); ax.set_xticklabels(models, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(models))); ax.set_yticklabels(models, fontsize=8)
    ax.set_xlabel("target model B"); ax.set_ylabel("source model A")
    ax.set_title("Attack transferability  A → B  (ASR on B | success on A)")
    for i in range(len(models)):
        for j in range(len(models)):
            v = grid[i][j]
            if v == v:  # not NaN
                ax.text(j, i, f"{v:.0%}", ha="center", va="center",
                        color="white" if v > 0.5 else "#0b0b0b", fontsize=8)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out / "transfer_matrix.png", dpi=200, bbox_inches="tight")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Attack transferability matrix.")
    ap.add_argument("--results", type=Path, required=True)
    args = ap.parse_args(argv)

    per_model = load(args.results)
    if len(per_model) < 2:
        print(f"need >=2 models in {args.results}; found {sorted(per_model)}")
        return 1
    result = build_matrix(per_model)
    (args.results / "transfer_matrix.json").write_text(
        json.dumps(result, indent=1), encoding="utf-8")
    _heatmap(result, args.results)

    print("transfer A->B (rows=source A, cols=target B):")
    models = result["models"]
    print("            " + "  ".join(f"{b[:10]:>10}" for b in models))
    for a in models:
        cells = "  ".join(
            ("     -    " if b == a else f"{result['matrix'][a][b]:>9.0%} ")
            for b in models)
        print(f"{a[:10]:>10}  {cells}")
    print(f"\nwrote transfer_matrix.json (+ .png if matplotlib) to {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
