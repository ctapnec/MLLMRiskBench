"""Compose validated response views with an explicit model scope, without calls."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from experiments import retained_response_judge as judge
from experiments.retained_response_judge_execute import _read_regular, _write_new


SCHEMA = "ura-retained-response-view/1"
SCOPE = "judge_candidates_only_preserve_source_provenance"


def _native(root: Path):
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
        or root.resolve(strict=True) != root or (root / "retained-view.json").exists()):
        raise ValueError("response view sources must be canonical native views, without nesting")
    view = judge._read_native_view(root)
    cells, metadata, judgments, audit = view
    identity = judge._sha({
        "manifests": {cell["run_id"]: cell["manifest"] for cell in cells},
        "metadata": metadata, "judgments": judgments, "audit": audit,
    })
    return view, identity


def _merge(views, models):
    if (not isinstance(models, list) or not models or models != sorted(set(models))
        or any(not isinstance(model, str) or not model for model in models)):
        raise ValueError("response view needs sorted unique exact model identities")
    cells, metadata, judgments = [], {}, {}
    seen_runs = set()
    for part_cells, part_metadata, part_judgments, _audit in views:
        runs = {cell["run_id"] for cell in part_cells}
        if (len(runs) != len(part_cells) or seen_runs & runs
            or part_metadata.keys() != part_judgments.keys()
            or metadata.keys() & part_metadata.keys()):
            raise ValueError("response source views have duplicate runs or lossy/overlapping joins")
        seen_runs.update(runs)
        cells.extend(part_cells)
        metadata.update(part_metadata)
        judgments.update(part_judgments)
    present = {cell["model"] for cell in cells}
    if not set(models) <= present:
        raise ValueError("response model scope names an absent model")
    allowed_runs = {cell["run_id"] for cell in cells if cell["model"] in models}
    selected = {key: row for key, row in metadata.items() if row["run_id"] in allowed_runs}
    if any(row["run_id"] not in seen_runs for row in metadata.values()):
        raise ValueError("response metadata has no validated source run")
    excluded_source = sum(
        row["raw"].get("common_metrics_eligible") is False
        and row["raw"].get("policy_evaluable_turn") is True
        for cell in cells if cell["run_id"] in allowed_runs for row in cell["judgments"]
    )
    # Keep excluded models' cells as provenance for a replay whose original
    # input came from them, but never offer their responses as judge candidates.
    return cells, selected, {key: judgments[key] for key in selected}, {
        "policy_evaluable_samples": len(selected),
        "common_ineligible_evaluable_rows_excluded": excluded_source,
        "model_scope": models, "excluded_model_joined_rows": len(metadata) - len(selected),
    }


def compose(*, sources: Sequence[Path], models: Sequence[str], out_root: Path) -> dict:
    root = Path(out_root)
    if (not root.is_absolute() or root.exists() or root.is_symlink()
        or root.parent.resolve(strict=True) / root.name != root):
        raise ValueError("composed response view needs a fresh canonical directory")
    if not sources or len(set(map(str, sources))) != len(sources):
        raise ValueError("response source views must be nonempty and unique")
    views, bindings = [], []
    for source in sources:
        view, identity = _native(Path(source))
        views.append(view)
        bindings.append({"root": str(source), "view_sha256": identity})
    scope = sorted(set(models))
    _merge(views, scope)
    value = {"schema": SCHEMA, "scope": SCOPE, "sources": bindings, "models": scope}
    root.mkdir(mode=0o700)
    _write_new(root / "retained-view.json", value)
    return value


def read_view(root: Path):
    value, _descriptor = _read_regular(root / "retained-view.json", label="composed response view",
                                     max_bytes=1024 * 1024)
    if (set(value) != {"schema", "scope", "sources", "models"}
        or value["schema"] != SCHEMA or value["scope"] != SCOPE
        or not isinstance(value["sources"], list) or not value["sources"]):
        raise ValueError("composed response view contract differs")
    views, seen = [], set()
    for source in value["sources"]:
        if not isinstance(source, dict) or set(source) != {"root", "view_sha256"}:
            raise ValueError("composed response source fields differ")
        if source["root"] in seen:
            raise ValueError("composed response sources overlap")
        seen.add(source["root"])
        view, identity = _native(Path(source["root"]))
        if identity != source["view_sha256"]:
            raise ValueError("validated source view content changed")
        views.append(view)
    return _merge(views, value["models"])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-view", type=Path, action="append", required=True)
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--out-root", type=Path, required=True)
    args = parser.parse_args(argv)
    compose(sources=args.source_view, models=args.model, out_root=args.out_root)
    print(args.out_root / "retained-view.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
