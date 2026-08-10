"""Inter-judge agreement from exported shadow-scoring trails.

Agreement is reported on a common binary construct (unsafe compliance versus
not unsafe compliance), restricted to items on which both stages made an actual
decision. Low-confidence or explicitly unparsed outputs are abstentions and are
reported in coverage rather than imputed as ``safe``. This avoids pretending
that a binary guardrail and a four-label refusal judge share the same ontology.
Exact-label agreement is included only as a diagnostic. Degenerate strata are
emitted as ``null``; agreement on one constant label contains no estimable
chance-corrected kappa.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from itertools import combinations
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))
from experiments.human_audit import (  # noqa: E402
    _validated_artifacts,
    load_trails as _strict_load_trails,
)
from ura import metrics  # noqa: E402


def load_trail_facets(
    results: Path,
    *,
    attacker: str = "replay",
    corpus: str | None = None,
) -> dict[str, tuple[dict[str, dict[str, str]], dict[str, dict], dict]]:
    """Load strict, completion-backed trail cohorts faceted by corpus."""
    _, cells = _validated_artifacts(results)
    grouped: dict[str, list[dict]] = {}
    for cell in cells:
        run_config = (cell["manifest"].get("config") or {}).get("run")
        if not isinstance(run_config, dict):
            raise ValueError(f"manifest {cell['manifest_path']} lacks config.run")
        cell_attacker = run_config.get("attacker")
        cell_corpus = run_config.get("corpus")
        if not isinstance(cell_attacker, str) or not isinstance(cell_corpus, str):
            raise ValueError(f"manifest {cell['manifest_path']} lacks attacker/corpus facets")
        if cell_attacker != attacker or (corpus is not None and cell_corpus != corpus):
            continue
        grouped.setdefault(cell_corpus, []).append(cell)
    if not grouped:
        raise ValueError(
            f"no completed trail cohorts for attacker={attacker!r}, corpus={corpus!r}"
        )

    facets = {}
    for corpus_name, cohort in sorted(grouped.items()):
        signatures = {cell["cohort_signature"] for cell in cohort}
        if len(signatures) != 1:
            raise ValueError(
                f"incompatible completed configurations within kappa facet "
                f"attacker={attacker!r}, corpus={corpus_name!r}"
            )
        files = [Path(cell["artifacts"]["trails"]) for cell in cohort]
        per_judge, metadata = _strict_load_trails(results, files=files)
        facets[corpus_name] = (
            per_judge,
            metadata,
            {
                "attacker": attacker,
                "corpus": corpus_name,
                "cohort_signature": next(iter(signatures)),
                "run_ids": sorted(cell["run_id"] for cell in cohort),
                "trail_source_files": sorted(str(path) for path in files),
                "completed_cells": len(cohort),
                "completion_integrity_modes": sorted({
                    cell["integrity_mode"] for cell in cohort
                }),
                "grid_accounting_modes": sorted({
                    cell["grid_audit"]["mode"] for cell in cohort
                }),
                "source_identity_validated": all(
                    cell["source_identity_validated"] is True for cell in cohort
                ),
                "dry_run_cells": sum(
                    bool((((cell["manifest"].get("config") or {}).get("run") or {}).get(
                        "dry_run"
                    )))
                    for cell in cohort
                ),
                "unexplained_exclusions": 0,
            },
        )
    return facets


def load_trails(
    results: Path,
    *,
    attacker: str = "replay",
    corpus: str | None = None,
) -> tuple[dict[str, dict[str, str]], dict[str, dict]]:
    """Compatibility wrapper requiring one explicit/available corpus facet."""
    facets = load_trail_facets(results, attacker=attacker, corpus=corpus)
    if len(facets) != 1:
        raise ValueError(f"multiple corpus facets found: {sorted(facets)!r}; select --corpus")
    per_judge, metadata, _ = next(iter(facets.values()))
    return per_judge, metadata


def _unsafe(label: str) -> str:
    return "unsafe_compliance" if label == "violation" else "not_unsafe_compliance"


def _kappa(labels_a: list[str], labels_b: list[str]) -> float | None:
    value = metrics.cohen_kappa(labels_a, labels_b)
    if value is None:
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _fmt(value: float | None) -> str:
    return "undefined" if value is None else f"{value:+.3f}"


def _pair_stats(a: str, b: str, ids: list[str], per_judge: dict[str, dict[str, str]]) -> dict:
    labels_a = [per_judge[a][sample] for sample in ids]
    labels_b = [per_judge[b][sample] for sample in ids]
    return {
        "unsafe_kappa": _kappa([_unsafe(label) for label in labels_a], [_unsafe(label) for label in labels_b]),
        "exact_label_kappa_diagnostic": _kappa(labels_a, labels_b),
        "raw_agreement": sum(x == y for x, y in zip(labels_a, labels_b)) / len(ids),
        "n": len(ids),
    }


def _analyse_facet(
    per_judge: dict[str, dict[str, str]], metadata: dict[str, dict], audit: dict,
) -> dict:
    judges = sorted(per_judge)
    if len(judges) < 2:
        raise ValueError(f"need >=2 shadow-scoring judge stages; found {judges}")

    results: dict[str, dict] = {}
    for a, b in combinations(judges, 2):
        shared = sorted(set(per_judge[a]) & set(per_judge[b]))
        population = set(metadata)
        union = set(per_judge[a]) | set(per_judge[b])
        coverage_audit = {
            "attempted_common_population": len(population),
            "judge_a_decisions": len(per_judge[a]),
            "judge_b_decisions": len(per_judge[b]),
            "judge_a_abstentions": len(population - set(per_judge[a])),
            "judge_b_abstentions": len(population - set(per_judge[b])),
            "shared_decisions": len(shared),
            "one_sided_decisions": len(union - set(shared)),
            "joint_abstentions": len(population - union),
            "decision_policy": (
                "cascade_confident=true and parsed is not false for both stages"
            ),
            "unexplained_exclusions": 0,
        }
        if not shared:
            results[f"{a}|{b}"] = {
                "construct": "unsafe_compliance_vs_not_unsafe_compliance",
                "pooled": None,
                "by_category": {},
                "not_evaluable_reason": "no_joint_stage_decisions",
                "coverage_audit": coverage_audit,
            }
            continue
        pooled = _pair_stats(a, b, shared, per_judge)
        print(f"  {a:>12} vs {b:<12}  kappa={_fmt(pooled['unsafe_kappa'])}  (n={len(shared)})")

        by_category: dict[str, dict] = {}
        for category in sorted({metadata.get(sample, {}).get("risk_category", "unknown") for sample in shared}):
            ids = [sample for sample in shared if metadata.get(sample, {}).get("risk_category", "unknown") == category]
            stats = _pair_stats(a, b, ids, per_judge)
            by_category[category] = stats
            print(f"        - {category:<26} kappa={_fmt(stats['unsafe_kappa'])}  (n={len(ids)})")

        results[f"{a}|{b}"] = {
            "construct": "unsafe_compliance_vs_not_unsafe_compliance",
            "pooled": pooled,
            "by_category": by_category,
            "coverage_audit": coverage_audit,
        }
    return {
        "pairs": results,
        "artifact_audit": audit,
        "publishable_real_run": (
            audit["completion_integrity_modes"] == ["v2_sha256_bytes_records"]
            and audit["grid_accounting_modes"] == ["grid_accounted"]
            and audit["source_identity_validated"] is True
            and audit["dry_run_cells"] == 0
            and audit["unexplained_exclusions"] == 0
        ),
        "unexplained_exclusions": 0,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Inter-judge agreement (pooled and stratified).")
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--attacker", default="replay")
    parser.add_argument("--corpus", default=None)
    args = parser.parse_args(argv)

    try:
        facets = load_trail_facets(
            args.results, attacker=args.attacker, corpus=args.corpus
        )
    except ValueError as exc:
        print(f"kappa input validation failed: {exc}", file=sys.stderr)
        return 1
    print("Cohen's kappa on common unsafe-compliance labels (undefined = degenerate stratum):")
    analysed: dict[str, dict] = {}
    try:
        for corpus_name, (per_judge, metadata, audit) in facets.items():
            print(f"  corpus facet: {corpus_name}")
            analysed[corpus_name] = _analyse_facet(per_judge, metadata, audit)
    except ValueError as exc:
        print(f"kappa facet is not estimable: {exc}", file=sys.stderr)
        return 1

    destination = args.results / "judge_kappa.json"
    output: dict = (
        next(iter(analysed.values()))
        if len(analysed) == 1
        else {
            "schema_version": "2.1-faceted",
            "attacker": args.attacker,
            "facets": analysed,
            "unexplained_exclusions": 0,
        }
    )
    destination.write_text(
        json.dumps(output, indent=1, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(f"\nwrote {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
