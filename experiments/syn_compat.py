"""Generate, oracle-check, and linearly evaluate the compatibility corpus.

SYN-001/SYN-002 driver. ``--generate`` writes the synthetic comparison corpus
and its sidecar split metadata (template/family/seed live only there);
``--check`` runs the deterministic oracle over a corpus and fails unless every
critical incompatibility reason is exercised; ``--evaluate`` trains and scores
the transparent linear baselines against the rules on held-out templates.

Every output declares its claim scope: rule fidelity on synthetic
distributions only. No output is campaign evidence, enters any measured tree,
or supports a real-world validity, ranking, or safety claim (SYN-003 was
withdrawn by recorded operator decision; ledger Section 11.20).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.compat_bundles import (  # noqa: E402
    CLAIM_SCOPE,
    evaluate_comparison,
    validate_case,
)
from ura.compat_linear import evaluate_linear_baselines  # noqa: E402
from ura.compat_synth import (  # noqa: E402
    coverage_report,
    generate_corpus,
    hand_authored_adversarial,
    templates,
)


def _write_new(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(text)


def _load_corpus(path: Path) -> list:
    cases = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            cases.append(validate_case(json.loads(line)))
        except ValueError as exc:
            raise ValueError(f"{path.name}:{line_number}: {exc}") from exc
    if not cases:
        raise ValueError("compatibility corpus contains no cases")
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Synthetic compatibility corpus: generate, oracle-check, and "
            "evaluate transparent linear baselines (rule-fidelity only)"
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--evaluate", action="store_true")
    parser.add_argument("--cases", type=Path, help="corpus JSONL path")
    parser.add_argument("--metadata", type=Path, help="split metadata path")
    parser.add_argument("--out", type=Path, help="report/corpus output path")
    parser.add_argument("--seed", type=int, default=20260813)
    parser.add_argument(
        "--perturbations-per-template", type=int, default=12,
    )
    args = parser.parse_args(argv)
    try:
        if args.generate:
            if args.cases is None or args.metadata is None:
                parser.error("--generate requires --cases and --metadata")
            cases, metadata = generate_corpus(
                seed=args.seed,
                perturbations_per_template=args.perturbations_per_template,
            )
            _write_new(args.cases, "".join(
                json.dumps(
                    case.model_dump(mode="json", by_alias=True),
                    sort_keys=True,
                ) + "\n"
                for case in cases
            ))
            _write_new(args.metadata, json.dumps({
                "claim_scope": CLAIM_SCOPE,
                "seed": args.seed,
                "perturbations_per_template": args.perturbations_per_template,
                "n_templates": len(templates()),
                "cases": metadata,
                "note": (
                    "template/family/seed metadata is split information only "
                    "and must never enter model inputs"
                ),
            }, indent=2, sort_keys=True) + "\n")
            print(json.dumps({
                "status": "generated",
                "claim_scope": CLAIM_SCOPE,
                "n_templates": len(templates()),
                "n_cases": len(cases),
                "cases": str(args.cases.resolve()),
                "metadata": str(args.metadata.resolve()),
            }, sort_keys=True))
            return 0
        if args.check:
            if args.cases is None or args.out is None:
                parser.error("--check requires --cases and --out")
            cases = _load_corpus(args.cases)
            report = coverage_report(cases)
            report["schema_version"] = "ura-syn-compat-coverage/1"
            report["claim_scope"] = CLAIM_SCOPE
            adversarial = hand_authored_adversarial()
            caught = sum(
                evaluate_comparison(case)["label"] == intended
                for case, intended in adversarial
            )
            report["hand_authored_adversarial"] = {
                "n_cases": len(adversarial),
                "rules_agreement": caught / len(adversarial),
            }
            _write_new(args.out, json.dumps(report, indent=2, sort_keys=True) + "\n")
            if not report["all_critical_reasons_covered"]:
                raise ValueError(
                    "corpus does not exercise every critical incompatibility "
                    f"reason: missing {report['missing_critical_reasons']}"
                )
            if report["hand_authored_adversarial"]["rules_agreement"] != 1.0:
                raise ValueError(
                    "deterministic rules failed a hand-authored adversarial case"
                )
            print(json.dumps({
                "status": "checked",
                "n_cases": report["n_cases"],
                "all_critical_reasons_covered": True,
                "out": str(args.out.resolve()),
            }, sort_keys=True))
            return 0
        if args.cases is None or args.metadata is None or args.out is None:
            parser.error("--evaluate requires --cases, --metadata and --out")
        cases = _load_corpus(args.cases)
        sidecar = json.loads(args.metadata.read_text(encoding="utf-8"))
        metadata = sidecar.get("cases")
        if not isinstance(metadata, dict):
            raise ValueError("split metadata lacks its cases mapping")
        missing = [case.case_id for case in cases if case.case_id not in metadata]
        if missing:
            raise ValueError(
                f"split metadata missing {len(missing)} case entries"
            )
        report = evaluate_linear_baselines(
            cases, metadata, hand_authored_adversarial(), seed=args.seed,
        )
        _write_new(args.out, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({
            "status": "evaluated",
            "n_train": report["split"]["n_train"],
            "n_test": report["split"]["n_test"],
            "models": sorted(report["models"]),
            "out": str(args.out.resolve()),
        }, sort_keys=True))
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"syn-compat failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
