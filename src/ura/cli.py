"""URA-Bench command-line interface (thesis III.2.2, III.3).

A single ``ura`` entry point that wires the harness end-to-end:

* ``convert`` — normalise a source framework's corpus into unified DataPoints
  (JSONL) via :func:`ura.converters.get_converter`;
* ``run`` — replay/attack a corpus against a registered target, judge every
  response through a cheapest-first :class:`~ura.judges.base.JudgeCascade`, and
  persist judgments, aggregated results, and the re-derivable
  :class:`~ura.data_models.RunManifest`;
* ``report`` — render an aggregated result set into a markdown risk card.

Only pydantic + the standard library are needed to import this module. Heavy
judge/target backends (guardrail HF models, provider SDKs) are constructed
lazily and only when the corresponding stage/target is actually requested, so
the fully-offline path (``synth`` corpus + ``mock`` target + ``rules`` judge)
runs with no third-party dependencies.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .adapters.base import AttackBudget, BaseAttacker
from .adapters.engines import get_attacker
from .converters import get_converter, synth_corpus
from .data_models import DataPoint, EvalResult
from .judges.base import BaseJudge, JudgeCascade
from .report import risk_card
from .runner import Runner
from .targets.base import REGISTRY

# Import provider/mock targets for their registration side effects so that
# ``REGISTRY`` knows about "mock", the hosted models, etc.
from .targets import api as _api  # noqa: F401
from .targets import local as _local  # noqa: F401


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #

def _load_datapoints(path: Path) -> list[DataPoint]:
    """Load a JSONL corpus into validated :class:`DataPoint` records."""
    points: list[DataPoint] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            points.append(DataPoint.model_validate_json(line))
    return points


def _load_corpus(spec: str, n: int) -> list[DataPoint]:
    """Resolve ``--corpus``: the literal ``synth`` or a JSONL path."""
    if spec.strip().lower() == "synth":
        return synth_corpus(n)
    path = Path(spec)
    if not path.is_file():
        raise FileNotFoundError(f"corpus file not found: {path}")
    return _load_datapoints(path)


def _write_jsonl(records, path: Path) -> None:
    """Serialise an iterable of pydantic models as one JSON object per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(record.model_dump_json())
            fh.write("\n")


def _load_results(path: Path) -> list[EvalResult]:
    """Load aggregated :class:`EvalResult` records from a JSONL file."""
    results: list[EvalResult] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            results.append(EvalResult.model_validate_json(line))
    return results


# --------------------------------------------------------------------------- #
# Judge cascade construction
# --------------------------------------------------------------------------- #

def _build_cascade(names: list[str], judge_model: str) -> JudgeCascade:
    """Assemble a cheapest-first cascade from ``--judges`` stage names.

    ``rules`` is pure-python; ``guardrail`` and ``llm`` are imported lazily so
    that a run using only ``rules`` needs no heavy dependencies. The ``llm``
    stage judges with a registered target (``--judge-model``), defaulting to the
    offline ``mock`` target.
    """
    stages: list[BaseJudge] = []
    for raw in names:
        key = raw.strip().lower()
        if not key:
            continue
        if key == "rules":
            from .judges.rules import RuleJudge

            stages.append(RuleJudge())
        elif key == "guardrail":
            from .judges.guardrail import GuardrailJudge

            stages.append(GuardrailJudge())
        elif key == "llm":
            from .judges.llm import LLMJudge

            stages.append(LLMJudge(REGISTRY.create(judge_model)))
        else:
            raise ValueError(
                f"unknown judge {raw!r}; choose from rules, guardrail, llm"
            )
    if not stages:
        raise ValueError("at least one judge stage is required")
    return JudgeCascade(stages)


# --------------------------------------------------------------------------- #
# Subcommand implementations
# --------------------------------------------------------------------------- #

def _cmd_convert(args: argparse.Namespace) -> int:
    """``convert``: source corpus -> unified DataPoint JSONL."""
    converter = get_converter(args.source)
    points = converter.parse(Path(args.input))
    out = Path(args.output)
    _write_jsonl(points, out)
    print(f"converted {len(points)} datapoints from {args.source} -> {out}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    """``run``: attack a corpus, judge responses, persist the full trail."""
    corpus = _load_corpus(args.corpus, args.n)
    attacker: BaseAttacker = get_attacker(args.attacker)
    target = REGISTRY.create(args.target)
    cascade = _build_cascade(args.judges.split(","), args.judge_model)
    budget = AttackBudget(
        max_queries=args.max_queries, max_turns=args.max_turns, seed=args.seeds[0]
    )

    runner = Runner(
        attacker=attacker,
        target=target,
        judge_cascade=cascade,
        budget=budget,
        seeds=args.seeds,
    )
    judgments, manifest = runner.run(corpus)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    runner.save_results(judgments, out_dir / "judgments.jsonl")

    group_keys = [k for k in args.group_by.split(",") if k.strip()]
    results = runner.aggregate(judgments, group_keys)
    _write_jsonl(results, out_dir / "results.jsonl")

    (out_dir / "manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )

    print(
        f"ran {len(corpus)} datapoints -> {len(judgments)} judgments, "
        f"{len(results)} aggregated results in {out_dir}"
    )
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """``report``: aggregated results -> markdown risk card."""
    results = _load_results(Path(args.results))
    card = risk_card(results, args.model)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(card, encoding="utf-8")
        print(f"wrote risk card for {args.model} -> {out}")
    else:
        print(card)
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def _seed_list(spec: str) -> list[int]:
    """Parse a comma-separated ``--seeds`` list into ``list[int]``."""
    seeds = [int(s) for s in spec.split(",") if s.strip()]
    if not seeds:
        raise argparse.ArgumentTypeError("at least one seed is required")
    return seeds


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ``ura`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="ura",
        description="URA-Bench: unified (M)LLM risk-assessment harness.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # convert -------------------------------------------------------------- #
    p_convert = sub.add_parser(
        "convert", help="normalise a source corpus into unified DataPoints"
    )
    p_convert.add_argument("--source", required=True, help="converter name")
    p_convert.add_argument("--input", required=True, help="source corpus path")
    p_convert.add_argument("--output", required=True, help="output JSONL path")
    p_convert.set_defaults(func=_cmd_convert)

    # run ------------------------------------------------------------------ #
    p_run = sub.add_parser("run", help="attack a corpus and judge the responses")
    p_run.add_argument(
        "--corpus", required=True, help="corpus JSONL path, or 'synth'"
    )
    p_run.add_argument("--attacker", default="replay", help="attacker adapter name")
    p_run.add_argument("--target", required=True, help="target model id (see REGISTRY)")
    p_run.add_argument(
        "--judges",
        default="rules",
        help="comma-separated cascade stages: rules[,guardrail,llm]",
    )
    p_run.add_argument(
        "--judge-model",
        default="mock",
        help="registered target id used by the 'llm' judge stage",
    )
    p_run.add_argument("--out", required=True, help="output directory")
    p_run.add_argument(
        "--seeds",
        type=_seed_list,
        default=[0],
        help="comma-separated integer seeds (default: 0)",
    )
    p_run.add_argument(
        "--n", type=int, default=12, help="size of the synth corpus (default: 12)"
    )
    p_run.add_argument("--max-queries", type=int, default=1, dest="max_queries")
    p_run.add_argument("--max-turns", type=int, default=1, dest="max_turns")
    p_run.add_argument(
        "--group-by",
        default="risk_category",
        dest="group_by",
        help="comma-separated grouping keys for aggregation",
    )
    p_run.set_defaults(func=_cmd_run)

    # report --------------------------------------------------------------- #
    p_report = sub.add_parser("report", help="render aggregated results as a risk card")
    p_report.add_argument("--results", required=True, help="aggregated results JSONL")
    p_report.add_argument("--model", required=True, help="model id for the card header")
    p_report.add_argument("--out", default=None, help="write markdown here (else stdout)")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
