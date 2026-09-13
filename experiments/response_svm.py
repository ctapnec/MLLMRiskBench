"""Export or evaluate retained-response SVMs without provider calls."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export", action="store_true")
    mode.add_argument("--evaluate", action="store_true")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--campaign", action="append", default=[])
    parser.add_argument("--matched-campaign")
    parser.add_argument("--judge-condition")
    parser.add_argument("--exclude-model", action="append", default=[])
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-feature-characters", type=int, default=20000)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--holdout-model", action="append", default=[])
    parser.add_argument("--holdout-corpus", action="append", default=[])
    args = parser.parse_args(argv)
    if args.export and not all((args.database, args.candidates, args.campaign,
                                args.matched_campaign, args.judge_condition)):
        parser.error("Export needs database, candidates, campaign, matched-campaign and judge-condition")
    if args.evaluate and not args.dataset:
        parser.error("Evaluation needs --dataset")
    args.out.mkdir(parents=True, exist_ok=False)
    try:
        if args.export:
            from experiments.response_svm_dataset import export_dataset
            rows, report = export_dataset(database=args.database, candidates=args.candidates,
                campaigns=args.campaign, judge=args.judge_condition,
                matched_campaign=args.matched_campaign, exclude_models=args.exclude_model)
            with (args.out / "dataset.jsonl").open("x", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
        else:
            from ura.response_svm import evaluate_study
            with args.dataset.open(encoding="utf-8") as stream:
                rows = [json.loads(line) for line in stream if line.strip()]
            def progress(value):
                print(json.dumps(dict(time_utc=datetime.now(timezone.utc).isoformat(), **value)), flush=True)
            report, predictions = evaluate_study(rows, seed=args.seed,
                max_chars=args.max_feature_characters, bootstrap=args.bootstrap,
                holdout_models=args.holdout_model, holdout_corpora=args.holdout_corpus, progress=progress)
            write_json(args.out / "predictions.json", predictions)
        report["time_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(args.out / "result.json", report)
        print(json.dumps({k: v for k, v in report.items() if k not in ("experiments", "split_membership")}), flush=True)
        return 0
    except Exception as exc:
        write_json(args.out / "error.json", dict(status="failed", error_type=type(exc).__name__, error=str(exc)))
        raise


if __name__ == "__main__":
    raise SystemExit(main())
