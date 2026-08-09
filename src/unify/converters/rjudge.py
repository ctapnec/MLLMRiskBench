"""CLI entry: convert R‑Judge dataset → unified JSONL."""
import argparse, json, pathlib
from unify.adapters.rjudge import RJudgeAdapter

parser = argparse.ArgumentParser()
parser.add_argument("--input", type=pathlib.Path, required=True)
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()

samples = RJudgeAdapter.parse_original(args.input)
with args.output.open("w") as f:
    for s in samples:
        f.write(s.model_dump_json() + "\n")
print(f"Wrote {len(samples)} unified samples → {args.output}")