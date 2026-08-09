"""Convert Confident‑AI DeepTeam dataset → unified JSONL."""
import argparse, json, pathlib, random
from unify.data_models import DataPoint

parser = argparse.ArgumentParser()
parser.add_argument("--input", type=pathlib.Path, required=True)
parser.add_argument("--output", type=pathlib.Path, required=True)
parser.add_argument("--max", type=int, default=5, help="max items for mini‑subset")
args = parser.parse_args()

with args.input.open() as f:
    raw = [json.loads(l) for l in f]

subset = random.sample(raw, k=min(args.max, len(raw)))
with args.output.open("w") as out:
    for r in subset:
        dp = DataPoint(
            id=r["id"],
            modalities=["text"],
            payload_text=r["prompt"],
            attack_tag=r["category"],
            expected_behavior="safe-answer" if r["expected_safe"] else "refuse",
            meta_source="DeepTeam",
        )
        out.write(dp.model_dump_json() + "\n")
print(f"Wrote {len(subset)} DeepTeam examples → {args.output}")