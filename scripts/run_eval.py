"""Generic runner that dispatches to selected adapter."""
import argparse, importlib, json
from pathlib import Path
from unify.data_models import DataPoint

parser = argparse.ArgumentParser()
parser.add_argument("--adapter", required=True, help="rjudge | deepteam | ...")
parser.add_argument("--subset", type=Path, required=True)
args = parser.parse_args()

module = importlib.import_module(f"unify.adapters.{args.adapter}_adapter")
Adapter = getattr(module, f"{args.adapter.capitalize()}Adapter")  # naming convention
adapter = Adapter()

results = []
with args.subset.open() as fp:
    for line in fp:
        dp = DataPoint.model_validate_json(line)
        results.append(adapter.run(dp))

print(f"{len(results)} evaluated - sample: {results[0].model_dump() if results else 'n/a'}")