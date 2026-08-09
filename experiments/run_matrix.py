"""Turnkey experiment driver for URA-Bench (thesis Chapter V).

Runs the model x attacker x judge matrix over one or more corpora, aggregates the
metrics, and writes per-cell JSONL + a combined results directory that the thesis
figure script (`Thesis-EN/diagrams/fig_results.py --results <dir>`) consumes.

This is designed to run on the project rig (2x RTX 4090) with provider API keys in
the environment. It is dependency-tolerant: any target whose SDK/weights or API key
is unavailable is skipped with a clear message, so a partial matrix still produces
results. A `--dry-run` uses the offline MockTarget so the whole flow is verifiable
with no keys and no GPU.

Examples
--------
# offline smoke of the whole matrix (no keys, no GPU):
python experiments/run_matrix.py --dry-run --limit 12 --out runs/dry

# real run: 3 APIs + 3 local open-weights, 200 items/corpus:
export ANTHROPIC_API_KEY=...  OPENAI_API_KEY=...  GOOGLE_API_KEY=...
python experiments/run_matrix.py \
    --api claude-opus-5,gpt-5.6,gemini-3.1-pro \
    --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:google/gemma-3-27b-it,ollama:llama3.3:70b \
    --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
    --corpora synth --limit 200 --seeds 0,1 --out runs/full

API model ids are the current (2026) frontier; you may also pass any id as
"<provider>:<model>" (e.g. openai:gpt-5.6-pro, anthropic:claude-fable-5) so the
harness never needs editing when a new checkpoint ships.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# make `import ura` work when run as a script from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.adapters.base import AttackBudget           # noqa: E402
from ura.adapters.engines import get_attacker         # noqa: E402
from ura.converters import get_converter, synth_corpus  # noqa: E402
from ura.data_models import DataPoint                 # noqa: E402
from ura.judges.base import JudgeCascade              # noqa: E402
from ura.judges.llm import LLMJudge                   # noqa: E402
from ura.judges.rules import RuleJudge                # noqa: E402
from ura.runner import Runner                         # noqa: E402
from ura.targets.api import MockTarget, build_api_target  # noqa: E402
from ura.targets.base import REGISTRY                 # noqa: E402


def build_target(spec: str):
    """Resolve a target spec to a BaseTarget, or return None if unavailable.

    spec is one of:
      * a hosted id or "<provider>:<model>" - e.g. "claude-opus-5", "mock",
        "anthropic:claude-fable-5", "openai:gpt-5.6-pro", "google:gemini-3.1-pro";
      * a local "<backend>:<model>" - "vllm:Qwen/Qwen3-VL-8B-Instruct",
        "ollama:llama3.3:70b".
    """
    try:
        if ":" in spec:
            backend = spec.split(":", 1)[0].lower()
            if backend in {"vllm", "ollama"}:
                _, model = spec.split(":", 1)
                if backend == "vllm":
                    from ura.targets.local import VLLMTarget
                    return VLLMTarget(model=model)
                from ura.targets.local import OllamaTarget
                return OllamaTarget(model=model)
            # provider:model (anthropic/openai/google/gemini)
            return build_api_target(spec)
        # bare id: resolve against the hosted/mock registry
        return build_api_target(spec)
    except Exception as exc:  # noqa: BLE001 - report and skip, don't abort the matrix
        print(f"  ! skipping target '{spec}': {type(exc).__name__}: {exc}")
        return None


def build_judges(names: list[str], judge_model: str) -> JudgeCascade:
    stages = []
    for n in names:
        if n == "rules":
            stages.append(RuleJudge())
        elif n == "llm":
            stages.append(LLMJudge(judge_target=REGISTRY.create(judge_model)))
        elif n == "guardrail":
            from ura.judges.guardrail import GuardrailJudge
            stages.append(GuardrailJudge())
        else:
            print(f"  ! unknown judge '{n}', skipping")
    return JudgeCascade(stages or [RuleJudge()])


def load_corpus(name: str, limit: int) -> list[DataPoint]:
    if name == "synth":
        return synth_corpus(limit)
    conv = get_converter(name)
    # expects data under datasets/<name>.jsonl by default; override via env
    path = Path(os.environ.get(f"URA_{name.upper()}_PATH",
                               f"datasets/samples/{name}.jsonl"))
    dps = conv.parse(path)
    return dps[:limit] if limit else dps


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="URA-Bench experiment matrix.")
    ap.add_argument("--dry-run", action="store_true", help="use MockTarget only")
    ap.add_argument("--api", default="", help="comma list of API model ids")
    ap.add_argument("--local", default="", help="comma list of backend:model specs")
    ap.add_argument("--attackers", default="replay,crescendo")
    ap.add_argument("--judges", default="rules,llm")
    ap.add_argument("--judge-model", default="mock", help="target id used by LLMJudge")
    ap.add_argument("--corpora", default="synth")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--seeds", default="0")
    ap.add_argument("--group", default="model,risk",
                    help="aggregation group keys, e.g. model,risk,modality (E5 m-ASR)")
    ap.add_argument("--defense", default="none",
                    choices=["none", "input", "output", "both"],
                    help="wrap targets in a GuardedTarget pre/post-filter (E4 ablation)")
    ap.add_argument("--defense-guard", default="rules", choices=["rules", "guardrail"],
                    help="judge used as the defense guardrail when --defense is set")
    ap.add_argument("--out", default="runs/exp")
    args = ap.parse_args(argv)

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    model_specs = ["mock"] if args.dry_run else (
        [s for s in args.api.split(",") if s] + [s for s in args.local.split(",") if s]
    )
    if not model_specs:
        model_specs = ["mock"]

    attacker_names = [a for a in args.attackers.split(",") if a]
    judge_names = [j for j in args.judges.split(",") if j]
    corpora = [c for c in args.corpora.split(",") if c]

    n_cells = 0
    for corpus_name in corpora:
        corpus = load_corpus(corpus_name, args.limit)
        if not corpus:
            print(f"corpus '{corpus_name}' is empty, skipping")
            continue
        print(f"corpus '{corpus_name}': {len(corpus)} datapoints")
        group_keys = [k for k in args.group.split(",") if k]
        for spec in model_specs:
            target = build_target(spec)
            if target is None:
                continue
            if args.defense != "none":  # E4: wrap in a guardrail pre/post-filter
                from ura.targets.guarded import GuardedTarget
                if args.defense_guard == "guardrail":
                    from ura.judges.guardrail import GuardrailJudge
                    guard = GuardrailJudge()
                else:
                    guard = RuleJudge()
                target = GuardedTarget(target, guard, mode=args.defense)
            for attacker_name in attacker_names:
                attacker = get_attacker(attacker_name)
                cascade = build_judges(judge_names, args.judge_model)
                runner = Runner(attacker, target, cascade,
                                AttackBudget(max_turns=4, seed=seeds[0]), seeds)
                judgments, manifest = runner.run(corpus, started_at="")
                results = runner.aggregate(judgments, group_keys=group_keys)

                stem = f"{corpus_name}__{target.name}__{attacker_name}"
                runner.save_results(judgments, out / f"{stem}.jsonl")
                runner.save_trails(out / f"{stem}.trails.jsonl")   # for kappa.py
                (out / f"{stem}.results.jsonl").write_text(
                    "\n".join(r.model_dump_json() for r in results) + "\n",
                    encoding="utf-8")
                (out / f"{stem}.manifest.json").write_text(
                    manifest.model_dump_json(indent=1), encoding="utf-8")
                print(f"  [{stem}] {len(judgments)} judgments -> {len(results)} results "
                      f"(run {manifest.run_id})")
                n_cells += 1

    print(f"\ndone: {n_cells} matrix cells written to {out}")
    print(f"figures: python ../../Thesis-EN/diagrams/fig_results.py --results {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
