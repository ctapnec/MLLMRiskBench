# URA-Bench - Unified Risk-Assessment Benchmark for (M)LLMs

*A plugin-based, standards-aligned, modality- and agentic-aware harness for measuring the safety risk of large and multimodal language models under adversarial and realistic conditions.*

> This repository is the reference implementation accompanying the master's thesis **“A Risk-Assessment System for Question Answering by Multimodal Language Models”** (Sofia University, FMI, MP “Artificial Intelligence”). It modernizes the project's pre-2025 prototype: the current package is **`src/ura/`** (schema v1.0); the earlier `src/unify/` (schema v0.3) is retained as **legacy** for reference.

## Why

The safety-evaluation ecosystem is fragmented: every red-teaming engine and benchmark uses its own format, its own definition of a “successful” attack, its own judge, and its own (or no) mapping to the risk taxonomies regulators now require. Results do not compose. URA-Bench unifies three concerns that today live in separate silos and **wraps** the mature tools (PyRIT, Garak, DeepTeam, Promptfoo, T3MP3ST, Petri, MM-SafetyBench, AgentHarm, …) rather than re-implementing attacks:

1. **Attacks** - single/multi-turn text, image+text, audio, and agentic tool-use.
2. **Targets** - hosted APIs (Anthropic/OpenAI/Google) and self-hosted open weights (vLLM/Ollama).
3. **Judgment & metrics** - a rule→guardrail→LLM cascade, modern metrics with confidence intervals, and first-class OWASP/NIST/MLCommons/EU-AI-Act mapping.

The three are **independent, interchangeable axes** (any attacker × any target × any judge).

## Design in one picture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (five layers, schema class diagram), [docs/SCHEMA.md](docs/SCHEMA.md) (the v1.0 data model), [docs/METRICS.md](docs/METRICS.md) (the metric set), and [docs/ATTACK_TAGS.md](docs/ATTACK_TAGS.md) (the risk taxonomy + standards mapping).

## Quickstart (offline, no keys, no GPU)

```bash
pip install pydantic            # the only hard dependency of the core
python -m pytest tests/ura -q   # 25 tests, ~1s

# full pipeline on a synthetic corpus against the offline MockTarget:
PYTHONPATH=src python -m ura.cli run --corpus synth --attacker replay \
    --target mock --judges rules,llm --out ./ura-demo
```

Everything in the core imports and runs with **only Pydantic + the standard library**; provider SDKs, `vllm`, `ollama`, `transformers`, the red-teaming engines, and `pandas`/`pyarrow` are imported lazily and only required when the corresponding feature is used.

## Running the experiment matrix (rig)

```bash
pip install -r requirements.txt      # + extras per backend (see requirements.txt)
export ANTHROPIC_API_KEY=…  OPENAI_API_KEY=…  GOOGLE_API_KEY=…
python experiments/run_matrix.py --dry-run --out runs/dry           # offline check
python experiments/run_matrix.py \
    --api claude-opus-5,gpt-5.6,gemini-3.1-pro \
    --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:google/gemma-3-27b-it \
    --attackers replay,crescendo --judges rules,llm \
    --corpora synth --limit 200 --seeds 0,1 --out runs/full
```

See [experiments/README.md](experiments/README.md). Figures: `python ../../Thesis-EN/diagrams/fig_results.py --results runs/full`.

## Layout

```text
src/ura/            modern package (schema v1.0) - the harness
  data_models.py    typed schema (Pydantic v2)
  taxonomy.py       RiskCategory → OWASP/NIST/MLCommons (data)
  metrics.py        ASR, StrongREJECT, FRR, robust-refusal, κ, bootstrap CIs
  adapters/         BaseAttacker + replay/crescendo/engine wrappers, converters
  targets/          Mock/Anthropic/OpenAI/Gemini + vLLM/Ollama
  judges/           rules → guardrail → LLM cascade
  runner.py         orchestrator (+ run manifest, aggregation)
  report.py, cli.py reporting + `ura convert|run|report`
tests/ura/          25 offline tests (core, plugins, end-to-end smoke)
experiments/        run_matrix.py - turnkey model×attacker×judge driver
docs/               architecture, schema, metrics, attack tags
src/unify/          LEGACY v0.3 prototype (kept for reference)
```

## Status

Core + offline pipeline: **implemented and tested** (25/25). Live target/judge/engine paths and real corpora: implemented with lazy deps, to be validated on first rig run. Experiments: turnkey, pending execution on the rig.

## License

Apache-2.0.
