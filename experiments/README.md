# Experiments (Chapter V) - how to run on the rig

`run_matrix.py` executes the model × attacker × judge matrix and writes results that the
thesis figure script turns into Chapter V figures.

## 0. Environment
- Rig: 2× RTX 4090 (48 GB), 128 GB RAM, Ryzen 5900.
- `pip install -r requirements.txt` plus, per backend you use: `vllm` (local GPU),
  `ollama` (local), `anthropic` / `openai` / `google-generativeai` (APIs),
  `transformers` (guardrail judge), `pandas`+`pyarrow` (Parquet).
- Export the API keys you have: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`.

## 1. Offline check (no keys, no GPU)
```bash
python experiments/run_matrix.py --dry-run --limit 12 --out runs/dry
python ../../Thesis-EN/diagrams/fig_results.py --results runs/dry
```

## 2. Real run
```bash
python experiments/run_matrix.py \
  --api    claude-opus-5,gpt-5.6,gemini-3.1-pro \
  --local  vllm:Qwen/Qwen3-VL-8B-Instruct,ollama:gemma3:27b,ollama:llama3.3:70b \
  --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth --limit 200 --seeds 0,1 --out runs/full
python ../../Thesis-EN/diagrams/fig_results.py --results runs/full
```
Swap `--corpora synth` for real corpora once their paths are set
(`URA_RJUDGE_PATH`, `URA_MMSAFETY_PATH`, …); any target whose key/weights are
missing is skipped with a message, so a partial matrix still produces figures.
See `RUN_AND_RETURN.md` for the full 2x RTX 4090 roster (incl. the Chinese-lab APIs and
the Gray Swan RR open-weight models) and exactly which artifacts to return.

## 3. Outputs (per matrix cell `<corpus>__<model>__<attacker>`)
- `*.jsonl` - raw judgments (full provenance)
- `*.results.jsonl` - aggregated `EvalResult`s (ASR+CI, refusal, over-refusal, StrongREJECT,
  robust-refusal, median-turns-to-break)
- `*.trails.jsonl` - each judge stage's verdict per attempt (+ risk_category) for inter-judge kappa
- `*.manifest.json` - the re-derivable `RunManifest` (seeds, hashes, code version, run date, env)

Fitting the 48 GB rig: the 27B/70B run 4-bit via **Ollama** (`ollama:gemma3:27b`,
`ollama:llama3.3:70b`), which is what actually delivers 4-bit here - the vLLM path needs an
explicit `--quantization awq/gptq` (or a pre-quantized checkpoint, auto-detected). 8B-class
models run under vLLM at fp16 sharded across both cards (`tensor_parallel_size=2`).
`Llama-4-Scout` (109B MoE) does not fit 48 GB even at 4-bit - run it hosted or omit it.
