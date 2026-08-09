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
  --local  vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:google/gemma-3-27b-it,ollama:llama3.3:70b \
  --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth --limit 200 --seeds 0,1 --out runs/full
python ../../Thesis-EN/diagrams/fig_results.py --results runs/full
```
Swap `--corpora synth` for real corpora once their paths are set
(`URA_RJUDGE_PATH`, `URA_MMSAFETY_PATH`, …); any target whose key/weights are
missing is skipped with a message, so a partial matrix still produces figures.

## 3. Outputs (per matrix cell `<corpus>__<model>__<attacker>`)
- `*.jsonl` - raw judgments (full provenance)
- `*.results.jsonl` - aggregated `EvalResult`s (ASR+CI, refusal, over-refusal, StrongREJECT)
- `*.manifest.json` - the re-derivable `RunManifest` (seeds, hashes, code version)

Local models >24 GB shard across both GPUs (vLLM `tensor_parallel_size=2`); use 4-bit
quantization for 70B-class models per the notes in the thesis (II.6.1 / III.1.3).
