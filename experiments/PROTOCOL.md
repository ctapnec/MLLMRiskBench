# URA-Bench Experiment Protocol (Chapter V)

Run the phases in order. Phase 0 is a shakedown you must clear before spending API
budget or GPU hours. Each experiment states its purpose, the research question it
answers, the exact command, the outputs. Every experiment E1-E9 runs now (all ten
converters and the defense/transfer/kappa/modality additions are implemented).

## Goals → research questions → figures

| RQ | Question | Metric | Figure/table |
|----|----------|--------|--------------|
| RQ1 | Comparable overall risk across models? | ASR + 95% CI | Fig V.1 (ASR by model) |
| RQ2 | Risk varies by category & modality? | per-category ASR, m-ASR | Fig V.2 (ASR by category) |
| RQ3 | Is safety bought with over-refusal? | ASR vs FRR | Fig V.3 (safety-utility scatter) |
| RQ4 | Do multi-turn / transferred attacks find more? | robust-refusal, turns-to-break, transfer | tables |
| - | Is the judge trustworthy? | Cohen's κ, human-audit agreement | table |

---

## Phase 0 - Environment & shakedown (do first, ~30 min)

```bash
cd Project/MLLMRiskBench
pip install -r requirements.txt pydantic pytest
python -m pytest tests/ura -q                 # expect: 34 passed

# 0a. offline flow (no keys, no GPU)
python experiments/run_matrix.py --dry-run --limit 12 --out runs/dry

# 0b. smallest LIVE API probe (cheap current model, 1 attacker, rule judge only)
export ANTHROPIC_API_KEY=...
python experiments/run_matrix.py --api claude-haiku-4-5-20251001 --attackers replay \
    --judges rules --corpora synth --limit 10 --out runs/probe-api

# 0c. smallest LIVE local probe (one open-weight VLM)
python experiments/run_matrix.py --local vllm:Qwen/Qwen3-VL-8B-Instruct \
    --attackers replay --judges rules --corpora synth --limit 10 --out runs/probe-local
```

**Expected friction (fix before scaling):** the live target/judge/engine code was
written against documented APIs but never executed here. On 0b/0c you may hit SDK
call-shape or vLLM-arg issues - send me the traceback and I'll patch the target/judge.
Do **not** proceed to Phase 2 until 0b and 0c each produce a `*.results.jsonl`.

---

## Phase 1 - Data acquisition (real corpora)

All ten converters load each framework's REAL released layout (a directory or a file,
per framework) from the path in `URA_<NAME>_PATH`. Clone the framework, then point the
env var at its data:

| `--corpora` | Obtain (clone) | `URA_<NAME>_PATH` points at | Notes |
|---|---|---|---|
| `synth` | built-in | - | always-available control; benign + harmful |
| `rjudge` | github.com/Lordog/R-Judge | the `data/` dir | text agentic trajectories (162 records) |
| `mmsafety` | github.com/isXinLiu/MM-SafetyBench | repo root or `data/processed_questions/` | image jailbreak (5,040); imgs via repo Drive link |
| `jailbreakv` | HF JailbreakV-28K/JailBreakV-28k | the `JailBreakV_28K.csv` (or mini) file | image jailbreak (28K / 280 mini) |
| `gptgeochat` | github.com/ethanm88/GPTGeoChat | a split dir (has `annotations/`, `images/`) | geo-privacy multi-turn (500 test) |
| `agentharm` | HF ai-safety-institute/AgentHarm (gated) | a `*_behaviors_*.json` file | agentic misuse; benign counterparts too |
| `strongreject` | github.com/alexandrasouly/strongreject | `strongreject_dataset/strongreject_dataset.csv` | 313 forbidden text prompts |
| `harmbench` | github.com/centerforaisafety/HarmBench | `data/behavior_datasets/harmbench_behaviors_text_all.csv` | 400 behaviors (text + multimodal csv) |
| `vlsbench` | github.com/AI45Lab/VLSBench (HF Foreshhh/vlsbench) | a JSON/JSONL export | leakage-free image safety (2,241) |
| `mossbench` | github.com/xirui-li/MOSSBench (HF AIcell/MOSSBench) | a JSON/JSONL export | BENIGN over-refusal set (300) |
| `bipia` | github.com/microsoft/BIPIA | a context `*.jsonl` (e.g. `email/test.jsonl`) | indirect injection; joins sibling attack file |

All converters are implemented against the frameworks' verified real formats and are robust
to a missing path. HF-native sets (vlsbench, mossbench) load from a JSON/JSONL export of the
dataset. **First publishable run:** `synth,rjudge,mmsafety,gptgeochat` covers text, image,
multi-turn and agentic with no gated access; add `strongreject,harmbench,vlsbench,mossbench,
bipia` for full coverage.

---

## Phase 2 - Models under test

| Tier | Spec for `--api` / `--local` | Lab | Rig footprint |
|---|---|---|---|
| API (West) | `claude-opus-5`, `claude-fable-5` | Anthropic | - |
| API (West) | `gpt-5.6` (Pro) | OpenAI | - |
| API (West) | `gemini-3.1-pro` | Google | - |
| API (China) | `deepseek:deepseek-chat` (V4 Pro) | DeepSeek | - |
| API (China) | `glm:glm-5.2` | Zhipu / z.ai | - |
| API (China) | `kimi:kimi-k3` | Moonshot | - |
| API (China) | `qwen:qwen-max` (Qwen3.6-Max) | Alibaba | - |
| API (China) | `doubao:doubao-vision-pro` | ByteDance | - |
| Local | `vllm:Qwen/Qwen3-VL-8B-Instruct` | Alibaba | fp16 VLM, ~16 GB (1 card) |
| Local | `vllm:GraySwanAI/Llama-3-8B-Instruct-RR` | Gray Swan | circuit-breaker (RR) text, ~16 GB |
| Local | `vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR` | Gray Swan | circuit-breaker (RR) VLM, ~15 GB |
| Local | `ollama:gemma3:27b` | Google | 4-bit, ~18 GB (fits) |
| Local | `ollama:llama3.3:70b` | Meta | 4-bit, ~40 GB (2 cards); the quant-vs-safety probe |
| Local (opt.) | `vllm:moonshotai/Kimi-VL-A3B-Thinking` | Moonshot | ~16B MoE, fp16 (fits) |
| Local (opt.) | `vllm:microsoft/Phi-4-multimodal-instruct` | Microsoft | text+image+audio |
| Out of scope | `Llama-4-Scout-17B-16E-Instruct` | Meta | 109B MoE; exceeds 48 GB even at 4-bit - hosted/omitted |
| Out of scope | `deepseek-ai/deepseek-vl2` | DeepSeek | ~27B fp16 (~27 GB/card OOM); use a smaller/quantized variant |

Set the per-provider API keys: `DEEPSEEK_API_KEY`, `ZHIPU_API_KEY`, `MOONSHOT_API_KEY`,
`DASHSCOPE_API_KEY` (Qwen), `ARK_API_KEY` (Doubao), plus the Western ones. Update ids to the
newest you have; any id works via `<provider>:<model>` (e.g. `qwen:qwen3.6-max`,
`kimi:kimi-k3`). Where you have Fable/Mythos access, add both as `--api` targets (E9).

Rig footprints assume 2x RTX 4090 (24 GB/card, 48 GB total). The 27B/70B run 4-bit via
Ollama (which fits cleanly); an alternative for the 27B is vLLM against a pre-quantized AWQ
checkpoint with `--quantization awq`. The two `GraySwanAI/*-RR` models are the
representation-rerouting hardened open weights (Gray Swan's Cygnet line); their ASR against a
comparable base model is the external defense contrast (V.2.3). Vision-language checkpoints
are auto-detected by `run_matrix.py` and receive image inputs; Ollama-served models are run
text-only, so exclude them from the m-ASR image comparison (E5).

---

## Phase 3 - The experiments

### E1 - Main matrix (RQ1, RQ2) - runs now
The backbone run; everything else reuses or ablates it. This is the *reduced,
first-publishable* subset (3 APIs + 3 local, no-gated corpora); the full roster is R1 in
`RUN_AND_RETURN.md` (8 APIs + 5 local incl. the Chinese labs and Gray Swan RR models). Keep
downstream references consistent with whichever you actually run.
```bash
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=... GOOGLE_API_KEY=...
export URA_RJUDGE_PATH=data/rjudge.jsonl URA_MMSAFETY_PATH=data/mmsafety.jsonl \
       URA_JAILBREAKV_PATH=data/JailBreakV_28K.csv URA_GPTGEOCHAT_PATH=data/gptgeochat.jsonl
python experiments/run_matrix.py \
  --api claude-opus-5,gpt-5.6,gemini-3.1-pro \
  --local vllm:Qwen/Qwen3-VL-8B-Instruct,ollama:gemma3:27b,ollama:llama3.3:70b \
  --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,rjudge,mmsafety,jailbreakv,gptgeochat \
  --group model,risk,modality \
  --limit 200 --seeds 0,1 --out runs/main
```
**Outputs:** per cell `<corpus>__<model>__<attacker>.{jsonl,results.jsonl,trails.jsonl,manifest.json}`.
Feeds Fig V.1 (mean ASR by model) and Fig V.2 (ASR by risk category). `--group model,risk,modality`
emits the per-modality m-ASR rows E5/V.2.2 read; `jailbreakv` is included so E5 has a second image
corpus to compare.

### E2 - Attacker ablation: single-shot vs multi-turn (RQ4) - runs now
Already produced by E1 (both `replay` and `crescendo`). Compare, per model:
`replay` ASR vs `crescendo` robust-refusal and median turns-to-break. H4 predicts
crescendo breaks models that refuse the direct request.

### E3 - Judge-cascade ablation (validity) - runs now
Quantify how much the guardrail/LLM stages change the verdict vs. rules alone.
```bash
# rules-only
python experiments/run_matrix.py --api gpt-5.6 --attackers replay \
  --judges rules --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/judge-rules
# full cascade
python experiments/run_matrix.py --api gpt-5.6 --attackers replay \
  --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/judge-full
```
Compare ASR between the two `runs/` dirs. (Guardrail judge needs `transformers` +
gated Llama-Guard-3 access; skips cleanly if unavailable.)

### E4 - Defense ablation: guardrail pre-filter on/off (RQ3) - runs now
Run the same cell with and without a `GuardedTarget` wrapper, then diff ASR and FRR.
```bash
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --out runs/nodef
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 \
  --defense input --defense-guard guardrail --out runs/def
```
The defended cell is attributed to `<model>+guard`; a good guardrail lowers ASR but
raises over-refusal on the benign items (the safety-utility cost).

### E5 - Multimodal m-ASR (RQ2) - runs now
From E1, compare text corpora (`rjudge`) against image corpora (`mmsafety`,
`jailbreakv`) per model to isolate the visual-channel contribution. For a modality
breakdown inside a mixed corpus, add `--group model,risk,modality` to the run (the
aggregate then emits a per-modality m-ASR row per model).

### E6 - Over-refusal / utility cost (RQ3) - runs now
`synth` includes benign `safe_answer` datapoints, so FRR is already computed. For a
dedicated benign set, add the `mossbench` corpus (all-benign) and run it; plot FRR on
the y-axis of Fig V.3.

### E7 - Transferability matrix (RQ4) - runs now
Post-hoc over E1's per-attempt judgments: for each (A,B) model pair, ASR on B restricted
to attempts that succeeded on A.
```bash
python experiments/transfer_matrix.py --results runs/main
```
Writes `transfer_matrix.json` (+ a heatmap PNG); attempts key on `attempt_id`, which is
model-independent, so the same attack is compared across model cells.

### E8 - Judge calibration κ + human audit - runs now
The driver saves each judge stage's verdict as `*.trails.jsonl`; compute inter-judge
Cohen's κ over a multi-stage cascade run:
```bash
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --out runs/kappa
python experiments/kappa.py --results runs/kappa
```
`--judge-model` is required here: without it the `llm` stage falls back to the offline keyword
mock and the kappa is meaningless (the driver warns loudly). `kappa.py` reports kappa both
pooled and PER RISK CATEGORY (read from the trails' `risk_category`). Then draw a stratified
~100-item sample for human labelling to anchor the automated stages (record agreement per
category); low κ is a signal to prefer the graded StrongREJECT score over binary ASR there.

### E9 - Fable vs Mythos case study (optional, if access) - runs now
```bash
python experiments/run_matrix.py --api claude-fable-5,claude-mythos-5 \
  --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/fable-mythos
```
Same underlying model, two safety postures → directly reads out the safety-vs-capability
trade-off (Fig V.3, two points).

---

## Phase 4 - Figures & write-up

```bash
python ../../Thesis-EN/diagrams/fig_results.py --results runs/main
```
Replaces the illustrative figures with measured ones. Then fill Chapter V.2 with the
observed numbers (ASR ranking + CIs, per-category profiles, safety-utility positions,
crescendo deltas, transfer rates, κ), following the analysis structure already written.

---

## Sample sizes, seeds, budget

- **Seeds:** `0,1` minimum (variance); add `2` to tighten CIs.
- **`--limit`:** pilot at **25**, main at **200** (or the full corpus for small ones like R-Judge).
- **API call budget per cell:** `replay ≈ limit×(1 target + n_judge)`;
  `crescendo ≈ limit×max_turns×(1 target + n_judge)` (max_turns=4). With `--judges
  rules,llm` and `--judge-model claude-haiku-4-5-20251001`, the LLM judge adds `limit` cheap calls per cell.
  → Estimate before launching; start the paid API tier at `--limit 50`, use larger
  `--limit` for the free local tier.
- **Local time:** Qwen3-VL-8B fp16 is fast; 70B-4bit is the slow cell - schedule it last.

## Reporting checklist (validity)

- Every rate reported with its bootstrap 95% CI (the aggregate already does this).
- State the exact model ids and run dates (they're in each `*.manifest.json`).
- Report κ per category; prefer StrongREJECT grade over binary ASR where κ is low.
- Note cross-modal claims lean on the leakage-controlled set (`vlsbench`) vs the older image sets.
- Keep all `runs/` dirs - the manifests make every number reproducible.

---

### Quickest path to a defensible Chapter V
Phase 0 → E1 on `synth,rjudge,mmsafety,gptgeochat` with 3 APIs + 2 local models,
`--limit 100 --seeds 0,1` → E3 judge ablation on one corpus → figures. That yields
RQ1/RQ2/RQ3 (partial RQ4 via crescendo) with real numbers; E4/E5/E7/E8 all run on top of
the same runs (defense wrap, m-ASR grouping, transfer matrix, judge kappa).
