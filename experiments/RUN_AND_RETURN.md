# Run-and-return: what to execute on the rig, and what to send back

This is the checklist that turns rig time into a finished Chapter V. Run the experiments
below, then return the artifacts listed. With those, I regenerate every figure from real
data and fill V.2.1-V.2.7 with measured numbers; then we translate.

The runbook ids below map one-to-one onto the protocol phases in `PROTOCOL.md`:

| Runbook | PROTOCOL.md | Purpose |
|---|---|---|
| R1 | E1 | Main matrix (models x attackers x judges x corpora) |
| R2 | E2 | Attacker ablation (read of R1: replay vs crescendo) |
| R3 | E3 + E8 | Judge-cascade ablation + inter-judge kappa |
| R4 | E4 | Defense ablation (guardrail on/off) |
| R5 | E6 | Over-refusal / utility (read of R1 + MOSSBench) |
| R6 | E7 | Transferability matrix |
| R7 | E9 | Fable vs Mythos case study |
| R8 | Phase 4 | Figures from real data |

## 0. TL;DR - what to send back

Zip and return the whole `runs/` tree. Do NOT prune it to a "minimum" set: the raw
`*.jsonl` and `*.trails.jsonl` are required (V.2.4 multi-turn metrics and the per-category
kappa are computed from them and cannot be reconstructed otherwise). Per matrix cell
`<corpus>__<model>__<attacker>` the tree holds:

| File | Contains | Feeds |
|---|---|---|
| `*.results.jsonl` | aggregated `EvalResult`s (ASR+CI, refusal, over-refusal, StrongREJECT, robust-refusal, median-turns-to-break), grouped | Fig V.1/V.2/V.3, V.2.1-V.2.4 |
| `*.jsonl` | raw per-attempt judgments (+ provenance) | transfer matrix, re-analysis |
| `*.trails.jsonl` | each judge stage's verdict per attempt (+ risk_category) | judge kappa, pooled and per-category (V.2.5) |
| `*.manifest.json` | model id, seeds, dataset hashes, code version, `started_at`, env | provenance, versioning-drift caveat (V.2.6) |
| `transfer_matrix.json` (+ `.png`) | A->B transfer rates | transfer heatmap, V.2.4 |
| `judge_kappa.json` | inter-judge Cohen's kappa, pooled + per category | V.2.5 |

Also paste the console summary lines from each run (including any `! WARNING`/`! skipping`
lines) and any tracebacks.

## 1. The runs (current models)

Set keys first: `ANTHROPIC_API_KEY OPENAI_API_KEY GOOGLE_API_KEY DEEPSEEK_API_KEY ZHIPU_API_KEY MOONSHOT_API_KEY DASHSCOPE_API_KEY ARK_API_KEY`.
Point the corpus env vars at the cloned frameworks (see PROTOCOL.md Phase 1). Order: local
open-weights and cheap APIs first; the 70B-4bit and the most expensive APIs last.

Rig note (2x RTX 4090 = 48 GB total, 24 GB/card): the local set below is chosen to fit.
The 27B and 70B run 4-bit via Ollama; the 8B-class models run under vLLM at fp16
(`tensor_parallel_size=2`). vision-language checkpoints (`Qwen3-VL`, the LLaVA-RR model)
are auto-detected and receive image inputs; the Ollama-served 27B/70B are treated text-only.
`Llama-4-Scout` (109B MoE) does NOT fit 48 GB even at 4-bit and is omitted from local runs
(run it via a hosted endpoint if you have one, else drop it).

### R1 - Main matrix  (-> Fig V.1, Fig V.2; V.2.1, V.2.2)
```bash
python experiments/run_matrix.py \
  --api claude-opus-5,gpt-5.6,gemini-3.1-pro,deepseek:deepseek-chat,glm:glm-5.2,kimi:kimi-k3,qwen:qwen-max,doubao:doubao-vision-pro \
  --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:GraySwanAI/Llama-3-8B-Instruct-RR,vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR,ollama:gemma3:27b,ollama:llama3.3:70b \
  --attackers replay,crescendo --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,rjudge,mmsafety,jailbreakv,gptgeochat,vlsbench,agentharm \
  --group model,risk,modality --limit 200 --seeds 0,1 --out runs/main
```
Return: all of `runs/main/`. (R2, R5, R6 are reads of this one cell set.)
The two `GraySwanAI/*-RR` models are Gray Swan's circuit-breaker/representation-rerouting
hardened open weights; their ASR next to a comparable base model is the external
defense contrast that feeds V.2.3 (and mirrors the Fable/Mythos split of R7).

If a 27B/70B fails to fit under Ollama on your box, swap in the vLLM+AWQ path, e.g.
`--local vllm:<awq-repo>/gemma-3-27b-it-AWQ --quantization awq` (a pre-quantized checkpoint
is auto-detected and needs no flag).

### R2 - Attacker ablation (single-shot vs multi-turn)  (-> V.2.4, RQ4)
No extra run: it is the `replay` vs `crescendo` cells inside `runs/main`. Robust-refusal and
median-turns-to-break are emitted directly into the crescendo `*.results.jsonl`
(metrics `robust_refusal_rate`, `median_turns_to_break`); the raw `*.jsonl` back them up.

### R3 - Judge-cascade ablation + kappa  (-> V.2.5, measurement validity)
```bash
# full cascade (feeds the pooled + per-category kappa)
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/kappa
python experiments/kappa.py --results runs/kappa
# cascade ablation: rules-only vs full-cascade ASR on the same cells
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/judge-rules
```
Return: `runs/kappa/` (incl. `judge_kappa.json`) and `runs/judge-rules/`. Also, if you can,
hand-label a stratified ~100-item sample (I will send a sampling script/CSV) so we report
human-vs-automated agreement. Keep the kappa cell on `claude-opus-5` (matches PROTOCOL E8).

### R4 - Defense ablation (guardrail pre-filter on/off)  (-> V.2.3, RQ3)
```bash
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/nodef
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 \
  --defense input --defense-guard guardrail --out runs/def
```
Return: `runs/nodef/` and `runs/def/`. I diff ASR and over-refusal to get the defense delta.
(Both pass `--judge-model` so the `llm` stage is a real model, not the offline mock.)

### R5 - Over-refusal / utility  (-> Fig V.3 y-axis; V.2.3)
No extra run: `synth` (benign items) and `mossbench` supply FRR. Add `mossbench` to `--corpora`
in R1 if you have it (`--corpora ...,mossbench`); otherwise `synth` benign items suffice.

### R6 - Transferability  (-> transfer heatmap; V.2.4)
```bash
python experiments/transfer_matrix.py --results runs/main
```
Return: `runs/main/transfer_matrix.json` (+ `transfer_matrix.png`). Note: the transfer heatmap
is produced by `transfer_matrix.py`, not by `fig_results.py`; I copy its `.png` into
`Thesis-EN/diagrams/figures/` for the V.2.4 figure slot.

### R7 - Fable vs Mythos case study (if access)  (-> V.3 case study; II.6.1 payoff)
```bash
python experiments/run_matrix.py --api claude-fable-5,claude-mythos-5 \
  --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/fable-mythos
```
Return: `runs/fable-mythos/`. (You have Fable; add Mythos only if your access allows.)

### R8 - Figures from real data (sanity check on your side)
```bash
python ../../Thesis-EN/diagrams/fig_results.py --results runs/main
```
This confirms the pipeline end-to-end; I regenerate the final figures on my side from the
returned artifacts so styling stays consistent.

## 2. Data each figure/subsection needs (so nothing is missed)

| Target in Chapter V | Exact data | From |
|---|---|---|
| **Fig V.1** ASR by model | ASR + 95% CI per model (n-weighted mean across corpora/attackers/seeds) | `runs/main/*.results.jsonl` (metric=ASR, group_by.model) |
| **Fig V.2** ASR by category | ASR per (model, risk) | `runs/main/*.results.jsonl` (group_by.model+risk) |
| **Fig V.3** safety-utility | ASR (x) vs over_refusal_rate (y) per model; benign FRR | `runs/main` (ASR) + `synth`/`mossbench` benign FRR; overlay `runs/def` vs `runs/nodef` |
| transfer heatmap | A->B transfer rates | `runs/main/transfer_matrix.json` (via `transfer_matrix.py`) |
| V.2.1 overall ranking | ASR+CI ordering; note CI overlaps | `runs/main` |
| V.2.2 per-category + m-ASR | per-risk ASR; m-ASR by modality | `runs/main` (`--group model,risk,modality`) |
| V.2.3 safety-utility + defense | FRR per model; ASR/FRR delta with guardrail; RR-vs-base | `runs/main`, `runs/def` vs `runs/nodef` |
| V.2.4 multi-turn + transfer | robust_refusal_rate, median_turns_to_break; transfer matrix | crescendo cells in `runs/main`; `transfer_matrix.json` |
| V.2.5 judge validity | kappa per judge pair, pooled + per category; human-audit agreement | `judge_kappa.json`; the labelled sample |
| V.2.6 threats to validity | exact model ids + run dates + env | `*.manifest.json` (`models`, `started_at`, `env`) |
| V.2.7 discussion | synthesis - no new data (draws on all of the above) | - |

## 3. Budget and knobs
- Start with `--limit 50` for the paid APIs, `--limit 200` for local; scale up if budget allows.
- `--seeds 0,1` minimum; add `2` to tighten CIs. Seeds no longer collide in the transfer/kappa
  maps (attempt ids carry the seed), so multi-seed data is fully used.
- Crescendo multiplies API calls by up to `max_turns` (4). If cost is tight, run crescendo on a
  subset (`--attackers crescendo --limit 50`) into a separate `runs/main-crescendo` dir.
- Skip any model whose key/weights you lack - the driver skips it with a message; a partial matrix
  still produces valid figures (I note the omissions).
- If `--judges` includes `llm`, always pass a real `--judge-model` (e.g. `claude-haiku-4-5-20251001`).
  The driver prints a loud warning if it would otherwise fall back to the offline keyword mock.

## 4. What I do with the return
Regenerate Fig V.1-V.3 and the transfer heatmap from the returned `*.results.jsonl` /
`transfer_matrix.json`, fill V.2.1-V.2.7 with the measured ASR/CI/FRR/kappa/transfer numbers and
the model ranking, remove the ILLUSTRATIVE watermark, and then we proceed to the Bulgarian
translation.
