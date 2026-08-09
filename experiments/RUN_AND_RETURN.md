# Run-and-return: what to execute on the rig, and what to send back

This is the checklist that turns rig time into a finished Chapter V. Run the experiments
below, then return the artifacts listed. With those, I regenerate every figure from real
data and fill V.2.1-V.2.7 with measured numbers; then we translate.

## 0. TL;DR - what to send back

Zip and return the whole `runs/` tree. Per matrix cell `<corpus>__<model>__<attacker>` it holds:

| File | Contains | Feeds |
|---|---|---|
| `*.results.jsonl` | aggregated `EvalResult`s (ASR+CI, refusal, over-refusal, StrongREJECT), grouped | Fig V.1/V.2/V.3, tables |
| `*.jsonl` | raw per-attempt judgments (+ provenance) | transfer matrix, re-analysis |
| `*.trails.jsonl` | each judge stage's verdict per attempt | judge kappa (V.2.5) |
| `*.manifest.json` | exact model id, seeds, dataset hashes, code version | provenance, versioning-drift caveat |
| `transfer_matrix.json` | A->B transfer rates | Fig V.4 (transfer heatmap), V.2.4 |
| `judge_kappa.json` | inter-judge Cohen's kappa | V.2.5 |

If the raw `*.jsonl` are large, at minimum send the `*.results.jsonl`, `*.manifest.json`,
`transfer_matrix.json`, and `judge_kappa.json` - those alone let me regenerate the figures and
write the analysis (the raw judgments only add re-analysis flexibility). Also paste the console
summary lines from each run and any tracebacks.

## 1. The runs (current models)

Set keys first: `ANTHROPIC_API_KEY OPENAI_API_KEY GOOGLE_API_KEY DEEPSEEK_API_KEY ZHIPU_API_KEY MOONSHOT_API_KEY DASHSCOPE_API_KEY ARK_API_KEY`.
Point the corpus env vars at the cloned frameworks (see PROTOCOL.md Phase 1). Order: local models
and cheap APIs first; the 70B-4bit and the most expensive APIs last.

### R1 - Main matrix  (-> Fig V.1, Fig V.2; V.2.1, V.2.2)
```bash
python experiments/run_matrix.py \
  --api claude-opus-5,gpt-5.6,gemini-3.1-pro,deepseek:deepseek-chat,glm:glm-5.2,kimi:kimi-k3,qwen:qwen-max \
  --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:meta-llama/Llama-4-Scout-17B-16E-Instruct,vllm:google/gemma-3-27b-it \
  --attackers replay,crescendo --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,rjudge,mmsafety,jailbreakv,gptgeochat,vlsbench,agentharm \
  --group model,risk,modality --limit 200 --seeds 0,1 --out runs/main
```
Return: all of `runs/main/`. (This one cell set already yields R2, R5, R6 below - they are reads of it.)

### R2 - Attacker ablation (single-shot vs multi-turn)  (-> V.2.4, RQ4)
No extra run: it is the `replay` vs `crescendo` cells inside `runs/main`. I read robust-refusal and
turns-to-break from the crescendo cells. (If you want deeper multi-turn, add `reveal` to `--corpora`.)

### R3 - Judge-cascade ablation + kappa  (-> V.2.5, measurement validity)
```bash
python experiments/run_matrix.py --api gpt-5.6 --attackers replay \
  --judges rules,guardrail,llm --judge-model claude-haiku-4-5-20251001 \
  --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/kappa
python experiments/kappa.py --results runs/kappa
```
Return: `runs/kappa/` incl. `judge_kappa.json`. Also, if you can, hand-label a stratified ~100-item
sample (I will send a sampling script/CSV) so we report human-vs-automated agreement.

### R4 - Defense ablation (guardrail pre-filter on/off)  (-> V.2.3, RQ3)
```bash
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --corpora synth,mmsafety --limit 200 --seeds 0,1 --out runs/nodef
python experiments/run_matrix.py --api claude-opus-5 --attackers replay \
  --judges rules,llm --corpora synth,mmsafety --limit 200 --seeds 0,1 \
  --defense input --defense-guard guardrail --out runs/def
```
Return: `runs/nodef/` and `runs/def/`. I diff ASR and over-refusal to get the defense delta.

### R5 - Over-refusal / utility  (-> Fig V.3 y-axis; V.2.3)
No extra run: `synth` (benign items) and `mossbench` supply FRR. Add `mossbench` to `--corpora` in R1
if you have it (`--corpora ...,mossbench`); otherwise `synth` benign items suffice.

### R6 - Transferability  (-> Fig V.4; V.2.4)
```bash
python experiments/transfer_matrix.py --results runs/main
```
Return: `runs/main/transfer_matrix.json` (+ `transfer_matrix.png`).

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
This confirms the pipeline end-to-end; I will regenerate the final figures on my side from the
returned artifacts so styling stays consistent.

## 2. Data each figure/subsection needs (so nothing is missed)

| Target in Chapter V | Exact data | From |
|---|---|---|
| **Fig V.1** ASR by model | ASR + 95% CI per model (mean across corpora) | `runs/main/*.results.jsonl` (metric=ASR, group_by.model) |
| **Fig V.2** ASR by category | ASR per (model, risk) | `runs/main/*.results.jsonl` (group_by.model+risk) |
| **Fig V.3** safety-utility | ASR (x) vs over_refusal_rate (y) per model | `runs/main` (ASR) + benign FRR (synth/mossbench); overlay `runs/def` vs `runs/nodef` |
| **Fig V.4** transfer heatmap | A->B transfer rates | `transfer_matrix.json` |
| V.2.1 overall ranking | ASR+CI ordering; note CI overlaps | `runs/main` |
| V.2.2 per-category + m-ASR | per-risk ASR; m-ASR by modality | `runs/main` (`--group model,risk,modality`) |
| V.2.3 safety-utility + defense | FRR per model; ASR/FRR delta with guardrail | `runs/main`, `runs/def` vs `runs/nodef` |
| V.2.4 multi-turn + transfer | robust-refusal, median turns-to-break; transfer matrix | crescendo cells in `runs/main`; `transfer_matrix.json` |
| V.2.5 judge validity | kappa per judge pair; human-audit agreement | `judge_kappa.json`; the labelled sample |
| V.2.6 threats to validity | exact model ids + run dates | `*.manifest.json` |

## 3. Budget and knobs
- Start with `--limit 50` for the paid APIs, `--limit 200` for local; scale up if budget allows.
- `--seeds 0,1` minimum; add `2` to tighten CIs.
- Crescendo multiplies API calls by up to `max_turns` (4). If cost is tight, run crescendo on a
  subset (`--attackers crescendo --limit 50`) into a separate `runs/main-crescendo` dir.
- Skip any model whose key/weights you lack - the driver skips it with a message; a partial matrix
  still produces valid figures (I note the omissions).

## 4. What I do with the return
Regenerate Fig V.1-V.4 from the returned `*.results.jsonl`/`transfer_matrix.json`, fill V.2.1-V.2.7
with the measured ASR/CI/FRR/kappa/transfer numbers and the model ranking, update the tables, remove
the ILLUSTRATIVE watermark, and then we proceed to the Bulgarian translation.
