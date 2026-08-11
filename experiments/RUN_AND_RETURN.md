# Run-and-return runbook (end-to-end, from a clean machine)

This is the complete operator runbook for executing the pending Chapter V study
and returning the data for analysis. It starts at point zero (a bare machine) and
ends with a packaged artifact set. The experiments are pending: a dry run, a
partial artifact family without its error record, or files produced with
placeholder IDs is **not** sufficient for Chapter V.

The planned executable comparison is an exact account-visible **Claude Fable**
endpoint versus the public **`gpt-5.6-sol`** model through the OpenAI Responses
API with Pro mode, medium effort, and current-turn reasoning context. It is
cross-provider and non-causal; it is not a same-base defense ablation. The
default output directory is `runs/fable-vs-gpt56-sol-pro`.

**Mythos is not a run target.** The researcher lacks access. Preserve Mythos in
the thesis as Anthropic's frontier cybersecurity model, external evidence, an
access/governance limitation, and a future replication target. Do not create a
Mythos row, placeholder measurement, or executable alias.

---

## Division of labor (read this first)

The core case study is **API-only** and needs **no GPU**. The GPU rig only
matters if you add local open-weight targets (vLLM), the model-backed Llama Guard
guard arm, or white-box engines.

**You run on the rig** (needs credentials, network, and possibly GPUs):

- Section 0 provisioning and offline sanity;
- Section 2 live probes;
- Section 4 (R1) main matched matrix and the source-monitor track;
- Section 6 (R3) defense arms, only if the E4 ablation is in scope;
- Section 9 (R6) human audit (this needs human raters).

**I (Claude) run from your returned `runs/` tree** (no model calls, no GPU):

- Section 5 (R2) judge sensitivity, Section 7 (R4) transfer, Section 8 (R5)
  kappa, Section 11 (R8) real-data figures;
- the provenance/completion audit and the Chapter V numbers and figures.

So the **minimum you must return** is the entire `runs/` tree from the
model-calling commands plus the freeze note, console logs, and an environment
freeze (and the human-audit files through a secure channel). You may run the
read-only analyses yourself as a cross-check, but you do not have to.

---

## 0. Provision from zero

### 0.1 Machine and prerequisites

- **Python 3.12 or 3.13** (the package requires `>=3.12,<3.14`), `git`, and a C
  toolchain for wheels.
- The case study endpoints are hosted APIs, so a plain Linux/macOS/Windows box
  with network access is enough.
- The 2x RTX-4090 rig is required only for local vLLM targets, the Llama Guard 3
  guard, or white-box engines. For those, assume a recent Ubuntu + matching CUDA
  driver and use the GPUs tensor-parallel across both cards.

### 0.2 Get the code and build the core environment

```bash
git clone https://github.com/ctapnec/MLLMRiskBench.git
cd MLLMRiskBench
git checkout <frozen-commit>          # pin the exact revision used for the run
python3.12 -m venv .venv
source .venv/bin/activate             # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e ".[dev,analysis,api]"  # core + tests + figures + Anthropic/OpenAI/Gemini SDKs
```

`.[api]` installs `anthropic>=0.108,<1`, `openai>=2.45,<3`, and
`google-genai>=1,<2`. `.[analysis]` installs Matplotlib/pandas/pyarrow for the
figures and Parquet mirror. `.[dev]` installs pytest.

Optional extras, installed only if you use that feature:

```bash
pip install -e ".[guardrail]"   # transformers, for the Llama Guard 3 defense arm
pip install vllm                # local open-weight GPU targets (needs CUDA)
# Ollama: install the Ollama runtime and serve on http://localhost:11434
# promptfoo / other wrapped engines: install per docs/NATIVE_ENGINE_IMPORTS.md
```

### 0.3 Secrets and corpus paths (environment variables only)

Keep API keys **only** in the process environment or an approved secret manager.
Do not put them in commands, manifests, filenames, label spreadsheets, or
returned archives.

```bash
export ANTHROPIC_API_KEY="<key>"      # Fable endpoint + Anthropic judge
export OPENAI_API_KEY="<key>"         # gpt-5.6-sol Responses API
# only if used: GEMINI_API_KEY (or GOOGLE_API_KEY), DEEPSEEK_API_KEY,
# ZHIPU_API_KEY, MOONSHOT_API_KEY, DASHSCOPE_API_KEY, ARK_API_KEY
```

Released corpora are **not** redistributed in this repository. Each corpus name
passed to `--corpora` resolves its file from `URA_<NAME>_PATH` (uppercased); a
missing, empty, malformed, or schema-drifted corpus fails closed instead of
shrinking the run. Point each real source and any approved media root at its
release before preflight (values depend on the actual released layouts):

```bash
export URA_STRONGREJECT_PATH="<released-strongreject-path>"
export URA_MMSAFETY_PATH="<released-mmsafety-path>"
export URA_MOSSBENCH_PATH="<released-mossbench-path>"
export URA_RJUDGE_PATH="<released-rjudge-path>"
export URA_GPTGEOCHAT_PATH="<released-gptgeochat-path>"
export URA_MEDIA_ROOTS="<approved-media-root-list>"
```

### 0.3.1 Download and place each corpus

`--corpora` takes a converter name; that name uppercased is the env var
(`strongreject` -> `URA_STRONGREJECT_PATH`). Each converter validates the release
layout and **fails closed** on a missing, empty, malformed, or schema-drifted
input, so a wrong or partial download is caught before any paid call. URLs drift
over time; the authoritative identifier for every source is its citation key in
`references.bib`, and the load-bearing requirement is the **local layout** the
converter reads, given below. The five corpora used by the templates in this
runbook:

| `--corpora` | Env var | Source (verify against `references.bib`) | Get it | Point the env var at |
| --- | --- | --- | --- | --- |
| `strongreject` | `URA_STRONGREJECT_PATH` | StrongREJECT, Souly et al., NeurIPS 2024 D&B, arXiv:2402.10260 `[strongreject-2024]` | authors' release (resolve the current repository from the citation) | the StrongREJECT dataset **CSV file** (columns `category,source,forbidden_prompt`), not its containing directory |
| `mmsafety` | `URA_MMSAFETY_PATH` | MM-SafetyBench, Liu et al., ECCV 2024, arXiv:2311.17600 `[mmsafetybench-2024]` | `git clone https://github.com/isXinLiu/MM-SafetyBench`, then fetch its released `data/` and `imgs/` per the repo README | the benchmark root (the directory that contains `data/processed_questions/<Scenario>.json` and `data/imgs/<Scenario>/SD_TYPO/<id>.jpg`) |
| `mossbench` | `URA_MOSSBENCH_PATH` | MOSSBench, Li et al., ICLR 2025, arXiv:2406.17806 `[mossbench-2025]` | authors' release (GitHub / HuggingFace; first author Xirui Li) | the release **directory** (its `information.csv`/`metadata.csv` plus the image assets) or the metadata table file directly; every item requires a resolvable image |
| `rjudge` | `URA_RJUDGE_PATH` | R-Judge, Yuan et al., Findings EMNLP 2024, arXiv:2401.10019 `[rjudge-2024]` | `git clone https://github.com/Lordog/R-Judge` | the R-Judge **`data/` directory** (the converter recursively loads every `*.json` under it); not a single scenario file |
| `gptgeochat` | `URA_GPTGEOCHAT_PATH` | GPTGeoChat, Mendes et al., EMNLP 2024, arXiv:2407.04952 `[gptgeochat-2024]` | authors' released dataset (see the paper's linked repository) | the split **root** that contains an `annotations/` directory of `annotation_*.json` files with an `images/` directory beside it |

**Media roots.** The media-bearing corpora (`mmsafety`, `mossbench`,
`gptgeochat`) reference local image files, and the runner reads local media only
under an approved root. Add the directory that actually holds those images to
`URA_MEDIA_ROOTS` (MM-SafetyBench keeps them under `data/imgs`, MOSSBench beside
its table, GPTGeoChat under `images/`); otherwise the media preflight fails
closed. `strongreject` and `rjudge` are text-only and need no media root.

Concrete example once the releases are on disk (substitute the real filenames of
your download; `<...>` marks a name that depends on the release):

```bash
DATA=/path/to/corpora     # wherever you downloaded the releases
export URA_STRONGREJECT_PATH="$DATA/strongreject/strongreject_dataset/strongreject_dataset.csv"  # the CSV inside the repo's strongreject_dataset/ directory
export URA_MMSAFETY_PATH="$DATA/MM-SafetyBench"          # root with data/processed_questions + data/imgs
export URA_MOSSBENCH_PATH="$DATA/MOSSBench"              # release dir with information.csv (meta_data_over) + images
export URA_RJUDGE_PATH="$DATA/R-Judge/data"              # the data/ directory (recursively loaded)
export URA_GPTGEOCHAT_PATH="$DATA/GPTGeoChat/human/test" # a split root (e.g. human/test) with annotations/ + images/
export URA_MEDIA_ROOTS="$DATA/MM-SafetyBench/data/imgs:$DATA/MOSSBench:$DATA/GPTGeoChat/human/test"
```

Record the exact release, split/version, and file hashes in the freeze sheet; do
not silently substitute a mirror or a different split. To add any other supported
source, download it the same way and use its converter name as both the
`--corpora` token and the `URA_<NAME>_PATH` variable. The full set of converter
names is `rjudge, mmsafety, jailbreakv, gptgeochat, agentharm, strongreject,
bipia, harmbench, vlsbench, mossbench, siuo, advbench, jailbreakbench, figstep,
cyberseceval, injecagent, mllmguard, jalmbench, videosafetybench` (plus the
offline-only `synth`). Each module's docstring states its own expected layout
(for example `URA_ADVBENCH_PATH` at the AdvBench CSV, `URA_FIGSTEP_PATH` at the
FigStep template CSV). `agentharm`, `bipia`, `injecagent`, and the
CyberSecEval prompt-injection split are convertible inputs but are not executable
scored cells until their source runtimes are integrated; the preflight rejects
them before target calls.

### 0.4 Offline sanity (no keys, no GPU, no paid calls)

```bash
python -m pytest -q                                                               # suite passes (388 at the frozen commit; optional-dependency tests skip cleanly if that extra is absent)
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
python -m experiments.figures --synth --out runs/_figcheck                         # renders three watermarked illustrative placeholders
```

`synth` is generated in code for smoke tests only; its outputs are never
publishable measurements. If any of these fail, fix the environment before
spending a paid or GPU-backed call.

---

## 1. Freeze sheet

Before any paid or GPU-backed run, save a short run note (`RUNNOTE.md` at the
repo root) containing:

- repository commit and worktree state;
- exact target and judge endpoint/checkpoint IDs copied from the accounts/backends;
- provider account tier/region and UTC access date;
- data releases, splits, licenses, paths, counts, and media roots;
- `--corpora`, `--limit`, `--sample-seed`, `--seeds`, query/turn budgets, grouping, judges, and defense settings;
- hardware and local-serving details if local targets are added;
- primary comparisons, exclusions, stopping rule, and protocol amendments.

Replace every `<...>` token in the commands. Preserve the exact substituted
command in the run note. Do not invent a Sol-Pro slug or replace the canonical
`openai-responses:...` condition with standard Chat Completions.

---

## 2. Shakedown and live probes

Run the offline checks of Section 0.4 first. Then run a separately named, tiny
live probe for each exact target and the exact judge. Use the same physical
modalities planned for the main study. Verify authentication, request shape,
timeout/rate-limit behavior, output parsing, media transmission, effective seed
control, and manifest IDs before scaling.

The runner rejects unsupported image, audio, or video requirements before the
first call. Do not work around that failure by dropping media or inserting text
captions. Fix target registration or change the declared study scope.

Inspect console output. Target-construction failures write setup-phase
`*.error.json` records. Once a cell is established, an exception writes its own
`*.error.json` and may leave partial artifacts; retain them all. Any requested
failure makes the command exit nonzero even if other cells completed.

---

## 3. Runbook map

| Runbook | Protocol | Purpose | New calls? |
| --- | --- | --- | --- |
| R1 | E1, E2, E5, E6 | Main matched matrix: harmful/benign, static/adaptive, risk/modality views | Yes |
| R2 | E3 | Same-response per-stage judge sensitivity with abstention bounds | No; reads R1 trails and responses |
| R3 | E4 | Within-target explicit guardrail intervention | Yes |
| R4 | E7 | Exact static transfer | No; reads R1 judgments |
| R5 | E8 | Inter-judge kappa | No; reads R1 trails |
| R6 | E8 | Blinded multi-rater human audit | Human work; reads R1 artifacts |
| R7 | E9 | Fable-versus-GPT-5.6-Sol-Pro primary case | No separate calls if R1 contains the frozen pair |
| R8 | Phase 4 | Real-data figures and traceability audit | No model calls |

R2, R4, R5, and R8 need no model calls and no GPU; you may run them here or leave
them for me to run from the returned tree (see the division of labor above).

---

## 4. R1 - Main matched matrix

After successful live probes, execute the frozen command. This template uses full
released real corpora (`--limit 0`); change the sampling plan only before freeze
or through a logged amendment.

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay,crescendo --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mmsafety,mossbench --sample-seed 0 --limit 0 --seeds 0,1 --max-queries 4 --max-turns 4 --group model,risk,modality --out runs/fable-vs-gpt56-sol-pro
```

If a limited sample is required, choose and record `--limit N --sample-seed S`.
Real-corpus subsampling is deterministic and corpus-scoped, not first-N. Do not
confuse the corpus sampling seed with `--seeds`, which controls attack/target
repetitions.

R1 should supply:

- harmful ASR and desired-refusal rows, plus unconditional StrongREJECT-style rows only where the dedicated LLM rubric graded the complete harmful bucket;
- benign FRR rows from the benign source;
- risk- and modality-grouped rows where populations exist;
- response-conditioned conversation-ASR, robust-refusal, and turns-to-break data;
- static replay rows eligible for exact transfer;
- joinable attempts, responses, judgments, and shadow judge trails.

Do not add R-Judge or GPTGeoChat rows to common ASR/FRR, but do not discard them.
Run these source tracks with static replay and return their source-specific
result families: validity/all-output accuracy and valid-prediction classification
metrics for R-Judge and GPTGeoChat at all five location thresholds. Preserve the
disclosed R-Judge single-call-versus-serial-protocol limitation and the pending
risk-effectiveness score. AgentHarm, BIPIA, InjecAgent, and the CyberSecEval
prompt-injection split are registered/convertible inputs, but they are not
executable scored Runner cells until their respective source runtimes/evaluators
are integrated. The preflight rejects them before target calls. A zero
implementation-coverage row may be retained only as an offline/native-artifact
diagnostic; it is neither a completed run nor a zero performance score. Other
harmful CyberSecEval suites remain distinct and may be common-metric eligible
where their construct maps.

Run the integrated source-specific tracks separately:

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora rjudge,gptgeochat --sample-seed 0 --limit 0 --seeds 0,1 --group model,source --out runs/source-monitors
```

### Optional: adding a local open-weight target on the rig

The case study needs no local models. If you add an open-weight arm, serve it and
pass `--local backend:model` with a `--local-config` JSON that pins immutable
identity and modalities. The config keys must exactly match the selected `--local`
specs; each value carries an HF `revision` (40-hex commit) **or** a `model_digest`
(64-hex tree hash), never both, plus an explicit `modality_support` declaration.
See `src/ura/targets/local.py` and PROTOCOL.md for the full field list; do not run
a measured local cell without it (a bare `--local` with no config is rejected).
`--quantization` and `--dtype` control the vLLM load; Ollama serves on
`http://localhost:11434` by default.

---

## 5. R2 - Judge sensitivity

Uses the full-shadow R1 trails; every configured stage already judged the same
target response, so sensitivity requires no repeat provider calls and introduces
no target-response nondeterminism.

```bash
python experiments/judge_sensitivity.py --results runs/fable-vs-gpt56-sol-pro --attacker replay
```

Produces `judge_sensitivity.json`. The postprocessor refuses incomplete or
misjoined cells, verifies each stage's response SHA-256 and cascade lineage, and
reports parse, confidence-gate, and decision coverage. It treats low-confidence
and explicitly unparsed rows as abstentions, never as `safe`. Accordingly,
harmful ASR and benign FRR are lower/upper identification bounds unless stage
decision coverage is complete. The complete-case rate is diagnostic only. Never
treat any automated stage or the cascade as ground truth.

---

## 6. R3 - Explicit guardrail intervention

Run one target with and without one prespecified guard while holding everything
else fixed. The following template uses an input rule guard; use the defense mode
frozen in the protocol.

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mossbench --sample-seed 0 --limit "<frozen-defense-limit>" --seeds 0,1 --defense none --out runs/defense-comparison/control
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mossbench --sample-seed 0 --limit "<frozen-defense-limit>" --seeds 0,1 --defense input --defense-guard rules --out runs/defense-comparison/input
python experiments/paired_compare.py --results runs/defense-comparison --left-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --right-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --left-defense none --right-defense input --attacker replay
```

Produces `paired_comparison.json`. Estimate paired datapoint-cluster changes in
harmful ASR and benign FRR. The effect direction is control minus guarded for the
command above. Confirm exact shared unit counts and all unmatched/excluded units
before interpretation. Do not use the Fable-versus-GPT comparison as a substitute
for this intervention: the cross-provider contrast cannot identify a defense
effect. The script marks the intervention as conditionally eligible for causal
interpretation but never asserts that a causal effect has been established.

If the frozen intervention uses the model-backed guard instead of `rules`,
install `.[guardrail]`, select `--defense-guard guardrail`, and add
`--guardrail-model meta-llama/Llama-Guard-3-8B --guardrail-revision
"<exact-40-hex-hf-commit>" --guardrail-device cuda` to both commands. Record the
actual device/runtime environment. A branch, tag or omitted revision is rejected;
do not invent a commit for this template. An output that does not match the model
guard's explicit verdict grammar is a cell error, not pass, block or an imputed
safe decision.

**The `GuardrailJudge` (Llama Guard) guard is text-only** and rejects any dialog
carrying physical media before the target is queried, so the model-guard arm
cannot use an image corpus. Drop `mossbench` from `--corpora` for this arm and use
a text-only benign source paired with `strongreject`; `mossbench` stays only on
the `rules`-guard arm above (the rule guard does not reject media).

---

## 7. R4 - Exact static transfer

```bash
python experiments/transfer_matrix.py --results runs/fable-vs-gpt56-sol-pro
```

Produces `transfer_matrix.json` and, when Matplotlib is available,
`transfer_matrix.png`. Each A-to-B cell conditions on harmful, transferable source
successes with the same `transfer_key` and rendered-input fingerprint on B. Live
response-conditioned Crescendo attempts are marked non-transferable and excluded.
`null` plus a reason/support count is a valid no-estimand result; never rewrite it
as zero.

Also compute the separate paired endpoint contrast:

```bash
python experiments/paired_compare.py --results runs/fable-vs-gpt56-sol-pro --left-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --right-model "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --left-defense none --right-defense none --attacker replay
```

Produces `paired_comparison.json`. It reports left-minus-right ASR and benign
over-refusal differences only on exact shared datapoint-by-seed units, with paired
datapoint-cluster intervals and complete match/exclusion lineage. This is not
conditional transferability and cannot identify why providers differ. A `null`
effect with an explicit no-shared-unit status remains a valid no-estimand result.

---

## 8. R5 - Inter-judge agreement

```bash
python experiments/kappa.py --results runs/fable-vs-gpt56-sol-pro
```

Produces `judge_kappa.json`. The primary statistic is kappa on `violation` versus
`other`, pooled and by risk category, only where both stages made decisions.
Low-confidence/unparsed outputs are abstentions; the report records each stage's
decisions, abstentions, joint-decision support, one-sided decisions, and joint
abstentions. Exact four-label kappa is diagnostic. Degenerate or no-joint-decision
strata remain JSON `null` with a reason/coverage record.

---

## 9. R6 - Human calibration

Preparation exports potentially harmful content and requires explicit
acknowledgement:

```bash
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --prepare 100 --acknowledge-sensitive-content --output runs/fable-vs-gpt56-sol-pro/human_audit_sample.csv
```

The script also writes an instruction file. Keep automated labels hidden.
Duplicate every selected row for at least two independent qualified raters, fill
distinct `rater_id` values and valid labels, preserve all sampling fields, then
adjudicate unresolved disagreements after independent rating. Save the completed
file under a new name, for example `human_audit_labels.csv`.

```bash
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --labels runs/fable-vs-gpt56-sol-pro/human_audit_labels.csv
```

Return the prepared sampling record, completed multi-rater labels, instruction
file, and `human_audit.json` through an approved access-controlled channel. Report
inter-human agreement before automated-versus-consensus agreement. Per-stage
automated calibration uses actual stage decisions only and reports missing
predictions where that stage abstained; the cascade-authoritative series remains
separately identified. The unweighted stratified-sample metrics are not population
rates.

---

## 10. R7 - Fable versus GPT-5.6 Sol Pro case-study extraction

R7 is the prespecified paired contrast inside R1, not an independent
Fable-versus-Mythos run. Verify that:

- both exact account-visible target IDs appear in manifests;
- the same source datapoints, sample seed, attack seeds, budgets, judges, and physical assets were used;
- failed and unsupported cells are disclosed rather than dropped from denominators;
- marginal harmful ASR/StrongREJECT-style estimates and benign FRR retain separate supports;
- model differences use paired datapoint-cluster intervals on shared observations;
- cross-provider endpoint policy, deployment controls, versioning, and sampling differences are listed as non-identifiable causes.

Mythos belongs in the accompanying literature discussion, supported by Anthropic's
[Mythos overview](https://www.anthropic.com/claude/mythos) and [Fable/Mythos
documentation](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5).
State explicitly that access was unavailable, no Mythos calls were made, and any
future Mythos comparison requires a new versioned replication protocol.

---

## 11. R8 - Figures and traceability check

Only after inspecting completion/error status and running the analyses above:

```bash
python -m experiments.figures --model-results runs/fable-vs-gpt56-sol-pro --defense-results runs/defense-comparison --model-left "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --model-right "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --model-defense none --model-corpus strongreject --model-corpus mmsafety --defense-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --defense-left none --defense-right input --defense-corpus strongreject --defense-corpus mossbench --attacker replay --policy-label "<frozen-policy-label>" --multiplicity-family "<frozen-family>" --minimum-cell-n "<pilot-frozen-minimum-unique-clusters>" --out ../../Thesis-EN/diagrams/figures
```

Do not generate measured thesis figures from `runs/dry`. The command requires
separate model-comparison and same-base defense roots and explicit repeatable
corpus selectors; it does not pool corpora. Replace the policy, multiplicity and
minimum-support placeholders with the pilot-frozen choices. Do not remove an
illustrative label unless every plotted value traces to a complete real-run
artifact and `fig-v-provenance.json` contains no missing-cell substitution.

For each plotted/table value, retain the sidecar's source file, run ID, metric
population, paired and unique-cluster support, grouping, status and interval. Keep
`transfer_matrix.png` separate from the main figure generator's outputs unless the
thesis build deliberately copies it.

This step (and Sections 5, 7, 8) can be left to me: return the `runs/` tree and I
will render the figures and produce the numbers against the frozen policy labels.

---

## 12. Package and return to me

### 12.1 Finalize provenance

```bash
python -m pytest -q                          # confirm the code is unchanged and green
pip freeze > runs/ENV-freeze.txt             # exact resolved dependency set
git rev-parse HEAD > runs/COMMIT.txt         # exact commit
git status --short > runs/WORKTREE.txt       # worktree state (should be clean)
cp RUNNOTE.md runs/RUNNOTE.md                 # the freeze sheet and exact substituted commands
# also drop the full console logs for each run under runs/logs/
```

### 12.2 Preserve the entire `runs/` tree

For each planned cell, retain all files that exist:

| Suffix | Required use |
| --- | --- |
| `*.attempts.jsonl` | Exact rendered inputs, seeds, strategies, fingerprints, and transfer flags |
| `*.responses.jsonl` | Exact outputs, latency/token metadata, requested/resolved target identity, disclosed provider fingerprint, and effective sampling control |
| `*.jsonl` | Authoritative final judgments and downstream transfer provenance |
| `*.trails.jsonl` | All shadow verdicts plus stage confidence/parse/authority fields and the exact Response SHA-256 for sensitivity, kappa, and audit sampling |
| `*.results.jsonl` | Population-specific aggregates, support, intervals, and grouping |
| `*.manifest.json` | Run/config identity, exact requested configuration, realized target/ordered-judge identity inventory and digest, code/environment, corpus/media hashes, and counts |
| `*.checkpoint.jsonl` | Append-only exact-resume record; do not edit or deduplicate manually |
| `*.complete.json` | Proof that required success artifacts existed when the cell completed |
| `*.error.json` | Structured cell failure and completed-attempt count |
| `*.grid.json` | The driver grid request and per-cell config, including the driver source digest |

Also preserve, where produced: `transfer_matrix.json` (+ optional PNG),
`paired_comparison.json` for each contrast, `judge_sensitivity.json`,
`judge_kappa.json`, the environment freeze/commit/worktree/run-note, and the
console logs.

### 12.3 Package

```bash
tar --exclude='__pycache__' --exclude='*.pyc' -czf ura-return-<YYYYMMDD>.tgz runs
sha256sum ura-return-<YYYYMMDD>.tgz > ura-return-<YYYYMMDD>.sha256   # Windows: use Get-FileHash
```

Do not include API keys, `.env` files, or restricted benchmark assets in the
archive. The run artifacts can contain harmful prompts, model outputs,
personal/location content, and provider metadata; review them before transfer and
use an approved encrypted/access-controlled channel. Send the **human-audit**
content (sample, instruction file, completed labels, `human_audit.json`)
separately through the approved secure channel, not in the general archive.

### 12.4 Hand it back

Copy `ura-return-<YYYYMMDD>.tgz` and its `.sha256` to the machine where you talk
to me. Put it (or the unpacked `runs/` tree) somewhere I can read, e.g. under this
repo at `Project/MLLMRiskBench/runs/`, and tell me the path. Then I will:

1. verify the SHA-256 and confirm every `*.complete.json` has its artifact family;
2. reconstruct each completion marker's realized-identity digest from the
   response/trail artifacts and confirm no target/judge identity drift;
3. check manifest run IDs join to attempts/responses/judgments/trails/aggregates,
   and that corpus/media hashes match the freeze sheet;
4. run R2 (judge sensitivity), R4 (transfer), R5 (kappa), and R8 (figures)
   against the frozen policy/multiplicity labels;
5. produce the Chapter V numbers and figures, and flag any incomplete, failed,
   underpowered, or unsupported cell rather than imputing a value.

If you already ran the analyses, include their JSON outputs and I will
cross-check rather than recompute.

---

## 13. Completion audit

Before calling Chapter V measured, verify all of the following:

- no `<...>` placeholders remain in executed commands or manifests;
- each intended target specification is accounted for: completed cells have a matching complete marker and every setup/runtime failure has a retained error artifact;
- manifest run IDs match attempts, responses, judgments, trails, and aggregates;
- the completion marker's realized-identity digest matches a reconstruction from the response/trail artifacts, with no target or judge identity drift;
- corpus and media hashes match the frozen inputs;
- unsupported physical modalities failed before calls and were not converted to text;
- no missing population, transfer support, or undefined kappa was encoded as zero;
- judge sensitivity reused exact R1 responses, and low-confidence/unparsed stage outputs were bounded as abstentions rather than imputed as safe;
- ASR uses harmful probes, FRR uses benign probes, and StrongREJECT comes only from complete dedicated LLM-rubric coverage with refusals contributing zero;
- transfer includes static exact replay only and excludes live Crescendo;
- the human audit has at least two independent ratings per analysed item unless explicitly marked exploratory;
- R-Judge/GPTGeoChat source-specific results and protocol qualifications remain visible; AgentHarm/BIPIA/InjecAgent/CyberSecEval-prompt-injection are recorded as pre-call rejected pending integrations, never as completed zero-coverage runs;
- Mythos appears only as literature/external evidence, access limitation, and future replication;
- all claims in the thesis match retained code, configuration, artifacts, and measured support.
