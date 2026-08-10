# Run-and-return checklist

Use this checklist after [PROTOCOL.md](PROTOCOL.md) has been frozen. The experiments are pending. Returning a dry run, a partial artifact family without its error record, or files produced with placeholder IDs is not sufficient for Chapter V.

The default output name below is `runs/fable-vs-gpt56-sol-pro`. The planned comparison is an exact account-visible Claude Fable endpoint versus the public `gpt-5.6-sol` model through the Responses API with Pro mode, medium effort, and current-turn reasoning context. It is cross-provider and non-causal; it is not a same-base defense ablation.

Mythos is not a run target. The researcher lacks access. Preserve Mythos in the thesis as Anthropic's frontier cybersecurity model, external evidence, an access/governance limitation, and a future replication target. Do not create a Mythos row, placeholder measurement, or executable alias.

## 0. Freeze sheet

Before any paid or GPU-backed run, save a short run note containing:

- repository commit and worktree state;
- exact target and judge endpoint/checkpoint IDs copied from the accounts/backends;
- provider account tier/region and UTC access date;
- data releases, splits, licenses, paths, counts, and media roots;
- `--corpora`, `--limit`, `--sample-seed`, `--seeds`, query/turn budgets, grouping, judges, and defense settings;
- hardware and local-serving details if local targets are added;
- primary comparisons, exclusions, stopping rule, and protocol amendments.

Replace every `<...>` token in the commands. Preserve the exact substituted command in the run note. Do not invent a Sol-Pro slug or replace the canonical `openai-responses:...` condition with standard Chat Completions.

Set corpus paths and local-media roots before preflight. Example variable names are shown; values depend on the actual released layouts:

```bash
export URA_STRONGREJECT_PATH="<released-strongreject-path>"
export URA_MMSAFETY_PATH="<released-mmsafety-path>"
export URA_MOSSBENCH_PATH="<released-mossbench-path>"
export URA_MEDIA_ROOTS="<approved-media-root-list>"
```

Keep API keys only in the process environment or an approved secret manager. Do not put them in commands, manifests, filenames, label spreadsheets, or returned archives.

## 1. Shakedown and live probes

Run the offline checks first:

```bash
python -m pytest
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
```

Then run a separately named, tiny live probe for each exact target and the exact judge. Use the same physical modalities planned for the main study. Verify authentication, request shape, timeout/rate-limit behavior, output parsing, media transmission, effective seed control, and manifest IDs before scaling.

The runner rejects unsupported image, audio, or video requirements before the first call. Do not work around that failure by dropping media or inserting text captions. Fix target registration or change the declared study scope.

Inspect console output. Target-construction failures write setup-phase `*.error.json` records. Once a cell is established, an exception writes its own `*.error.json` and may leave partial artifacts; retain them all. Any requested failure makes the command exit nonzero even if other cells completed.

## 2. Runbook map

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

## 3. R1 - Main matched matrix

After successful live probes, execute the frozen command. This template uses full released real corpora (`--limit 0`); change the sampling plan only before freeze or through a logged amendment.

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay,crescendo --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mmsafety,mossbench --sample-seed 0 --limit 0 --seeds 0,1 --max-queries 4 --max-turns 4 --group model,risk,modality --out runs/fable-vs-gpt56-sol-pro
```

If a limited sample is required, choose and record `--limit N --sample-seed S`. Real-corpus subsampling is deterministic and corpus-scoped, not first-N. Do not confuse the corpus sampling seed with `--seeds`, which controls attack/target repetitions.

R1 should supply:

- harmful ASR and desired-refusal rows, plus unconditional StrongREJECT-style rows only where the dedicated LLM rubric graded the complete harmful bucket;
- benign FRR rows from the benign source;
- risk- and modality-grouped rows where populations exist;
- response-conditioned conversation-ASR, robust-refusal, and turns-to-break data;
- static replay rows eligible for exact transfer;
- joinable attempts, responses, judgments, and shadow judge trails.

Do not add R-Judge or GPTGeoChat rows to common ASR/FRR, but do not discard
them. Run these source tracks with static replay and return their source-specific
result families: validity/all-output accuracy and valid-prediction classification
metrics for R-Judge and GPTGeoChat at all five location thresholds. Preserve the disclosed R-Judge
single-call-versus-serial-protocol limitation and the pending risk-effectiveness
score. AgentHarm, BIPIA, InjecAgent, and the CyberSecEval prompt-injection split
are registered/convertible inputs, but they are not executable scored Runner
cells until their respective source runtimes/evaluators are integrated. The
preflight rejects them before target calls. A zero implementation-coverage row
may be retained only as an offline/native-artifact diagnostic; it is neither a
completed run nor a zero performance score. Other harmful CyberSecEval suites
remain distinct and may be common-metric eligible where their construct maps.

Run the integrated source-specific tracks separately:

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora rjudge,gptgeochat --sample-seed 0 --limit 0 --seeds 0,1 --group model,source --out runs/source-monitors
```

## 4. R2 - Judge sensitivity

Use the full-shadow R1 trails. Every configured stage already judged the same target response, so sensitivity requires no repeat provider calls and introduces no target-response nondeterminism.

```bash
python experiments/judge_sensitivity.py --results runs/fable-vs-gpt56-sol-pro --attacker replay
```

Return `judge_sensitivity.json`. The postprocessor refuses incomplete or misjoined cells, verifies each stage's response SHA-256 and cascade lineage, and reports parse, confidence-gate, and decision coverage. It treats low-confidence and explicitly unparsed rows as abstentions, never as `safe`. Accordingly, harmful ASR and benign FRR are lower/upper identification bounds unless stage decision coverage is complete. The complete-case rate is diagnostic only. Never treat any automated stage or the cascade as ground truth.

## 5. R3 - Explicit guardrail intervention

Run one target with and without one prespecified guard while holding everything else fixed. The following is a template using an input rule guard; use the defense mode frozen in the protocol.

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mossbench --sample-seed 0 --limit "<frozen-defense-limit>" --seeds 0,1 --defense none --out runs/defense-comparison/control
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --attackers replay --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mossbench --sample-seed 0 --limit "<frozen-defense-limit>" --seeds 0,1 --defense input --defense-guard rules --out runs/defense-comparison/input
python experiments/paired_compare.py --results runs/defense-comparison --left-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --right-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --left-defense none --right-defense input --attacker replay
```

Return `paired_comparison.json`. Estimate paired datapoint-cluster changes in harmful ASR and benign FRR. The effect direction is control minus guarded for the command above. Confirm exact shared unit counts and all unmatched/excluded units before interpretation. Do not use the Fable-versus-GPT comparison as a substitute for this intervention: the cross-provider contrast cannot identify a defense effect. The script marks the intervention as conditionally eligible for causal interpretation but never asserts that a causal effect has been established.

If the frozen intervention uses the model-backed guard instead of `rules`,
install `.[guardrail]`, select `--defense-guard guardrail`, and add
`--guardrail-model meta-llama/Llama-Guard-3-8B --guardrail-revision
"<exact-40-hex-hf-commit>" --guardrail-device cuda` to both commands. Record the
actual device/runtime environment. A branch, tag or omitted revision is rejected;
do not invent a commit for this template. An output that does not match the
model guard's explicit verdict grammar is a cell error, not pass, block or an
imputed safe decision.

## 6. R4 - Exact static transfer

```bash
python experiments/transfer_matrix.py --results runs/fable-vs-gpt56-sol-pro
```

Return `transfer_matrix.json` and, when Matplotlib is available, `transfer_matrix.png`. Each A-to-B cell conditions on harmful, transferable source successes with the same `transfer_key` and rendered-input fingerprint on B. Live response-conditioned Crescendo attempts are marked non-transferable and excluded. `null` plus a reason/support count is a valid no-estimand result; never rewrite it as zero.

Also compute the separate paired endpoint contrast:

```bash
python experiments/paired_compare.py --results runs/fable-vs-gpt56-sol-pro --left-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --right-model "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --left-defense none --right-defense none --attacker replay
```

Return `paired_comparison.json`. It reports left-minus-right ASR and benign over-refusal differences only on exact shared datapoint-by-seed units, with paired datapoint-cluster intervals and complete match/exclusion lineage. This is not conditional transferability and cannot identify why providers differ. A `null` effect with an explicit no-shared-unit status remains a valid no-estimand result.

## 7. R5 - Inter-judge agreement

```bash
python experiments/kappa.py --results runs/fable-vs-gpt56-sol-pro
```

Return `judge_kappa.json`. The primary statistic is kappa on `violation` versus `other`, pooled and by risk category, only where both stages made decisions. Low-confidence/unparsed outputs are abstentions; the report records each stage's decisions, abstentions, joint-decision support, one-sided decisions, and joint abstentions. Exact four-label kappa is diagnostic. Degenerate or no-joint-decision strata remain JSON `null` with a reason/coverage record.

## 8. R6 - Human calibration

Preparation exports potentially harmful content and requires explicit acknowledgement:

```bash
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --prepare 100 --acknowledge-sensitive-content --output runs/fable-vs-gpt56-sol-pro/human_audit_sample.csv
```

The script also writes an instruction file. Keep automated labels hidden. Duplicate every selected row for at least two independent qualified raters, fill distinct `rater_id` values and valid labels, preserve all sampling fields, then adjudicate unresolved disagreements after independent rating. Save the completed file under a new name, for example `human_audit_labels.csv`.

```bash
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --labels runs/fable-vs-gpt56-sol-pro/human_audit_labels.csv
```

Return the prepared sampling record, completed multi-rater labels, instruction file, and `human_audit.json` through an approved access-controlled channel. Report inter-human agreement before automated-versus-consensus agreement. Per-stage automated calibration uses actual stage decisions only and reports missing predictions where that stage abstained; the cascade-authoritative series remains separately identified. The unweighted stratified-sample metrics are not population rates.

## 9. R7 - Fable versus GPT-5.6 Sol Pro case-study extraction

R7 is the prespecified paired contrast inside R1, not an independent Fable-versus-Mythos run. Verify that:

- both exact account-visible target IDs appear in manifests;
- the same source datapoints, sample seed, attack seeds, budgets, judges, and physical assets were used;
- failed and unsupported cells are disclosed rather than dropped from denominators;
- marginal harmful ASR/StrongREJECT-style estimates and benign FRR retain separate supports;
- model differences use paired datapoint-cluster intervals on shared observations;
- cross-provider endpoint policy, deployment controls, versioning, and sampling differences are listed as non-identifiable causes.

Mythos belongs in the accompanying literature discussion, supported by Anthropic's [Mythos overview](https://www.anthropic.com/claude/mythos) and [Fable/Mythos documentation](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5). State explicitly that access was unavailable, no Mythos calls were made, and any future Mythos comparison requires a new versioned replication protocol.

## 10. R8 - Figures and traceability check

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
population, paired and unique-cluster support, grouping, status and interval.
Keep `transfer_matrix.png` separate from the main figure generator's outputs
unless the thesis build deliberately copies it.

## 11. What to preserve and return

Preserve the entire `runs/` tree and the exact console logs. For each planned cell, retain all files that exist:

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

Also preserve:

- `transfer_matrix.json` and optional PNG;
- `paired_comparison.json` for each prespecified target or defense contrast;
- `judge_sensitivity.json` with stage coverage and abstention bounds;
- `judge_kappa.json`;
- the human-audit sample, instruction file, completed multi-rater labels, and `human_audit.json`;
- the frozen run note, protocol amendments, exact commands, dependency lock/freeze, and console logs;
- figure-generation logs and generated real-data figures.

The run artifacts can contain harmful prompts, model outputs, personal/location content, and provider metadata. Review them before transfer and use an approved encrypted/access-controlled channel. Do not publish secrets or restricted benchmark assets.

## 12. Completion audit

Before calling Chapter V measured, verify all of the following:

- no `<...>` placeholders remain in executed commands or manifests;
- each intended target specification is accounted for: completed cells have a matching complete marker and every setup/runtime failure has a retained error artifact;
- manifest run IDs match attempts, responses, judgments, trails, and aggregates;
- the completion marker's realized-identity digest matches a reconstruction from
  the response/trail artifacts, with no target or judge identity drift;
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
