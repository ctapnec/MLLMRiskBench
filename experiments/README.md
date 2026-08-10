# Experiments for Chapter V

The experiments are pending. This directory provides the execution and analysis path for Chapter V; no dry-run output, placeholder ID, or illustrative figure is evidence about a real model.

Use [PROTOCOL.md](PROTOCOL.md) for estimands and validity rules. Use [RUN_AND_RETURN.md](RUN_AND_RETURN.md) as the operator checklist once access, data, budget, and exact model IDs have been frozen.

## 1. Preflight

Before spending provider or GPU budget:

1. Record the commit, Python and package versions, run date, hardware/backend configuration, data licenses, and exact account-visible target and judge IDs.
2. Replace all angle-bracketed placeholders. Do not invent a convenient alias for an account-specific endpoint.
3. Put each real corpus at `URA_<CORPUS>_PATH`. Set `URA_MEDIA_ROOTS` to the approved roots containing local media.
4. Probe each target on a few benign and harmful items and verify the requested physical modalities. Unsupported image, audio, or video cells fail before the first model call; there is no text fallback.
5. Confirm that a real `--judge-model` is configured for any run using the `llm` judge. The offline mock judge is suitable only for plumbing tests.
6. If a run selects the `guardrail` judge or defense, install `.[guardrail]`, freeze its exact Hugging Face repository id and 40--64-hex commit, and pass them with `--guardrail-model` and `--guardrail-revision`; optionally freeze `--guardrail-device`. A tag, branch or omitted revision is not admissible.
7. Inspect console warnings and every `*.error.json`; a partial matrix must be reported as partial.

Install only the extras required by the chosen backends:

```bash
python -m pip install -e ".[dev,analysis,api]"
python -m pytest
```

Local vLLM/Ollama and guardrail dependencies are deliberately not hard requirements. The `guardrail` extra installs the bounded Torch, Transformers and Accelerate backend; install and freeze it only if that path is part of the registered protocol.

The commands below the preflight are written for a shell launched from the
Project root. On the Windows rig, set corpus/media paths and load keys in the
current PowerShell process as follows; replace paths, but never paste secret
values into a command, configuration file, run name, log, or commit:

```powershell
$env:URA_STRONGREJECT_PATH = 'D:\datasets\strongreject'
$env:URA_MMSAFETY_PATH = 'D:\datasets\mm-safetybench'
$env:URA_MOSSBENCH_PATH = 'D:\datasets\mossbench'
$env:URA_MEDIA_ROOTS = 'D:\datasets\mm-safetybench;D:\datasets\mossbench'
$env:ANTHROPIC_API_KEY = (Get-Content -Raw '<approved-anthropic-secret-file>').Trim()
$env:OPENAI_API_KEY = (Get-Content -Raw '<approved-openai-secret-file>').Trim()
```

Use the corresponding approved secret-store command instead of `Get-Content`
where one is available. POSIX shells use `export NAME='value'` and join media
roots with `:` rather than PowerShell's `;`.

## 2. Offline shakedown

```bash
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
```

This checks corpus conversion, strict modality handling, lineage, aggregation, checkpointing, and persistence with `MockTarget`. It is not a scored pilot and must not feed a thesis result table.

## 3. Planned Fable versus GPT-5.6 Sol Pro case

After small live probes succeed, run the account-visible Fable endpoint and the
frozen OpenAI Responses condition. One compact template is:

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay,crescendo --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mmsafety,mossbench --sample-seed 0 --limit 0 --seeds 0,1 --max-queries 4 --max-turns 4 --group model,risk,modality --out runs/fable-vs-gpt56-sol-pro
```

The exact corpus set, sample size, seeds, budgets, and judge must be preregistered or frozen in the run notes before the main run. `--limit 0` means all records for real corpora. For a limited real-corpus run, `--limit N --sample-seed S` makes a deterministic corpus-scoped subsample; it is not first-N selection. `--seeds` controls repeated attack/target runs and is distinct from `--sample-seed`.

The comparison is matched at the probe/protocol level but crosses providers. It cannot isolate a safety intervention, cannot be called a same-base ablation, and must report endpoint, policy, system-prompt, sampling-control, and provider-version differences as possible explanations.

For the OpenAI arm, `gpt-5.6-sol` is the model ID and Pro is the Responses
`reasoning.mode`, not a separate endpoint slug. The canonical target string also
freezes medium effort and `current_turn` reasoning context; ordinary
`openai:gpt-5.6-sol` is a different Chat Completions condition and is not an
admissible substitute.

## 4. Mythos: literature boundary and future replication

Claude Mythos is prominently relevant because Anthropic describes it as a frontier cybersecurity model. It informs the thesis discussion of specialized security capability, dual-use risk, deployment controls, access concentration, and evaluation of frontier security systems. It is supported as external literature by Anthropic's [Mythos overview](https://www.anthropic.com/claude/mythos) and [Fable/Mythos documentation](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5).

There is no Mythos access for this study. Therefore:

- Mythos is not an executable target or a row in the measured roster;
- there is no Fable-versus-Mythos run, effect estimate, or empirical claim;
- references to Mythos in Chapter V must say external evidence, access limitation, or future replication;
- if access becomes available later, it requires a new preflight, frozen endpoint, protocol amendment, and separately labelled replication.

## 5. Real corpora and construct eligibility

`run_matrix.py` locates a selected corpus through `URA_<NAME>_PATH` and rejects missing or malformed data. Converter availability does not by itself make every source eligible for the same estimand.

| Source class | Common-metric use | Required qualification |
| --- | --- | --- |
| Harmful chat/jailbreak sets such as StrongREJECT, HarmBench, AdvBench, JailbreakBench, MM-SafetyBench, JailbreakV, VLSBench, SIUO, FigStep, and compatible MLLMGuard rows | Harmful ASR/refusal/StrongREJECT-style analysis, subject to source and modality checks | Preserve source split, prompt, media, expected behavior, and licensing; do not merge missing cells into zero |
| Benign sets such as MOSSBench and benign source splits | FRR/over-refusal | Never include in harmful ASR denominators |
| R-Judge | Source-specific first-class track; not common ASR/FRR | With static replay, emit validity/all-output accuracy and valid-prediction F1/recall/specificity/precision/accuracy. The current single-call analysis-plus-label protocol is disclosed as a deviation from the released serial two-call recipe; open-ended risk-identification effectiveness remains pending |
| GPTGeoChat | Source-specific first-class track; not common ASR/FRR | With static replay, emit validity/all-output accuracy and valid-prediction binary metrics separately at country, city, neighborhood, exact-location-name, and exact-GPS thresholds; cluster by conversation |
| CyberSecEval prompt-injection split | Registered/convertible source-specific judge-question representation; not executable as a scored Runner cell yet | Retain the system/user task and released judge question. Scored execution fails before target calls until a substantive task-success/injection-following evaluator is integrated. Other harmful CyberSecEval suites remain separately eligible for common metrics |
| AgentHarm | Registered/convertible prompt-and-tool-requirements representation; not executable as a scored Runner cell yet | Integrate the interactive tool runtime and grading function before scored execution; prompt conversion alone does not implement the source construct |
| InjecAgent | Registered/convertible poisoned-observation representation; not executable as a scored Runner cell yet | Integrate the agent/tool runtime and source scorer before scored execution; static conversion alone is not official ASR |
| BIPIA | Registered/convertible context/attack representation; not executable as a scored Runner cell yet | Preserve the exact join, but integrate the required indirect-injection task-success evaluator before scored execution |
| JALMBench / Video-SafetyBench | Audio/video only on supporting targets | Unsupported physical modality rejects the cell before calls |

Local and inline media is hash-verified. Local reads are disabled unless the containing directories are allowlisted through `URA_MEDIA_ROOTS` (or explicit target media roots). Although low-level target clients can accept absolute HTTPS media, scored Runner cells reject remote references because provider-fetched bytes cannot be verified against the manifest; materialize them under an approved root or use a hashed inline data URI.

## 6. Artifacts

For each planned `<corpus, target, attacker, configuration>` cell, retain the entire run-ID-bearing artifact family:

| Suffix | Meaning |
| --- | --- |
| `*.attempts.jsonl` | Exact rendered attempts and attack provenance |
| `*.responses.jsonl` | Joinable target responses and sampling-control provenance |
| `*.jsonl` | Final authoritative judgments |
| `*.trails.jsonl` | Shadow verdict, parse/confidence/authority metadata, and exact Response SHA-256 from every judge stage |
| `*.results.jsonl` | Grouped metrics, population, support, and intervals |
| `*.manifest.json` | Run/config identity, requested configuration, realized target/ordered-judge identity inventory, data/media hashes, environment, and counts |
| `*.checkpoint.jsonl` | Append-only completed-attempt records used for exact resume |
| `*.complete.json` | Success marker written only when required artifacts exist |
| `*.error.json` | Structured target-setup or established-cell failure record; partial snapshots may accompany it |

Target construction failures and failures inside established cells write explicit error artifacts. The driver exits nonzero if any requested target or cell fails, even when other cells complete. Never infer that absent output means zero risk or a successful skip.

A matching completion marker prevents repeat calls. A matching checkpoint resumes without re-querying completed attempts, including the saved responses required to continue a response-conditioned session. Realized provider/model/fingerprint/revision identities are recomputed across restored and new evidence; drift fails the cell. The completion marker binds the SHA-256 of the manifest identity inventory, which postprocessors verify against the hashed response and trail artifacts.

## 7. Post-processing

Generate these only from complete, inspected real-run artifacts:

```bash
python experiments/kappa.py --results runs/fable-vs-gpt56-sol-pro
python experiments/judge_sensitivity.py --results runs/fable-vs-gpt56-sol-pro --attacker replay
python experiments/transfer_matrix.py --results runs/fable-vs-gpt56-sol-pro
python experiments/paired_compare.py --results runs/fable-vs-gpt56-sol-pro --left-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --right-model "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attacker replay
python -m experiments.figures --model-results runs/fable-vs-gpt56-sol-pro --defense-results runs/defense-comparison --model-left "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --model-right "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --model-defense none --model-corpus strongreject --model-corpus mmsafety --defense-model "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000" --defense-left none --defense-right input --defense-corpus strongreject --defense-corpus mossbench --attacker replay --policy-label "<frozen-policy-label>" --multiplicity-family "<frozen-family>" --minimum-cell-n "<pilot-frozen-minimum-unique-clusters>" --out ../../Thesis-EN/diagrams/figures
```

The figure command keeps the model and same-base defense experiments in
separate roots. Every `--model-corpus` and `--defense-corpus` is explicit and
remains a separate facet; the renderer does not pool corpora. Replace all three
angle-bracketed values with the pilot-frozen analysis choices. It writes the
three retained PNG names plus `fig-v-provenance.json`, which records the
estimands, selectors, support/status and source-cell lineage.

The transfer script estimates target-model violation conditional on a harmful static input that violated the source model and has the same `transfer_key` and rendered-input fingerprint on both models. Non-transferable live Crescendo rows are excluded. Empty transfer support is serialized as `null` with a reason and counts, never as zero.

`judge_sensitivity.py` makes no provider calls. It reads completion-validated R1 responses and full-shadow trails, verifies that each stage row is bound to the exact Response SHA-256, and reports per-stage parse, confidence-gate, and decision coverage. Low-confidence or explicitly unparsed outputs are abstentions even if their placeholder label is `safe`; harmful ASR and benign FRR are therefore reported as identification bounds unless all relevant units receive stage decisions.

`kappa.py` likewise excludes stage abstentions from its joint-decision agreement
cohort and reports decision/abstention support for both stages. Human calibration
scores each shadow stage only where it made an actual decision; missing stage
predictions remain visible in coverage, while the final `cascade_authoritative`
series is reported separately.

`paired_compare.py` is the prespecified contrast path. It reads only integrity-checked completed cells, requires compatible manifests, and reports `left - right` changes in harmful ASR and benign over-refusal on exact shared `datapoint_id × requested seed` units. Static units additionally require the same `transfer_key` and rendered-input fingerprint. Live response-conditioned runs use one bounded conversation per datapoint and seed; their arm-specific transcripts are not called identical. The JSON records every matched, unmatched, common-ineligible, and input-mismatch unit plus run IDs, source files, configuration signatures, and the paired datapoint-cluster bootstrap interval. Cross-target/provider results remain non-causal endpoint comparisons. A same-`model_spec` defense contrast must also have identical normalized planned base-target components; conflicting jointly observed realized provider/model identity fields reject it. If an input guard blocks every request in one arm, the comparison may proceed from the identical planned base but is explicitly marked `unobserved_planned_same_base_only`, with no claim that realized base identity equality was observed. The script never declares that a causal effect has been established. Experiments and estimates remain pending until real completed artifacts are supplied.

Human calibration is deliberately two-step:

```bash
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --prepare 100 --acknowledge-sensitive-content --output runs/fable-vs-gpt56-sol-pro/human_audit_sample.csv
python experiments/human_audit.py --results runs/fable-vs-gpt56-sol-pro --labels runs/fable-vs-gpt56-sol-pro/human_audit_labels.csv
```

Duplicate each sampled row for independent labelling by at least two qualified raters, preserve the sampling fields, and adjudicate unresolved disagreements only after independent labels. The CSV contains potentially harmful model interactions and must remain access-controlled.

## 8. Interpretation gates

- Report ASR only on harmful probes and FRR only on benign probes, each with its own `n`.
- Include refusals as zero in the unconditional harmful StrongREJECT-style mean; emit it only from complete dedicated LLM-rubric coverage, never from a rule/guardrail confidence score.
- Report static `ASR` per attempt and live `conversation_ASR` per bounded conversation; never pool live turns into an attempt denominator.
- Report the implemented R-Judge and GPTGeoChat source metrics in their own tables. AgentHarm, BIPIA, InjecAgent, and the CyberSecEval prompt-injection split fail scored Runner preflight until their required source runtimes/evaluators are integrated. A zero implementation-coverage row is an offline/native-artifact diagnostic only, not a completed run or a zero performance score.
- Report datapoint-cluster intervals and paired clustered differences for planned matched comparisons.
- Treat an undefined kappa, a missing population, a failed cell, and a measured zero as distinct.
- Record exact model and judge IDs, effective seed control, corpus/media hashes, access date, and all deviations.
- Keep synthetic/dry-run figures visibly illustrative. Only the measured `python -m experiments.figures` interface with separate validated model/defense roots may replace thesis placeholders.
- Treat standards mappings as informational crosswalks, not certification or compliance results.
