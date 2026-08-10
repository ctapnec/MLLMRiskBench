# URA-Bench

URA-Bench is the research software accompanying the master's thesis *A Risk-Assessment System for Question Answering by Multimodal Language Models*. It converts heterogeneous safety corpora to one typed schema, generates static or response-conditioned attacks, calls hosted or local targets, shadow-scores responses with multiple judges, and persists the lineage needed for later audit.

The experiment results are pending. This repository contains an implementation and an experimental protocol; it does not yet establish a model ranking, a defense effect, a compliance finding, or any other empirical result.

## What is measured

The common estimands keep harmful and benign populations separate:

- attack success rate (ASR) and desired-refusal rate use harmful probes; the StrongREJECT-style score is emitted only when every harmful item in the bucket has a dedicated LLM-rubric grade;
- false-refusal/over-refusal rate (FRR) uses benign probes;
- conversation ASR, robust refusal, and Kaplan-Meier turns-to-break summarize bounded live response-conditioned conversations, never static replay or pooled turns;
- uncertainty uses datapoint-cluster bootstrap intervals so seeds, variants, and turns from one source item are not treated as independent;
- transfer analysis is restricted to harmful, static, exactly replayed inputs with matching fingerprints. Live response-conditioned Crescendo conversations are excluded.

An aggregate row is omitted when its estimand population is empty. Missing support, an undefined kappa, and an observed rate of zero are different states and are not collapsed.

See [docs/METRICS.md](docs/METRICS.md), [docs/SCHEMA.md](docs/SCHEMA.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ATTACK_TAGS.md](docs/ATTACK_TAGS.md), and [docs/NATIVE_ENGINE_IMPORTS.md](docs/NATIVE_ENGINE_IMPORTS.md).

## Install and run an offline smoke test

Python 3.12 is the supported baseline. The core package requires Pydantic; provider, local-inference, guardrail, and analysis dependencies are optional.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
```

The dry run uses `MockTarget`. It checks plumbing and artifacts only; its outputs are not thesis measurements.

If a registered run uses the Hugging Face guardrail judge or defense, install
the complete optional backend and pin the model to an immutable repository
commit:

```bash
python -m pip install -e ".[guardrail]"
python experiments/run_matrix.py ... --judges rules,guardrail,llm --guardrail-model meta-llama/Llama-Guard-3-8B --guardrail-revision "<exact-40-hex-hf-commit>" --guardrail-device cuda
```

`--guardrail-revision` is mandatory whenever the guardrail backend is selected;
the model id, commit and device are retained in the grid/cell configuration and
component provenance. Do not replace the commit with `main`, a tag, or a moving
model alias.

## Target identity and the planned comparison

Publishable runs freeze the exact endpoint IDs visible in the researcher's provider accounts. Prefer `provider:exact-id` target specifications. Bare IDs exist only for a small conservative registry and must never be used to guess a preview or account-specific endpoint.

The planned case study is:

```bash
python experiments/run_matrix.py --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" --attackers replay,crescendo --judges rules,llm --judge-model "anthropic:<exact-account-visible-judge-id>" --corpora strongreject,mmsafety,mossbench --sample-seed 0 --limit 0 --seeds 0,1 --out runs/fable-vs-gpt56-sol-pro
```

This is a matched cross-provider comparison, not a same-base-model defense ablation and not a causal estimate of a safety mechanism. Replace only the angle-bracketed judge ID with the exact account-visible judge endpoint. The Fable condition selects the public `claude-fable-5` model, explicitly freezes adaptive thinking at high effort and a 25,000-token output ceiling, and omits unsupported temperature control. The OpenAI condition selects the public `gpt-5.6-sol` model through the Responses API and freezes Pro mode, medium effort, and current-turn reasoning context. Confirm live access to both arms in preflight and preserve requested and returned settings in the manifests. Runner 2.0 normalizes every reported target and ordered judge-stage provider/model/fingerprint/revision identity; a conflicting non-null value within a cell or across checkpoint resume fails the cell instead of silently mixing deployments.

### Why Mythos remains central but is not executable here

Anthropic presents Claude Mythos as a frontier cybersecurity model. It is therefore important to the thesis's account of frontier security specialization, capability-risk trade-offs, access concentration, and evaluation governance. The thesis uses Mythos as literature and external evidence, based on Anthropic's [Mythos overview](https://www.anthropic.com/claude/mythos) and [Fable/Mythos model documentation](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5).

The researcher does not have Mythos access. Mythos is consequently not registered as an executable experiment target, is not part of the measured roster, and must not appear in result tables as a tested system. It remains a clearly labelled future replication target if access later becomes available. The executable case study is Fable versus GPT-5.6 Sol Pro, with the non-causal cross-provider limitation above.

## Corpora and media

Real corpora are selected with `--corpora` and located through `URA_<CORPUS>_PATH`. `--limit N --sample-seed S` selects a deterministic, corpus-scoped subset of real data without first-N bias; `--seeds` controls attack/target repetitions and is a separate choice.

Local media is content-addressed and confined to explicit roots. Set `URA_MEDIA_ROOTS` to the approved corpus/media directories before a live multimodal run, separating multiple roots with the operating system path separator (`;` on Windows, `:` on POSIX). Missing corpus files, missing media, path escapes, hash mismatches, and malformed source layouts fail explicitly.

The runner checks physical modalities before the first target call. A target that lacks required image, audio, or video support causes that cell to fail; URA-Bench does not silently turn a multimodal intervention into text-only input.

Some converters preserve source constructs that require their own estimands. They
remain first-class experiment tracks; exclusion from a common ASR denominator is
construct isolation, not exclusion from URA-Bench:

- R-Judge emits strict safety-label validity and all-output accuracy, plus F1,
  recall, specificity, precision, and accuracy conditional on valid parsed
  predictions. Its open-ended risk-identification effectiveness score remains
  pending because no validated external scorer is configured;
- GPTGeoChat emits binary moderation metrics separately at country, city,
  neighborhood, exact-location-name, and exact-GPS thresholds, using the released
  at-or-finer ground-truth rule and conversation-cluster intervals;
- CyberSecEval's prompt-injection split is registered and convertible with its
  released judge question, but is not an executable scored Runner cell until a
  substantive task-success/injection-following evaluator is integrated. Other
  harmful CyberSecEval suites remain separately eligible for common metrics;
- AgentHarm is registered as a prompt-and-tool-requirements representation, but
  cannot be executed as a scored Runner cell until its interactive tool runtime
  and grading function are integrated;
- InjecAgent preserves a static poisoned tool observation, but cannot be
  executed as a scored Runner cell until its agent/tool runtime and source scorer
  are integrated;
- BIPIA preserves the released context/attack join, but cannot be executed as a
  scored Runner cell until the required indirect-injection task-success evaluator
  is integrated.

The scored Runner fails these four pending source families before any target
call; conversion support is not scoring support. Offline or native-artifact
analysis may retain an explicit `source_metric_implementation_coverage=0`
diagnostic so pending work does not disappear, but that row is not evidence of a
completed run and is not a zero performance score.

The registered source-specific classification condition uses static `replay`.
Applying Crescendo or another attack adapter would change the source construct,
so such cells fail preflight instead of being pooled with benchmark results.

## Artifacts and resume behavior

Each planned matrix cell uses a run-ID-bearing, collision-safe filename stem and can produce:

- `*.attempts.jsonl`, `*.responses.jsonl`, final judgment `*.jsonl`, and `*.trails.jsonl`;
- grouped `*.results.jsonl` and `*.manifest.json`;
- append-only `*.checkpoint.jsonl` for exact resume;
- `*.complete.json` only after all required success artifacts exist;
- `*.error.json` for target-setup or established-cell failures, plus any safely persisted partial artifacts.

The matrix driver exits nonzero if any requested target or cell fails; completed sibling cells remain available but the run must be reported as partial.

A target-construction failure is recorded in a setup-phase error artifact rather than silently omitted. A matching completion marker makes a rerun call-free. An interrupted matching cell restores checkpointed attempts, including state needed to continue native response-conditioned attacks, without repeating completed provider calls. The refreshed manifest contains the realized target and ordered judge-stage identity inventory, observation counts, and its SHA-256; the completion marker binds that digest, and completion validation reconstructs it from the hashed response and trail artifacts.

Trail rows retain per-stage confidence, parse status, cascade role, and the
SHA-256 of the exact persisted response. `experiments/judge_sensitivity.py`
uses those completion-validated rows without new provider calls and reports
abstention-safe harmful-ASR and benign-FRR bounds; it never interprets a
low-confidence/unparsed placeholder label as `safe`.

## Repository layout

```text
src/ura/       typed schema, converters, attackers, targets, judges, runner, CLI
tests/ura/     offline regression and integration tests
experiments/   pending-study driver and post-processing tools
docs/          architecture, schema, metrics, and taxonomy crosswalk
datasets/      local dataset area; released corpora are not redistributed here
```

For the study workflow, start with [experiments/README.md](experiments/README.md), then follow [experiments/PROTOCOL.md](experiments/PROTOCOL.md) and [experiments/RUN_AND_RETURN.md](experiments/RUN_AND_RETURN.md).

## Security and scope

Model inputs and outputs may be harmful or sensitive. Keep run artifacts access-controlled, avoid placing secrets in configs or artifact names, use the human-audit acknowledgement gate, and review [SECURITY.md](SECURITY.md). Taxonomy mappings are informational research crosswalks, not certifications or legal compliance determinations.

## License

Apache-2.0. See [LICENSE](LICENSE).
