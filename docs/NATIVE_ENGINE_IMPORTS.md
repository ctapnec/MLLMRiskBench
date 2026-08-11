# Native evaluator integrations

FuzzyAI, Garak, Promptfoo, Petri, EasyJailbreak, AutoDAN-Turbo, Giskard v2, ASB
and AgentDojo are
supported as complete, source-native evaluators. They are not prompt-only
attacker adapters. Running one through
`BaseAttacker.generate()` would erase part of the upstream experiment and make a
second target call, so URA admits their completed artifacts through
`import_run()` instead.

The returned `NativeEngineRun` is intentionally marked
`common_metric_eligible=false` and `runner_replay_eligible=false`. Its native
outcomes remain reportable in their own track, but cannot enter URA ASR/FRR by
accident.

The operator first runs each pinned upstream project in its isolated
environment, using that project's supported target, attack, runtime and
evaluator. URA does not download or execute those projects through the common
runner. After the upstream run completes, a strict JSON configuration dispatches
the corresponding audited importer:

```text
python -m experiments.native_import --config native-config.json --out native-run.json
python -m experiments.native_import --validate native-run.json
```

The import command writes `ura-native-import-envelope/2`: a relative
content-addressed reference to the strict import config plus the derived
`NativeEngineRun`. Validation re-runs the importer over the authoritative files
and rejects any changed case, outcome, score, aggregate, role, hash, byte count,
record count, join, or target identity. It never runs an upstream attacker,
target or judge. Keep the envelope, import config, and all config-referenced raw
artifacts together when returning or relocating evidence; config-relative paths
remain portable across extraction roots. The nine supported engine keys are
`agentdojo`, `asb`, `autodan_turbo`, `easyjailbreak`, `fuzzyai`, `garak`,
`giskard`, `petri`, and `promptfoo`.

After common-run cells and native imports are complete, the descriptive suite
inventory can be built with repeated inputs:

```text
python -m experiments.suite_summary \
  --results runs/hosted-text \
  --results runs/multimodal \
  --native runs/native/garak.json \
  --native runs/native/agentdojo.json \
  --out runs/suite-evidence.json
```

This is not a cross-framework leaderboard. Native rates and scores retain their
own task, detector, oracle, target and scale; common runner rates retain exact
model/source/policy/modality/attacker/defense strata. Only coverage and
conformance counts can be totaled globally.

## FuzzyAI

Run the official end-to-end fuzzer outside URA and retain its entire timestamped
results directory:

```text
fuzzyai fuzz -m ollama/llama3 -a asc -a bon -T prompts.txt
```

The supported import boundary is the paired `raw.jsonl` and `report.json` that
FuzzyAI writes. Configure the adapter to match the native run, and supply the
exact upstream Git commit because FuzzyAI's artifacts do not embed a package
version:

```python
from ura.adapters.fuzzyai import FuzzyAIAttacker

native = FuzzyAIAttacker(
    model="ollama/llama3",
    attacks=["asc", "bon"],
).import_run(
    "results/2026-08-10_00-00-00",
    upstream_revision="<40-character FuzzyAI Git commit>",
)
```

The importer validates each raw attack summary and entry, reconstructs the
upstream report's harmful/failed categorisation, deduplication, counters and
integer success rates, and requires the reconstruction to match `report.json`
exactly. It also verifies the configured model and attack-mode set, rejects blank
prompts/responses, and records file/record SHA-256 lineage. Optional expected
file hashes support auditable artifact admission.

FuzzyAI's classifier map and harmful/failed/uncategorized outcome are retained
as native evidence. They are not relabelled as a URA judge verdict.

## Garak 0.15.1

Garak is a complete target-running scanner. URA does not read a probe's internal
`prompts` member and call that a Garak execution: doing so would omit Garak's
target response, detector invocation, threshold evaluator and run provenance.
Use the audited v0.15.1 release at commit
`c43aed7d3e2b97e3b62c12a2eb5d171860bf8909` and run the documented scanner,
for example through `build_native_command()`:

```text
python -m garak --target_type openai.OpenAICompatible \
  --target_name <exact-target> --probes dan.Dan_11_0 \
  --detectors auto --generations 1 --seed 0 --eval_threshold 0.5 \
  --report_prefix <absolute-run-prefix>
```

Retain the resulting `<prefix>.report.jsonl`. Record its expected count and,
where available, its SHA-256 before import:

```python
from ura.adapters.garak import GARAK_REVISION, GarakAttacker

native = GarakAttacker(
    target_type="openai.OpenAICompatible",
    target_name="<exact-target>",
    probe_spec="dan.Dan_11_0",
    detector_spec="auto",
    generations=1,
    seed=0,
    eval_threshold=0.5,
).import_run(
    "runs/garak/native.report.jsonl",
    upstream_revision=GARAK_REVISION,
    expected_records=<expected-line-count>,
    expected_sha256="<optional-expected-sha256>",
)
```

The importer requires setup/init/plugin-cache/completion/native-digest lineage,
the exact version and configured target/probe/detector/seed/generation/threshold
values, and paired status-1/status-2 records for every attempt. Tree-search
probes may legitimately carry their primary-detector score in status 1; that
early score must be unchanged in status 2. Target outputs and conversations
must remain stable; detectors may only enrich (not alter or drop) pre-detector
notes. Detector arrays must
align with output slots, and every evaluator row is reconstructed from them at
the recorded threshold. Null scores remain unscored. Native hit rates stay
separate by probe/detector pair; no global Garak ASR is fabricated across
overlapping detectors, and none of these results enter URA common ASR/FRR.

## Promptfoo 0.121.15

Promptfoo's red-team interface generates target-specific tests and then runs the
target and native assertions. There is no supported `redteam generate --output
JSON` prompt-export contract suitable for URA replay. Pin release 0.121.15 at
commit `4805856060d026521794d4e69decb938155580ad` and use the official two-step
workflow returned by `build_native_commands()`:

```text
promptfoo redteam generate -c promptfooconfig.yaml --strict --force \
  --no-cache --no-progress-bar -o generated-redteam.yaml
promptfoo redteam eval -c generated-redteam.yaml --no-cache --no-share \
  --no-progress-bar --no-table -o results.json
```

For reproducible admission, the config must bind the target provider(s),
`redteam.provider` used for attack generation, and the native grading provider
through Promptfoo's `defaultTest.provider`/`defaultTest.options.provider` chain.
Configure the adapter with those exact identities, resolved (not collection
alias) plugin IDs, configured strategy IDs, and injection variable. If
Promptfoo inferred and omitted `redteam.injectVar`, the explicitly configured adapter
value is checked against every generated test and result.

```python
from ura.adapters.promptfoo import PROMPTFOO_REVISION, PromptfooAttacker

native = PromptfooAttacker(
    target_providers=("<exact-target-provider>",),
    plugins=("harmful:hate",),
    strategies=("basic",),
    include_basic=True,
    inject_var="prompt",
    generation_provider="<exact-generation-provider>",
    grader_provider="<exact-grader-provider>",
).import_run(
    "runs/promptfoo/results.json",
    generated_config="runs/promptfoo/generated-redteam.yaml",
    upstream_revision=PROMPTFOO_REVISION,
    expected_results=<expected-result-count>,
    expected_results_sha256="<optional-results-sha256>",
    expected_config_sha256="<optional-generated-config-sha256>",
)
```

The generated YAML is retained and hashed; the authoritative result is the full
JSON `OutputFile`/`EvaluateSummaryV3`, not JSONL or a prompt list. Admission
requires exact role/plugin/strategy configuration, a complete generated-tests ×
completed-prompts matrix, consistent variables and red-team assertions,
substantive target responses for scored rows, matching grading polarity/scores,
and reconstructable summary and per-prompt counters. Promptfoo's implicit
`basic` cases are kept alongside configured transformed strategies. Set
`include_basic=False` only when the generated configuration explicitly disables
the basic strategy (`basic.config.enabled: false`); that choice is cross-checked.

Promptfoo's native polarity is important: assertion failure means the attack
succeeded; assertion pass means the defence held. Its official ASR is failed
assertions divided by scored tests and expressed as a percentage. Rows classified
as execution/grading `ERROR` are unscored, reported via coverage, and excluded
from that denominator. A recursive `graderError` marker inside a nominally scored
row fails admission instead of being counted as attack success. This stays a
Promptfoo-native metric, not URA common ASR/FRR.

Normal eval JSON can contain `promptfoo://blob/<sha256>` media references without
the bytes. When a reference exists, create a portable export with the official
command returned by `build_native_export_command()`:

```text
promptfoo export eval <eval-id> --include-media --output results.json
```

The importer requires a one-to-one blob inventory and validates strict base64,
declared byte length and SHA-256. Missing or extra media fails closed. Full
responses, grader/component records, traces and configuration remain in the
content-addressed source artifact; each normalized case retains its full native
result record.

## EasyJailbreak 0.1.3

EasyJailbreak recipes own their attack-model, target-model and evaluator calls.
Run one exact exported recipe in an immutable checkout, keep the complete
`attack_results`, and use upstream `JailbreakDataset.save_to_jsonl()` to write
the four-field native JSONL (`jailbreak_prompt`, `query`, `target_responses`,
`eval_results`). Do not extract a transformed prompt and call that a native
EasyJailbreak result: it would discard the response and recipe evaluator.

```python
from ura.adapters.easyjailbreak import EasyJailbreakAttacker

native = EasyJailbreakAttacker(
    recipe="ReNeLLM",
    attack_model="openai/<exact-attacker-id>",
    target_model="openai/<exact-native-target-id>",
    eval_model="openai/<exact-evaluator-id>",
).import_run(
    "runs/easyjailbreak/attack_results.jsonl",
    upstream_revision="<40-character EasyJailbreak Git commit>",
    expected_records=100,
    expected_sha256="<expected-file-SHA-256>",
)
```

The adapter accepts only the exact recipe classes exported by the upstream
0.1.3 package. It validates the precise `save_to_jsonl` schema, requires every
target response to have one binary native evaluation, rejects truncated record
counts and optionally enforces an expected digest. Recipe class, all three
model roles, native responses, evaluations, per-record hashes and aggregate
native success fraction remain explicit. The importer does not execute the GPL
package, and this process boundary is not a conclusion about license duties.

## Petri v3

Run Petri through its official three-role Inspect task, binding the auditor,
target and judge separately:

```text
inspect eval inspect_petri/audit \
  --model-role auditor=anthropic/auditor-model \
  --model-role target=anthropic/target-model \
  --model-role judge=anthropic/judge-model
```

Import either the native `.eval` log (requires `inspect-ai>=0.3.236` locally) or
an official JSON conversion produced by:

```text
inspect log convert --to json --output-dir converted path/to/run.eval
```

```python
from ura.adapters.petri import PetriAttacker

native = PetriAttacker(
    auditor_model="anthropic/auditor-model",
    target_model="anthropic/target-model",
    judge_model="anthropic/judge-model",
).import_run("converted/run.json")
```

The importer admits only a successful, non-invalidated `inspect_petri/audit`
log from an `inspect_petri` 3.x package. It requires the three model roles,
versioned package inventory, positive turn budget, explicit rollback/tool-mode
task arguments, non-empty samples and transcript-bearing messages/events/timelines.
For scored samples, every `audit_judge` dimension must be an integer in `[1, 10]`
and the dimension set must be stable. Petri's explicit judge-refusal result is
retained as unscored and contributes to reported score coverage; it is never
imputed safe. Sample fallbacks and the full Inspect result/task/revision metadata
remain visible in provenance, while the authoritative transcript stays in the
content-addressed source log.

## AutoDAN-Turbo

AutoDAN-Turbo's official `AutoDANTurbo.test()` is target-conditioned: each step
generates a prompt, calls the target, scores the response and retrieves the next
strategy from that response. It returns only the final prompt. Consequently,
the old local `--max_prompts`, `--attacker_model` and `--output` invocation was
not an upstream CLI and has been removed.

Run the pinned upstream revision
`389df844439888fc44ea7f5e8e95fd2b5c82ea64` through `main.py` (standard) or
`main_r.py` (reasoning), retaining all eight artifacts written by `save_data`:

```text
warm_up_strategy_library.json      warm_up_strategy_library.pkl
warm_up_attack_log.json            warm_up_summarizer_log.json
lifelong_strategy_library.json     lifelong_strategy_library.pkl
lifelong_attack_log.json           lifelong_summarizer_log.json
```

The JSON logs do not identify the participating models. Immediately after the
run, add the versioned provenance sidecar with the explicit attacker, target,
scorer, summarizer and embedding-model identities, dataset hash and run
configuration:

```python
from ura.adapters.autodan import AutoDANTurboAttacker

AutoDANTurboAttacker.write_run_manifest(
    "upstream/AutoDAN-Turbo/logs",
    run_id="recorded-run-id",
    variant="standard",
    model_roles={
        "attacker": "provider/attacker",
        "target": "provider/target",
        "scorer": "provider/scorer",
        "summarizer": "provider/summarizer",
        "embedding": "provider/embedding",
    },
    epochs=150,
    warm_up_iterations=1,
    lifelong_iterations=4,
    warm_up_requests=100,
    lifelong_requests=100,
    dataset_sha256="<64 hex characters>",
)
native = AutoDANTurboAttacker(target_model="provider/target").import_run(
    "upstream/AutoDAN-Turbo/logs",
    expected_manifest_sha256="<expected-manifest-SHA-256>",
)
```

Admission is fail-closed. The importer requires the full pinned file family and
hashes, exact warm-up prefixes in both lifelong logs, preserved strategy IDs,
valid source requests/prompts/responses/system prompts, 1-10 one-decimal danger
scores, configured request/iteration/epoch bounds, and retrieval references that
match the lifelong library. The upstream misspelling `retrival_strategy` is
retained as part of the native schema. Pickles preserve the full library
checkpoint (including scores and embeddings), but are treated strictly as
opaque bytes and never deserialized.

Each imported case retains the source request, adversarial prompt, target
response, attacker/scorer system context, retrieved strategy IDs, native score
and upstream break-condition result. The latter is an optimisation stopping
condition, not a common ASR label.

## Giskard v2 Scan and RAGET

The stable integration is pinned to `giskard[llm]==2.19.2` (upstream commit
`86512399daf097358422e1f30d19abbacbe5ce9a`). `run_scan()` accepts the caller's
real `giskard.Model` and `giskard.Dataset`, calls the documented synchronous
`giskard.scan(model, dataset)` API, and exports the returned `ScanReport` through
its native `to_json()` and `to_html()` methods. Completed exports can instead be
admitted with `write_scan_manifest()` followed by `import_scan_run()`.

The scan importer validates the detector → severity → description structure,
preserves every native issue and the full HTML report by hash, and also retains
a valid empty report as `no_issues_in_native_report`. That outcome is explicitly
not treated as a safety certification or common ASR result.

RAGET support uses the separate documented `giskard.rag.evaluate()` API and the
returned `RAGReport.save()` artifact family:

```text
report.html              testset.jsonl          agent_answer.json
report_details.json      metrics_results.json
knowledge_base.jsonl     knowledge_base_meta.json  # paired and optional
```

Use `run_raget()` for execution, or add missing model/dataset provenance to an
already saved report with `write_raget_manifest()` and then call
`import_raget_run()`. The importer requires one aligned answer and metric object
for every unique testset ID, boolean source-native correctness, report metadata,
and a complete optional knowledge-base pair. It retains per-question inputs,
references, contexts, histories, target answers, retrieved documents, evaluator
identity, native metrics and recommendation. Overall, grouped and component
correctness are reported on the upstream **0-1** scale (the HTML may render them
as percentages), not as an invented 0-100 metric and not as URA ASR/FRR.

Giskard v3 is a separate rewrite. Its official project notes that v2 Scan and
RAGET are unavailable there; `giskard-scan` is a pre-release successor rather
than a prompt-suite exporter. This integration therefore does not claim a v3
`generate_suite`/registry API.

## ASB

ASB is launched from a checkout pinned to an exact 40-hex commit. DPI, OPI and
memory poisoning use the official config launcher:

```text
python scripts/agent_attack.py --cfg_path config/DPI.yml
python scripts/agent_attack.py --cfg_path config/OPI.yml
python scripts/agent_attack.py --cfg_path config/MP.yml
```

PoT is a distinct upstream surface: `python scripts/agent_attack_pot.py`, run
with the checkout as its working directory, reads `config/POT.yml` itself. The
adapter therefore does not fabricate `--cfg_path config/POT.yml` for that
launcher. `build_native_command()` verifies the checkout revision and returns
the appropriate command.

`import_run()` admits the selected official YAML config and the CSV written by
`main_attacker.py`. It requires the exact native header, parses the Python-literal
message trace without executing it, and preserves agent name, original task,
attacker tool, full messages, attack-success, original-task-success, refusal,
memory-found and aggressiveness artifacts. The config identity is cross-checked
against the selected model, attack type and attacker-tool class. Memory
poisoning is admitted only under ASB's documented `memory_attack` name with
`read_db: true`; `memory_poisoning` is not accepted as an invented alias.

## AgentDojo

Use `build_native_command()` to run the official environment benchmark, for
example:

```text
python -m agentdojo.scripts.benchmark \
  --model gpt-4o-2024-05-13 --benchmark-version v1.2.2 \
  --attack important_instructions -s workspace --logdir runs
```

The supported package pin is checked against
`agentdojo_package_version` in every trace (currently `0.1.35`). Point
`import_run()` at the fresh `pipeline/suite` trace subtree. It validates
TraceLogger's exact path/metadata relationship and modern content-block,
FunctionCall, injection and completion schemas. A complete import must contain
the attacked user-task traces and the no-attack execution of every injection
task. URA then reconstructs AgentDojo's three native maps: utility under attack,
the upstream field named security, and injection-task utility. No polarity is
silently flipped: in AgentDojo v0.1.35's task contract, `security=True` means
the injection goal was executed.

The exact environment injections and full system/user/assistant/tool trajectory
remain in each native case. No injection is appended as a user turn, and no
trace is replayed through `Runner` as though that were an AgentDojo execution.

Artifact imports do not themselves execute FuzzyAI, Garak, Promptfoo, Inspect,
EasyJailbreak, AutoDAN-Turbo, Giskard, ASB, AgentDojo, a target, an auditor or a judge. The
explicit Giskard `run_scan()` and `run_raget()` methods are execution surfaces
and may call the configured target/evaluator.
The upstream artifacts may contain harmful or sensitive content and must remain
under the same access controls as other measured run artifacts.

Primary contracts: [CyberArk FuzzyAI](https://github.com/cyberark/FuzzyAI),
[FuzzyAI CLI](https://github.com/cyberark/FuzzyAI/blob/main/src/fuzzyai/cli.py),
[Garak v0.15.1](https://github.com/NVIDIA/garak/tree/v0.15.1),
[Garak reporting](https://reference.garak.ai/en/stable/reporting.html),
[Promptfoo 0.121.15](https://github.com/promptfoo/promptfoo/tree/0.121.15),
[Promptfoo output files](https://www.promptfoo.dev/docs/configuration/outputs/),
[Promptfoo red teaming](https://www.promptfoo.dev/docs/guides/llm-redteaming/),
[EasyJailbreak](https://github.com/EasyJailbreak/EasyJailbreak),
[EasyJailbreak dataset export](https://github.com/EasyJailbreak/EasyJailbreak/blob/master/easyjailbreak/datasets/jailbreak_datasets.py),
[Inspect Petri](https://github.com/meridianlabs-ai/inspect_petri),
[Petri audit task](https://github.com/meridianlabs-ai/inspect_petri/blob/main/src/inspect_petri/_task/audit.py),
[Inspect eval logs](https://inspect.aisi.org.uk/eval-logs.html),
[AutoDAN-Turbo](https://github.com/SaFo-Lab/AutoDAN-Turbo),
[Giskard v2.19.2](https://github.com/Giskard-AI/giskard-oss/tree/v2.19.2),
[Giskard ScanReport](https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/scanner/report.py),
[Giskard RAGReport](https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/rag/report.py),
[Agent Security Bench](https://github.com/agiresearch/ASB), and
[AgentDojo](https://github.com/ethz-spylab/agentdojo).
