# Reusable rig registries

These files are operator inputs for the broad experiment lanes. They are
registries, not a request to run every source against every model in one
Cartesian product:

- `api-targets.example.json` supplies execution conditions for hosted targets;
- `source-instances.example.json` maps logical corpus-arm names to environment
  variables that locate real releases.

Both files are reusable supersets. `run_matrix` reads and validates only the
selected target and corpus keys. It persists the registry filename, digest and
normalized selected entries, but not API credentials or source path values.
Results remain benchmark-, policy-, modality-, attacker- and defense-conditioned;
these registries do not define a universal safety score.

## Hosted target registry

The exact IDs and input modes below reflect primary provider documentation
checked on **2026-08-11**. This is a dated protocol snapshot, not proof that an
ID is visible in a particular account or that a preview/alias still resolves.
Before a measured grid, make one bounded live call for every declared physical
input mode and retain the provider-returned model identity. Stop if access,
serialization, or returned identity differs from the selected condition.

Keep two statuses distinct: **documentation-verified** means the dated primary
documentation supported the exact ID and modality declaration;
**operator-attested** means the rig account completed the bounded call and the
provider returned the expected identity. The example records the first status
only. A measured cell requires the second as well.

| Registry key | Declared adapter input combinations |
|---|---|
| `anthropic:claude-opus-5` | text; text + image |
| `anthropic:claude-sonnet-5` | text; text + image |
| `anthropic:claude-haiku-4-5-20251001` | text; text + image (judge/default utility role) |
| `google:gemini-3.6-flash` | text; text + image; text + audio; text + video |
| `deepseek:deepseek-v4-pro` | text |
| `kimi:kimi-k3` | text; text + image |
| `qwen:qwen3.7-max-2026-06-08` | text; text + image |

The JSON uses `temperature: null`, which tells the adapters to omit the
temperature field, and a common 4096-token response bound. Opus and Sonnet also
use the adapter's explicit adaptive-thinking contract at `effort: high`. Change
a condition only deliberately and retain the changed config digest with the run.

The fixed Fable and Sol conditions are intentionally absent: their sampling and
reasoning controls are inherent in their canonical target implementations, so
adding generic config entries would be misleading. GLM and Doubao are also
absent because an exact current account route/model pair was not independently
verified for this snapshot. They may be added only after checking the provider's
primary documentation and a bounded live response; do not guess a slug.

Pass the registry alongside the selected comma-separated targets:

```text
--api anthropic:claude-opus-5,google:gemini-3.6-flash \
--api-config experiments/rig/api-targets.example.json
```

When `llm` is in the judge cascade, its generic exact model spec must also have
an entry in this same registry; the loader binds the judge to that execution
condition rather than constructing an unconfigured hidden target.

Credentials stay in provider environment variables, never in JSON:

| Provider | Credential environment variable |
|---|---|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI fixed Sol condition | `OPENAI_API_KEY` |
| Google | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| Kimi | `MOONSHOT_API_KEY` |
| Qwen | `DASHSCOPE_API_KEY` |
| GLM (z.ai) | `ZHIPU_API_KEY` |

These keys can be set or rotated from the console's Config section
(`/config/secrets`): the console records only whether a key is present plus a
last-four masked hint, never the value, and writes it to the operator secrets
file (mode 600, `~/.ura_env` by default) for jobs launched afterwards. Setting
a key this way is equivalent to exporting the environment variable by hand.

`experiments/rig/pricing.example.json` seeds the per-model cost table
(`experiments/pricing.json`); rates can be typed by hand or pulled with the
"Fetch from provider pricing pages" button (module `experiments/pricing_fetch`),
which reads the published pages listed in `pricing-sources.example.json` and
never overwrites a hand-entered rate. See `docs/SCHEMA.md` for the provenance
and merge rules.

For OpenAI-compatible providers, the adapter's credential-free default endpoint
is used unless the operator supplies the exact account/region endpoint through
`URA_DEEPSEEK_BASE_URL`, `URA_KIMI_BASE_URL`, or `URA_QWEN_BASE_URL` (or the
entry's `base_url`). URLs containing credentials are rejected.

Local targets do not belong in this file. Use `--local` plus `--local-config`,
with **one local target per process**. This avoids retained vLLM allocations and
makes GPU placement and the separately identified scoring/defense guard
auditable.

## Source-instance registry

Select the logical keys in `source-instances.example.json`, for example:

```text
--corpora strongreject_official,jailbreakbench_harmful,jailbreakbench_benign \
--source-config experiments/rig/source-instances.example.json
```

Each selected `path_env` must contain a nonblank path to the real local release.
The value is resolved only at runtime and is not copied into result artifacts.
`source_label` and `split` are provenance labels only: they do **not** filter,
rewrite, or validate a mixed physical file. Point every environment variable at
the matching official file/directory.

The registry hash identifies only which logical mapping was requested. It is not a
release-acquisition attestation. After copying this example to the ignored
`experiments/source-instances.json` and configuring all selected paths, complete
and validate the separate compact `ura-source-conformance/1` receipt described in
[`docs/SOURCE_CONFORMANCE.md`](../../docs/SOURCE_CONFORMANCE.md), then expose its
exact path and byte digest as `URA_SOURCE_CONFORMANCE_MANIFEST` and
`URA_SOURCE_CONFORMANCE_SHA256`. Any selected real arm that remains pending,
blocked, file-mismatched, or without a passed reviewer-attributed mapping check
is rejected before a target is constructed. The receipt is evidence supplied by
the operator; it does not establish upstream authenticity or a legal determination.
The retained historical 26-entry receipt is not current admission: 19 entries
have no newly found issue, six mapping reviews are superseded, and JALMBench has
a separate upstream-accounting gap (VLSBench overlaps the mapping and accounting
groups). Preserve it and follow the exact refresh list in
[`docs/SOURCE_CONFORMANCE.md`](../../docs/SOURCE_CONFORMANCE.md#historical-receipt-boundary).

The registry covers all 25 converters and keeps physically or semantically
distinct source instances separate. Its 45 logical arms comprise 28 common-
metric arms, two implemented source-classification arms, and 15 conversion-only
arms:

| Converter | Logical arms | Physical input | Common-runner status |
|---|---|---|---|
| AdvBench | `advbench_harmful` | text | harmful common metrics |
| AgentHarm | `agentharm_harmful`, `agentharm_benign` | text + tool requirements | converter/native analysis only; official tool grading is not implemented in the common runner |
| BIPIA | `bipia_test_email`, `bipia_test_qa`, `bipia_test_abstract`, `bipia_test_table`, `bipia_test_code` | text with an untrusted-context boundary | converter/native analysis only; task-success scorer is not implemented |
| CyberSecEval | `cyberseceval_mitre`, `cyberseceval_interpreter`, `cyberseceval_insecure_coding`, `cyberseceval_prompt_injection` | text | MITRE/interpreter/insecure-coding prompts are common-metric eligible; prompt injection requires its unimplemented task judge |
| FigStep | `figstep_full` | text + image | harmful common metrics |
| GPTGeoChat | `gptgeochat_release` | text + image | implemented source-specific binary moderation metrics, not common ASR/FRR |
| HarmBench | `harmbench_text`, `harmbench_multimodal` | text; text + image | harmful common metrics |
| InjecAgent | four direct-harm/data-stealing base/enhanced arms | text + tool trace | converter/native analysis only; official tool-call scoring is not implemented |
| JailbreakBench | `jailbreakbench_harmful`, `jailbreakbench_benign` | text | harmful-response and benign-refusal strata remain separate |
| JailBreakV-28K | `jailbreakv_full` | text + image | harmful common metrics; image assets are mandatory |
| JALMBench | `jalmbench_audio` | text + audio | harmful common metrics over audio-bearing rows |
| MLLMGuard | four harmful/refusal dimensions plus three truthfulness task arms | text + image | privacy/bias/toxicity/legality use common metrics; hallucination/position-swapping/noise-injection are conversion-only until their exact truthfulness scorers exist |
| MM-SafetyBench | `mmsafety_official` | text + image | common proxy metrics; does not claim execution of the upstream evaluator |
| MOSSBench | `mossbench_official` | text + image | benign-refusal common proxy; does not claim execution of the upstream image-conditioned evaluator |
| R-Judge | `rjudge_release` | text trajectory evidence | implemented source-specific safety-classification metrics, not common ASR/FRR |
| SIUO | `siuo_release` | text + image | harmful common metrics |
| StrongREJECT | `strongreject_official` | text | harmful common metrics |
| Video-SafetyBench | `videosafetybench_benign_query`, `videosafetybench_harmful_query` | text + video | harmful common metrics; query-type strata remain separate |
| VLSBench | `vlsbench_release` | text + image | harmful common metrics |

The converter contracts and accepted layouts are the executable authority in
[`src/ura/converters`](../../src/ura/converters/). In particular:

- JailbreakBench and AgentHarm infer benign status from the physical filename;
- BIPIA infers the task from the parent directory and test/train from the file
  stem, and its attack companion file must remain next to or above the context;
- InjecAgent infers direct-harm/data-stealing and enhanced/base from the stem;
- MLLMGuard requires one of the exact released `Category I` dimensions;
- Video-SafetyBench requires benign/harmful identity in a row field or path;
- HarmBench, FigStep, JailBreakV, MLLMGuard, MM-SafetyBench, MOSSBench, SIUO,
  VLSBench and GPTGeoChat require their referenced image files;
- JALMBench expects the JSONL produced by `experiments.export_jalmbench` (or an
  equivalent manifest whose rows reference real bounded audio files). JALMBench
  and VLSBench also require their retained exporter summaries for receipt
  upstream-count accounting.

These filename rules are why the multi-instance arms are explicit. Relabeling a
path in JSON cannot turn one source subset into another.

For hosted media calls, set `URA_MEDIA_ROOTS` to an operating-system-separated
allow-list containing the selected release roots. Every media reference must be
inside an allowed root and pass byte-size, MIME/signature and SHA-256 checks.

## Environment setup pattern

Use a private operator script or shell session to bind paths. Do not commit that
script if it contains workstation-specific locations. For example:

```text
URA_STRONGREJECT_OFFICIAL_PATH=<data-root>/strongreject/strongreject_dataset/strongreject_dataset.csv
URA_JAILBREAKBENCH_HARMFUL_PATH=<data-root>/jbb/data/harmful-behaviors.csv
URA_JAILBREAKBENCH_BENIGN_PATH=<data-root>/jbb/data/benign-behaviors.csv
URA_MMSAFETY_OFFICIAL_PATH=<data-root>/MM-SafetyBench
URA_JALMBENCH_AUDIO_MANIFEST_PATH=<data-root>/jalm-export/jalmbench.jsonl
URA_JALMBENCH_EXPORT_SUMMARY_PATH=<data-root>/jalm-export/export-summary.json
URA_VLSBENCH_RELEASE_PATH=<data-root>/vls-export/vlsbench.jsonl
URA_VLSBENCH_EXPORT_SUMMARY_PATH=<data-root>/vls-export/export-summary.json
```

The angle-bracket values above are notation, not literal paths. Bind the same
pattern for every selected key using the exact `path_env` name in the JSON.
Unselected source variables need not be set.

Run modality lanes separately when target support differs. An image-capable
declaration does not admit audio or video, and a text-only target must receive
only text sources. Unsupported combinations are N/A with a reason, not silently
dropped or converted to text.

The registry covers common-runner source converters, not upstream-native engine
outputs. FuzzyAI, Garak, Promptfoo, EasyJailbreak, Petri, AutoDAN-Turbo,
Giskard, Agent Security Bench and AgentDojo must run in their own pinned
environments and be imported through `experiments.native_import`; see
[`docs/NATIVE_ENGINE_IMPORTS.md`](../../docs/NATIVE_ENGINE_IMPORTS.md). Their
native scales remain separate from common URA metric families.
