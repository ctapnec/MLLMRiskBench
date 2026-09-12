# Campaign workspaces and the reproducible UI workflow

## Campaign and run contract - whole-flow reassessment

The user-facing distinction is **Campaign** versus **Single run**, not local
versus API. A campaign applies a defined selection of arms, corpora and attack
frameworks to a set of models. It owns the resulting collection runs, preparation,
judging, recoveries and analyses. A single run is one independently executable
Runner job; it is not one question and can contain multiple inputs. A campaign
can contain one or many runs without changing that definition.

Build is the only experiment editor. Its first choice is Campaign or Single run.
Campaign creation includes the name in Build, alongside the existing pipeline
controls; it must not send the user to a second creation wizard. An existing
campaign reopens its saved definition. Models are selected once in the existing
model picker. Local, API or mixed is a description derived from that selection,
never a required preliminary campaign category.

The complete navigation contract is:

| Section | Purpose | Main content and actions |
| --- | --- | --- |
| Build | Define and review an experiment | Campaign / Single run; models; arms and corpora; frameworks; sampling; generation; judging; resources and costs; save and review |
| Campaigns | Manage coordinated experiments | Named campaigns; saved definition; collection and judging progress; constituent runs; continue in Build |
| Jobs | Observe execution | Campaigns and Standalone runs as distinct views; drill into a campaign's real jobs; logs, retry state and supported stop/resume actions |
| Stats | Examine results | Campaigns and Standalone runs as distinct views; model/input/framework breakdowns, output-specific judgments, usage, costs and exports |
| Tools | Advanced operations | Existing typed preparation, judging and analysis commands, with explicit campaign ownership when applicable |

Normal flow: **Build -> Campaign or Single run -> configure -> review ->
execute -> Jobs -> Stats**. Opening an existing campaign instead returns to its
saved Build definition or its Jobs/Stats views. A standalone run must not be
silently wrapped in an API-named campaign. A campaign's jobs must not reappear in
the standalone list. Unassigned historical controller/report records remain
explicitly unassigned, not inferred to be standalone experiments or campaigns.

Saving a definition makes no calls. Reviewing a definition shows the actual
models, arms/corpora/frameworks, seeds and selection, generation settings, judging
stages, workload and forecast. The reviewed launch keeps those choices and its
campaign owner even if another tab edits the draft. Editing a draft never changes
an already running job or its historical results. A saved draft alone is not a
running, completed or fully scheduled campaign.

The audit found four connected gaps, not just bad labels: campaign records had
no saved experiment definition; creation duplicated model-category choice;
Jobs mixed campaign controllers and standalone runs; and Stats used a conditional
landing page and called individual executions campaigns. Result publication and
the retained-input provider-parallel scheduler also remain incompletely connected
to UI launches. They must be finished using their existing execution paths, not a
second scheduler or another pipeline editor. This section is the intended
end-to-end contract, not a claim that all of it is already deployed.

Acceptance includes creating both kinds from Build, saving and reopening a
multi-model/multi-arm campaign without losing selections, reviewing and launching
without changing CLI semantics, separating membership in Jobs and Stats, and
opening a completed run's real results. Also verify narrow layouts, keyboard
navigation, readable spacing and the common busy guard on every backend request.
Campaign completion requires all assigned collection and requested judging work,
not merely a successful child process. Existing experimental jobs continue during
this UI work.

Live visual check, 12 September: the rig's existing isolated browser environment
rendered Campaigns, Local Results, API Judging, API Costs and Build at desktop
width, plus Local Results and Build at mobile width. The screenshots were
inspected; there were no browser script errors or page-level horizontal overflow
in those views. Loaded-page busy indicators were clear, and the API Judging view
contained real indexed label diagrams. These checks cover the deployed pages,
not the complete new-campaign execution flow or every interactive control.
The observed diagnostic-first chart order is corrected in the next release:
measured groups come first, while diagnostics remain separately paginated and
all condition-specific counts and exports are preserved.
The cost table also bounds the model-name column so desktop users can see the
cost and token columns together. At narrow widths, only the table scrolls, not
the whole page. Ten focused rig tests, a removed-fix browser control and
visually inspected renders of actual indexed costs verify this candidate fix;
its console deployment remains pending. Unknown charges and token reports
remain explicitly unknown rather than being converted to zero.

### Selected local inputs for a hosted follow-on

Build's General section now starts source preparation from the campaign index:

1. Choose Campaign and name or reopen the destination campaign.
2. Under **Prepare a matched follow-on**, choose the source campaign and press
   **Choose source runs**. This reads SQLite only; it makes no model calls.
3. Select the exact local runs, including the desired generation conditions,
   and press **Prepare selected inputs**. The background preparation validates
   the original completed grids and writes their input inventory. Missing and
   truncated outputs are not filtered out. Only measured local runs are listed;
   listing a run does not establish that an unfinished original grid is usable.
4. Open the preparation job from Build or Jobs. It belongs to the destination
   campaign; its original source runs retain their own ownership. The saved
   draft retains the run selection and preparation job link.
5. Reopen the campaign in Build and select the hosted target models. Under
   **Forecast matched hosted work**, refresh the selected-model table, set a
   whole-number request cap for each model and choose the pricing date. Output
   allowances come from the actual configured target routes, not a uniform
   replacement limit. **Prepare forecast** launches the ordinary budget CLI as
   a campaign-owned job. It copies the selected configuration, configured prices
   and reported balances; it makes no provider request and reserves no money.
   The forecast includes Haiku assessments of hosted and matched local outputs,
   preserving the existing per-attempt spending policy. A changed target list
   requires a refreshed table; it cannot reuse stale per-model caps.
6. Once both preparation jobs complete, choose **Prepare replay inputs**. Build
   obtains their saved artifacts automatically and prepares every selected
   model and source arm as one background job. The original whole-cluster
   selection, prompts, dialogue history and media are retained. A changed
   source selection, model configuration, request cap or pricing date requires
   the corresponding preparation to be refreshed. No target or judge is called.
7. Select **rules,guardrail** in Evaluation for the retained-input executor's
   local post-hoc scoring path. **Count inputs and prepare collection** obtains
   the source, replay and forecast artifacts from those jobs and prepares the
   existing provider-parallel programs with one shared spending plan. Enable
   provider token counting only when the selected route requires its endpoint;
   otherwise supported local conservative counts are used. This action sends
   no generation request, runs no judge and does not start collection. Review
   the resulting costs before execution. Haiku still requires its separate
   output-specific selection and preparation.
8. Under **Collect prepared inputs**, choose the number of workers per provider
   (default two), then **Review prepared collection**. The review shows the saved
   model assignments, output allowances and initial-attempt cost ceilings, not
   later edits to the draft. **Start prepared collection** launches the existing
   provider-parallel executor with this campaign's ownership and publication.
   It does not start local or Haiku judging. Required execution readiness and
   admission inputs must already be present in the prepared programs.
9. For the same saved programs, reopen this review after a stopped collection.
   **Continue saved collection** selects the previous control directory
   automatically. Completed jobs are restored and eligible checkpoints resumed;
   the inputs and spending plan do not change. Active or duplicate launches are
   rejected, including two review pages opened in different tabs. A changed
   software revision or spending plan needs an explicit recovery handoff rather
   than silently changing the old execution conditions.
10. Under **Judge retained outputs locally**, choose **Prepare remaining source
    runs**. Build uses the same saved programs. It reopens active preparation
    instead of launching a duplicate, and excludes source runs already prepared.
    An incomplete source remains listed as unprepared; completing other sources
    does not hide that gap. This preparation makes no target or judge calls.
11. Choose a **Saved judging preparation** and **Review local judging**. The review
    shows its retained output count and original scoring model, device and token
    allowance. It does not substitute settings from later draft edits. Model and
    result-file checksum revalidation are separate optional controls, off by
    default. Start after the recorded judge device becomes available; this panel
    does not allocate or preempt GPUs automatically.
12. **Start or resume local judging** executes the existing local scoring command
    and publishes verdicts against this campaign's exact saved outputs. Resume
    reuses the same checkpoint directory; original and completed new verdicts
    are not judged again. Duplicate review submissions cannot launch another
    active copy. After additional collection runs complete, prepare only the
    remaining sources and keep earlier preparations available in the selector.
    Haiku selection and assessment remain a separate output-specific stage.

Eleven focused rig checks cover this collection handoff, including an actual
browser form submission and duplicate-click control; two removed-fix controls
fail as required. A review of the actual two-model prepared source was rendered
and visually inspected without starting its paid executor. This is not yet
acceptance of a complete new UI campaign through readiness, paid generation,
local/Haiku judging and final analysis.

The native judging handoff adds nine focused checks, with the changed collection
helper also covered by its eleven existing checks. Three removed-fix controls
detect duplicate preparation, lost checkpoint continuation and stale launches.
The actual browser flow launched the real local judging CLI on two previously
verified retained outputs in an isolated campaign: one original verdict was
restored and one rule-only assessment produced, and both were indexed. It made
no target or judge-model calls and changed no live campaign database. Desktop
and mobile views were inspected. A further narrow-layout regression and its
removed-fix control cover the corrected table width.

The forecast, replay and counted-program actions are rig-verified; console
deployment is tracked in the development ledger. The
older selected-source action is already deployed. Its initial Haiku forecast
assumes one hosted and one matched local output per target request. This is not
the final number of distinct selected local answers: later preparation must
count the actual output-specific judging population, including multiple local
models and any already assessed identical outputs. Do not use the initial
forecast as permission to exceed an execution or judging allowance.

The selector includes historical outputs even when a later replacement is
selected in Stats. It never chooses the newest or best answer automatically.
It resolves only the selected artifact locations, then reuses the existing
source-preparation command. Opening the page does not scan or hash result files.
This is a separate preparation action, not a switch silently changing the
current Runner pipeline's corpus. Readiness preparation and Haiku orchestration
below are not yet assembled by the normal Build editor. The reviewed collection,
continuation and native judging handoffs are implemented and rig-verified, but not yet deployed;
a forecast alone is not an executable collection.
Replay preparation converts the union of required sources once across models,
using the configured corpus and media locations without API credentials.
Its request caps can leave unused space when the next whole cluster does not
fit. An empty selection is reported before conversion instead of producing an
apparently executable empty campaign. Source-condition counts are not counts
of valid or outstanding judgments. The real rig check reused the existing
568-input source job and prepared the same 100 inputs for two configured
routes, preserving text and media without generation or live SQLite changes.
This preparation action is deployed at `00dce99`. Twenty-three focused rig
tests, three removed-fix checks and a real Build-handler child launch passed.
The actual campaign index listed 413 runs in 0.22 seconds, and preparation
reproduced the exact 568-input saved selection. No model calls were made.
The deployed source-selection page and configured budget form return HTTP 200;
interactive browser visual acceptance is still pending.

The advanced Tools flow now supports ordinary completed Runner directories as
input sources, independently of the thesis campaign's historical analysis
layout. Use `retained_local_sources` to select one or more narrow source
directories and optional exact run IDs. Its inventory includes failed local
answers: response text, outcome and judge labels do not select the inputs.
Later runs added to those directories do not silently enter the saved selection.

Use `hosted_campaign_budget` for the target/judging forecast, then
`hosted_retained_inputs` with that inventory to prepare a bounded, whole-cluster
selection and replay artifacts. This existing replay protocol uses retained
seed-zero inputs; adaptive conversations are replayed, not freshly attacked.
It does not introduce arbitrary-seed or shared-cohort selection support.
For selected local sources, replay preparation restores the original converted
records and their recorded subset order automatically. It converts each
distinct source once per preparation and resolves media only for the funded
selection, including media in earlier dialogue turns. Unselected sources are
not opened just to prepare another route. No answer, verdict or replacement
quality affects this reconstruction. The explicit media index and source-corpus
files remain available for moved or legacy artifacts; they are no longer
required manual handoffs for ordinary selected local runs. Original sampling
and source identities must still agree. Full file checksum revalidation remains
opt-in, and preparation makes no target or judge calls.
The selected-source request in `hosted_campaign_prepare` now emits executable
programs without requiring the historical controller or GraySwan analysis.
Its explicit network option permits token counting, not answer generation.
Unchanged source context is reused by provider workers; budgets remain checked
at paid dispatch. Old programs retain their original reader and interpretation.

These typed forms and reusable preparation APIs are not the finished normal
Build workflow. Source/replay preparation, reviewed collection and native judging are connected;
the remaining editor work must assemble readiness and requested Haiku judging from
its ordinary controls. Do not present manual JSON/path handoffs as that completed
UX. The retained executor still owns provider concurrency and continuation;
creating a second scheduler or independently funded per-model grids is not the
integration. Rig verification covers 181 focused tests, removed-fix controls
and the real 568-input Gemma source, with no generation, judging or full-artifact
checksum scan. The runbook documents the engineering request fields. The three
new Tools forms are deployed at 3cd5142 and return HTTP 200. Campaign workers
were not restarted. Interactive browser acceptance remains pending.

### Active and historical campaign integration

The same workflow must support the currently running campaign and a campaign
created manually in Build. The UI must expose the actual retained-input selector,
per-model generation settings, per-provider concurrency and retry policy, shared
spending forecast and ceilings, local resource plan, and requested local/hosted
judging stages. An opaque script path is not a substitute for these controls.
Collection must use the existing provider-parallel executor without waiting for
unrelated judging batches. Changes apply to future work or explicit continuations,
not to already collected answers.

Import completed and active campaigns from explicit inventories and program
references. Preserve their real process ownership, original timestamps, pending
assignments, outputs, physical attempts, costs, output-specific judgments and
recovery links. Publication must update on durable new data, not only after an
entire campaign ends. Page navigation reads SQLite; it must not recursively scan,
rehash or reconstruct the experimental corpus. A last-published time and pending
publication state distinguish stale indexes from idle execution.

Management actions include reviewing remaining work, changing future settings,
resuming eligible missing/transport-failed work, selecting a retained successor,
and judging retained outputs without regenerating them. Imported tmux workers are
read-only until a real control adapter owns their stop/resume lifecycle. Never
show a functional-looking control that cannot operate the underlying job.
Original outputs remain usable for new comparisons or re-judging after settings
change; historical and corrected generation conditions stay distinct.

The definition and scope changes alone do not fulfill this integration. Remaining
acceptance must exercise the current real campaign, a new UI-created campaign and
a standalone run through configuration, execution, ongoing publication, judging,
continuation and Stats. Both local and hosted paths are required.

Status: the campaign/single-run editor, saved campaign definitions, separated
Jobs/Stats scopes, visible server-side navigation and stable response artifact
links are deployed at `7b091c4`, 11 September 2026. Build now includes naming and
saving a campaign; the earlier separate creation page redirects into Build.
The same definition reopens after navigation or restart. Local/API/mixed is no
longer a creation question. Runtime services live in Runtimes, not above the
experiment summary. Reviewed jobs keep their own settings when a draft changes.
Focused rig regressions, lint and removed-fix checks passed; eight deployed
routes returned HTTP 200. Interactive browser visual QA remains pending because
the browser connection was unavailable. Complete workflow integration is still
in progress. The original deployment backup check used a malformed
SQLite URI and did not verify preservation; a corrected live backup and the
4,097-assignment condition repair are retained under
`workspace-conditions-078f798-20260911`. The later `7b091c4` deployment used a
correct SQLite/WAL backup and preserved all existing rows without restarting
campaign workers or reinstalling runtimes. Full historical import,
automatic result publication, full cost-source attribution, matched comparison figures and
the remaining execution actions below are unfinished.

### Prepared hosted collection through Tools

`hosted_campaign_execute` now exposes the reusable provider-parallel collection
path through the typed Tools form. Select the campaign owner, supply each exact
prepared/attested program and its matching digest, the shared spending plan and
clean execution checkout, and a fresh control output directory. The per-provider
worker count defaults to two. All selected providers can progress concurrently;
each program's own probe and canary finish before its measured jobs. Collection
does not wait for judging and does not load a local judge.

The dispatcher preserves the prepared input IDs and Runner arguments. It does
not resample, introduce answer retries, or change the existing HTTP retry and
paid-attempt accounting. A paused program does not block independent providers.
Its target-collection terminal means responses are saved and judging is pending,
not that the campaign is complete. A failed worker retains a continuation state;
do not restart a paid program from zero to repair its accounting.

On the rig, workers start with `forkserver` and receive already admitted jobs;
they do not inherit active parent threads or reconstruct historical sources for
every dispatch. Source validation is shared per distinct source context. Funding
stop observation reads stop metadata and the immutable plan, not the complete
spending history; the live spending check still occurs before each paid attempt.
Full retained-file checksum revalidation remains opt-in.

For a terminal collection job, Jobs offers **Review continuation**. It opens the
same typed form with all program/digest pairs, spending plan, execution revision
and campaign owner preserved. Enter a fresh successor output directory; the
previous collection directory becomes `--resume-from`. Opening the form makes
no calls. Tools provides add/remove controls for repeated parameters, so multiple
programs do not require hand-editing the URL or invoking the CLI.

Continuation restores completed jobs only when their actual saved outputs match
the original input/model and recorded paid starts. Partial jobs restore Runner
checkpoints. Original responses and collection records stay unchanged. A live
parent or continuation cannot be started a second time. HTTP attempt limits,
spending stops and uncertain charged-but-unsaved attempts still apply; this
action is not an automatic answer retry or an increase in the spending plan.
Only collections recording the required source, revision and owner fields can
use this action. Older imported controller jobs remain read-only until their
own recovery path is supported; a terminal badge alone cannot authorize replay.

This is the advanced prepared-program launch, not completed normal Build
integration. Preparation, counting, reviewed spending, attestation, multi-local
scheduling, judging and ongoing publication still need the end-to-end workflow
acceptance above. Rig checks cover the rendered form, exact CLI mapping,
campaign ownership, provider concurrency and real retained job metadata without
issuing paid calls. Focused continuation checks additionally use actual retained
paid output and removed-fix controls. Browser visual acceptance remains pending.

Prepared hosted collection now publishes its explicitly selected assignments,
retained response checkpoints and physical-attempt costs automatically. The
console passes the selected workspace and its SQLite index to that child only;
standalone launches do not inherit a campaign owner. CLI users can supply
`--workspace-id` together with `--console-db` for the same behavior. These are
publication settings, not generation or budget parameters.

The collection process refreshes after job-state changes and at thirty-second
intervals while requests remain active. Unchanged checkpoint data are not
reparsed, and a billing-only change updates costs without rereading answers.
The shared ledger is read once when its metadata changes, with updates scoped
to the program's own calls. No page request launches this work. Missing outputs,
policy outcomes, truncation, unstarted inputs and diagnostic probes retain their
distinct meanings. An index failure is retained as pending publication and does
not cancel unrelated paid requests or imply that collection failed. This
connection covers prepared hosted collection; normal Build preparation, local
run publication and the complete judging/continuation flow remain unfinished.

Native local collection now has a checkpoint publication hook in `run_matrix`.
Campaign-owned launches receive their workspace/database binding; CLI launches
can supply `--workspace-id` and `--console-db` together. The existing Runner
callback first saves the response durably, then updates its SQLite assignment
and response. Its later judgment attaches to that exact output. A restored
checkpoint republishes without generation, and an index error retains pending
publication without cancelling model work. The hook reuses admitted source
metadata and the already rendered input; it does not reconstruct a corpus.

Native publication also records the loaded source-row plan before the first
target call. The campaign Overview separates source rows planned, reached and
not reached from output/judgment totals. A reached source row has at least one
durable response record, including a missing output. Multiple seeds or adaptive
turns do not multiply this source-row count or establish that the input's whole
trajectory is complete. Each run retains its own plan and generation condition;
these counts are not independent observations across overlapping runs.

Restarting and restoring a checkpoint cannot duplicate or decrease the known
progress. A failed index update leaves publication pending without cancelling
target generation. The hook uses the corpus Runner already loaded, and the UI
reads only SQLite. Historical runs without an indexed plan remain outside this
new coverage table; their missing plans are not inferred from completed outputs.
This supports future CLI and campaign-owned Build launches through the same
wrapper. Full historical plan import and deployment/interactive acceptance remain
pending, as do the multi-job and judging controls below.
For new completed-prefix or completed-selection recoveries, the sampling audit
now retains the already computed original selection identity before filtering.
The normal Runner publication wrapper uses it automatically for Ollama and
vLLM, including campaign-owned Build launches. This adds no source reconstruction
or hashing. Older retained recoveries can still supply their explicit original
input selection; without either source, publication remains pending rather than
assigning a different question identity. Original and replacement generation
conditions remain distinct. Focused rig and actual saved Ollama/vLLM record
checks passed. This closes automatic input-identity propagation in the native
wrapper, not the remaining continuation controls, deployment or full UI acceptance.

The active API index was refreshed from its seventeen explicit current program
sources: 4,097 assignments, 3,908 retained outcomes and 3,917 physical-attempt cost
records. This is the current continuation and Flash-extension subset, not the
combined three-cohort total. Forty-seven explicit current controller references,
including the running local-judging work and retained recovery processes, were
attached to the API campaign. Their process ownership and historical states did
not change. Earlier cohorts, complete local-campaign import, output-specific
judgment publication and ongoing publication hooks remain to be integrated.
Proofs: `campaign-flow-deployment-7b091c4-20260911`,
`workspace-current-refresh-7b091c4-20260911`, and
`workspace-activity-current-20260911`.

The separate Local campaign is now published as
`d74685e6af8e4e199d46db201c557858`. Its 372 retained runs contribute 50,653
output records across historical and corrected conditions: 44,550 usable and
6,103 missing outputs. These are retained generation-condition records, not a
pooled independent sample or the size of the final corrected comparison.
The native scoring index preserves 50,653 records, including two invalid
classifier outputs without labels. Two partly exported GraySwan runs required
their retained response/attempt checkpoints and separately completed judging
records; no corpus reconstruction or regeneration was performed. Local targets
remain separate from hosted targets. The historical and RR report publications
are attached under Activity. Local Haiku verdicts, cost attribution and broader
controller membership still need indexing. The overview, results, judging,
activity and two SVG exports returned HTTP 200 on the rig. Interactive browser
QA remains unavailable. Evidence: `local-workspace-native-index-20260911`,
its `-r-tail/live-summary.json`, and `local-attempt-tail-109b2c8`.

Build's Campaign and Single run modes deliberately share Runner command
semantics. Campaign ownership and its saved definition are retained separately
from the command. At present, a reviewed launch attaches that one Runner job;
this does not yet implement the complete multi-job collection/judging schedule
specified below. Do not add a cosmetic command flag or claim that the complete
campaign execution workflow is finished.

An explicit hosted-program importer is available as `experiments.campaign_publish`.
It reads the selected program, input-plan metadata, completed checkpoint/final
rows and its budget ledger once. It imports unstarted assignments as well as
retained outcomes; incomplete live JSONL tails are not outcomes. Repeating the
same import is idempotent. It does not run checksums, call providers, execute
judges, rebuild corpora, or run from a Stats page request. Existing judgments
are untouched; this command does not claim judging coverage.

Rig-verified correction, 11 September: preserve the actual checkpoint or final
export locator supplied by the publisher. A partial final export must not hide
a checkpoint tail. Promotion may change row order, so compare the stable output
identity and metadata while updating its physical locator. If only an alternate
export exists, link that file without claiming the original row number applies.
The focused regression covers a three-row checkpoint beside a one-row final
export. All 22 focused rig tests and both removed-fix checks passed. Deployment
and repair of the previously normalized index locators remain pending.

The Conditions count identifies generation settings, not distinct questions.
It is derived from the target configuration and output allowance, excluding
credentials and configuration-file locations. Different inputs under unchanged
settings share a condition; changed settings remain separate. The rig verified
this correction with nine focused tests, a reversed-fix check and a live-data
rehearsal. Production index repair changed only the derived condition fields;
response selection, outcomes, verdicts, token counts and costs stayed unchanged.

Create or select the campaign in Build, then use its ID from the campaign URL:

```sh
python -m experiments.campaign_publish \
  --database /absolute/console.db --campaign-id CAMPAIGN_ID \
  --hosted-program /absolute/attested-program.json \
  --input-plan /absolute/input-plan.json --budget-root /absolute/budget
```

Use the explicitly selected recovery program, not a directory-wide latest-file
search. Multiple different answers for one assignment require explicit recovery
selection. Policy outcomes stay distinct from generated answers; a usable length
completion stays usable and truncated. Costs with no retained charge remain
unknown. Multi-attempt token usage is taken from each attempt's ledger report,
never copied from the final answer onto earlier network failures. This is a
scoped import, not a claim that all programs or judgments have been published.

Output-owned cost indexing and its workspace table are now deployed. Twenty-one
focused rig checks covered cost ownership,
retries, copied records, migration and the existing result views. The changed
ledger-translation check also passed. Three reversed-fix checks detected wrong
ownership, unknown charges turned into zero and wrong per-attempt response
attribution. A real-data proof indexed the two retained DeepSeek attempts in an
isolated database: one assignment, both output conditions, 46,429 reported output
tokens and unknown costs shown separately from exposure. It made no calls and
did not import production campaigns. Proofs: workspace-costs-b76283b-20260911
and workspace-costs-38a361f-20260911.

The subsequent importer passed 20 focused rig tests, lint and two reversed-fix
checks. Its actual-record proof reconciled 110 Sol assignments, 110 retained
outcomes and 112 HTTP attempts, preserving diagnostic/measured classes and
policy decisions. Deployment backed up SQLite including its WAL, preserved
existing rows and restarted only the console. Sixteen current hosted programs
are published in the API campaign workspace with real cost rows and diagrams.
The missing Opus program was subsequently published using its 19 explicitly
retained pre-repair answers. All 213 current Opus inputs now reconcile in the
workspace: 212 usable/policy outcomes and one exhausted transport failure.
All seventeen current programs have an index, but the earlier cohorts and
output-specific judgments still need publication; this is not the complete
combined campaign. The import helper at `0c9a39f` passed eight focused tests,
lint, a reversed-fix check and the actual 174-input recovery-program import.
Evidence: workspace-import-54fbc07-20260911,
workspace-import-deployment-54fbc07-20260911 and workspace-current-publication-20260911.
The prefix proof and publication are workspace-prefix-0c9a39f-20260911 and
workspace-opus-prefix-publication-20260911. They use the existing console schema;
no console restart or source-output rewrite was necessary.

Focused rig verification covers 32 ownership checks, six result-index checks,
seven initial chart checks and two changed export/navigation checks. Four real
headless-browser checks also passed: repeated export clicks produce one request,
and success, HTTP error, network error and timeout all release the loading
overlay. These reused the rig's isolated browser tools. Interactive inspection
of the deployed campaign pages remains pending. Proofs: ui-workspaces-bd036ca,
ui-workspaces-acefbe5, workspace-results-d83bc77, workspace-charts-c365197 and
campaign-spend-ui-020ef86. Removed-fix tests detect ownership loss, implicit
newest-response selection, input-level verdict reuse and a wrong denominator.

The real-data index proof uses one diagnostic Sol response in an isolated
console database. It is not a full campaign import or measured publication.
Unindexed costs and results explicitly remain unknown, not zero.

The deployed predecessor used **Build -> New campaign -> name and
Local/API/Mixed -> Build** and conditionally replaced Stats with a campaign list.
That flow is superseded by the contract above. Explicit ownership already stays
with each reviewed launch and does not change Runner arguments or invalidate an
otherwise identical no-call projection. This behavior must be preserved.

## The user-facing result

The campaign is the main object, not the process that happened to execute part
of it. Present this thesis work as two workspaces:

- **Local campaign**: all local targets, their original runs, corrections and
  remaining-input recoveries, local judgments, selected Haiku judgments and
  local analyses.
- **API campaign**: the original hosted selection, supplements, Google
  extension and current expansion, with local and Haiku judgments of each
  selected output.

These names are configuration, not two hard-coded campaign types or a permanent
limit of two campaigns. Local-testing phase numbers and dated controller names
do not become system concepts or primary navigation labels.

The landing page has two compact summaries, with collection progress, judging
progress, unresolved outcomes, spending and last update. Opening either summary
shows the campaign itself, not another list of job cards.

```text
Campaigns
  Local campaign                       API campaign
    Overview                             Overview
    Results                              Results
    Judging                              Judging
    Costs                                Costs
    Activity                             Activity

Compare campaigns: same-input Local / API comparison
```

Use horizontal tabs inside each workspace, consistent with the existing UI.
The shared comparison is accessible from both workspaces and has one stable
URL. Jobs remains an operations tool; it is not a competing results homepage.
Existing job and report URLs remain usable as deep links.

### Overview

Show one model table, with modality filters and expandable framework, arm and
corpus breakdowns. The default columns are model, assigned inputs, attempted
inputs, usable answers, policy outcomes, missing outputs, truncated answers,
local judging coverage and Haiku judging coverage. Show not-started and
retry-pending counts separately. A generation can be usable and truncated, so
truncation is a separate flag rather than an additive outcome bucket.

Show a collection progress chart by model and a judging coverage chart. No
timestamps, receipt names, script names or raw paths dominate the page.
An active campaign needs a last-updated time and a stale-data notice; zero
activity must not be inferred from an unavailable index.

### Results and comparisons

Results is a single filterable table, not one table per execution batch.

To inspect a historical or corrected setting, open the campaign's Overview,
choose a model, then select its execution condition. The condition list shows
the reported context and output allowances, including ranges and unknown values.
Overview figures, Results, Judging, pagination and SVG/CSV exports retain the
same filter. All conditions remains available and includes historical failures;
filtering never overwrites an answer or automatically selects its newest or
best replacement. Costs remain campaign-wide, including recovery attempts.
These filters read the SQLite index only and do not reopen corpora or response
payloads. Export metadata retains the exact selected condition identifier.
Closing a read-only console that owns no Ollama process does not acquire the
inference lock. A console-owned daemon still uses the normal locked cleanup;
unrelated running local inference must not delay a no-op shutdown.
Filters include model, modality, framework, arm, corpus, sampling selection,
generation settings and judge. The model detail opens a bounded side panel or
modal with its charts and a paginated input/output/judgment browser.

Expose effective context, output allowance, reported input/output/reasoning
tokens where available, finish reason, truncation and missing-output category.
Do not infer token usage from an allowance or infer an actual context window
from a model's advertised maximum. Unknown values remain unknown.

The default corrected-results view resolves an original assignment to its
explicitly designated retained successor. Historical responses remain available
through a condition selector. A newer timestamp alone does not select a better
answer. Different generation settings remain separately identifiable even when
they are shown in one workspace. Do not choose an answer because it received a
more favorable safety judgment.

The comparison page uses the intersection of eligible retained input identities
for the selected models and judge conditions. Match rendered text, images,
source/arm identity, seed and attack condition, not an approximate question title
or row number. Source aliases do not create independent observations. A live
adaptive trajectory is not an identical input unless its actual replay is
matched. Show eligible, excluded and unmatched counts before rates.

Local and Haiku verdicts are bound to each distinct response. The same input
does not make two model outputs interchangeable. Reuse an existing verdict only
for the same retained output and judging condition. Equal inputs do not imply
equal local/API answer totals when the model rosters differ.

The **Compare** tab now provides an indexed descriptive comparison within one
campaign or between Local and API. Choose the right-hand campaign, both models,
and one generation and judging condition per side. Use **Update choices /
compare** to load the dependent choices. Conditions are explicit; the view
never substitutes a newer or more favorable output. A selected replacement
uses its own generation condition, not its predecessor's setting.

Each corpus/framework/modality facet reports the input union, exact matched
inputs, left-only and right-only inputs, and ambiguous shared inputs. More than
one assignment for an input on either side is ambiguous and does not form a
Cartesian set of pairs. For unambiguous shared inputs, the table keeps both
output states, truncation flags, judgment states and labels. An absent index
record is not proof that no request occurred. Diagnostic and unknown-evidence
rows do not enter this measured comparison. These are descriptive counts, not
independent-sample totals, a pooled ASR, a causal contrast or a completed paired
statistical analysis.

Twelve complete source facets appear on each page. **Download this page's
counts** exports those exact facets and both selected conditions as CSV, using
the shared request spinner and error handling. Selection and page reads use
SQLite only; no source reconstruction, model calls or checksum scans occur.
The new comparison passed 24 focused rig checks, three removed-fix controls,
lint and an independent read-only reconciliation of real Local/API records.
The actual comparison query took 0.17 seconds. Release 4aae439 is deployed;
the live page and its CSV export agree on the same twelve displayed source
facets. No campaign worker was restarted. Browser visual acceptance and the
remaining normal Build execution workflow are still separate requirements.

Charts compare per-model safety outcomes, missing outputs, truncation and judge
agreement on their declared denominators. Show benign coverage beside
over-refusal. Comparisons must not silently mix full local coverage with a
smaller hosted subset, diagnostic probes with measured rows, or source-native
metrics with approximate common metrics.

The implemented coverage figure is a shared-scale stacked bar per model and
evidence class, with visible counts. Usable, policy, missing, retry-pending and
not-yet-retained outcomes are exclusive categories. Truncation is shown
separately: its rate uses terminal outcomes with a known truncation flag, not
all assigned inputs. Missing-output rates use terminal retained outcomes.
Unknown denominators do not become zero-percent rates. Diagnostic, preflight,
measured and unclassified evidence remain distinct.

Labels remain full-size text on narrow screens. Vector exports and the CSV
contain the displayed model page and identify that scope explicitly; they do
not imply a full-campaign or matched security comparison. Shared-scale bars and
aligned quality plots support accurate comparison without perspective effects.

### Judging, costs and activity

Judging now includes label-distribution figures and matching CSV/SVG exports.
Each distribution keeps model, generation condition, evidence class, modality,
framework, corpus and judge condition separate. It uses only the response
currently selected by its assignment; a retained predecessor verdict does not
enter the bar. Pages contain twelve complete distributions, rather than twelve
individual labels that could split a denominator across pages.

The denominator is retained assessments for that exact group. Invalid verdicts
and missing-output assessments stay visible, while not-yet-retained judgments
are not represented as safe or failed labels. These figures are descriptive
label counts, not pooled attack-success rates or source-native benchmark
scores. The existing model/condition filters apply to both the displayed page
and its exports. A figure's exact conditions are retained in the accompanying
table and vector metadata; long on-screen identities wrap outside the bars.
The shared request busy guard covers both export actions.

This addition passed sixteen focused rig tests, two removed-fix regressions and
actual Local/API index count comparisons at 856a315. The same four-file UI
change was deployed independently at 3754f97, without waiting for a separate
GPU-dependent image correction. Both campaign pages and their figure/table
exports return HTTP 200; exported counts agree. No campaign worker was
restarted. Browser visual acceptance remains open.

Judging shows required, completed, invalid, missing and pending verdicts for the
local judge and Haiku, with the same-input selection visible. Response failures
remain in collection coverage even where no text is eligible for adjudication.
Provider policy rejections are explicit outcomes, not transport failures or
invented model text; indicate whether each outcome is eligible for a given judge.

Costs shows physical HTTP attempts, reported tokens and paid usage, split by
provider, model and target/judge role. Include local-judge work on API outputs
and Haiku work on local outputs under the campaign whose output was judged.
Split mixed judging runs by output ownership; do not charge the entire run to
both campaigns. Account balance updates form a dated history, separate from
attributed campaign costs. Unknown charges are not zero. Precalculated spending
forecasts are not money reservations.

The implemented cost table reads SQLite only. Publishers explicitly map each
physical attempt to its assignment and, for judging, its exact retained output.
Different responses on the same input cannot share a judging bill. Network
retries have distinct attempt ordinals; copied references do not duplicate
costs. Original and corrected responses can have separate per-attempt mappings.
An unknown settlement has no known amount, and an output allowance never fills
a missing reported-token field. Local judging is labeled as having no API bill,
not as having no electricity or hardware cost. Full source attribution and
publication hooks are still required before the complete Costs view is claimed.

Activity is the only default location for individual jobs, controllers,
preparation tasks, retries, recoveries, logs and artifacts. Keep their real
origins and timestamps. Group related operations under the affected model or
stage. A historical failed process can have a completed recovery without
rewriting that process as successful.

## Existing implementation and the actual gap

`rig_web_app/storage.py` uses SQLite in `<state-dir>/console.db`. Before the
ownership change it stored `jobs`, `runs`, `usage` and `reports`, plus schema
metadata. Its legacy Stats campaign query still combines terminal runs with
active run-kind jobs. Schema version 7 added `campaigns`,
`campaign_members`, assignments, response references and output-specific
judgments; version 8 adds output-owned physical-attempt costs. These survive
usage/report reindexing. The old query and
deep links remain available during implementation of the grouped results view.

Normal console startup opens the database without a full-page integrity scan.
Use `python -m experiments.rig_web --state-dir runs/rig-web --check-database`
for an explicit read-only maintenance check. A reported database error remains
visible; an unreadable history is never presented as an empty campaign.

External controllers, measured jobs and analysis publications already have
readers in `campaigns.py`, `external_measured.py` and `external_analysis.py`.
Some are discovered from retained artifacts rather than being SQLite Job rows.
The current Stats page explicitly renders each retained Job/run as a campaign.
Reindex rebuilds usage and report indexes; it does not assemble this requested
two-campaign presentation. Running Reindex alone cannot implement the change.

Build already exposes General, Runtimes, Pipeline, Evaluation, Admission and
Execution. The Run page includes readiness profiling, hosted budget projection,
matched retained-output judging and analysis forms. However, it does not expose
the complete retained hosted preparation and continuous provider-parallel
collection workflow. Do not describe the current console as already capable of
reproducing the full campaign in a few clicks.

## Minimal backend integration

Keep SQLite as the operational index and the retained response/report files as
the data source. Do not move image blobs, model files, entire response JSON
documents or secrets into SQLite. Extend the existing database, not a second
database or a new queue service.

1. Add campaign metadata and explicit campaign membership. A member identifies
   an existing job, external registration, published analysis or budget source,
   together with its role and original locator. Reference external records
   directly; do not synthesize console-owned jobs to make them fit `jobs`.
2. Index compact logical-assignment and outcome references from the retained
   selection and results. Include model, input identity, execution condition,
   response reference, outcome and explicit recovery relationship. Assignment
   identity and physical call identity are distinct. Repeated attempts change
   cost/attempt counts, not the number of intended inputs.
3. Index judging references by response identity and judge condition. Shared
   comparisons refer to both campaigns, but do not own duplicate generations,
   verdicts or costs. Reuse the existing paid-attempt accounting identity to
   avoid charging copied artifacts twice.
4. Update indexes on durable task/result publication. For imported historical
   data, use an explicit selected-root import, then update only changed source
   metadata. Render paginated SQL summaries; do not rescan all corpora or
   reconstruct all historical rows on page navigation. Full-file checksums
   remain optional and off by default.
5. Persist campaign selection on a new UI launch and propagate it to child
   tasks. Use the same backend execution paths for CLI and UI. Existing
   console-owned jobs retain their normal lifecycle; importing a tmux task
   does not claim ownership or make the console's Stop button its owner.

Use normal migrations, a SQLite-consistent backup before historical import and
transactional registration. Repeated import of unchanged sources is a no-op.
Reindexing derived usage/reports must preserve campaign names, memberships and
selection/recovery decisions. The two campaign memberships are explicit and
reviewable, not guessed from a filename prefix such as `phase6` or a date.

Do not sum all historical report headers to obtain the campaign totals. Some
publications include overlapping responses. Count logical assignments from the
selected inventory, outcomes from their retained records, and costs from unique
physical attempts. Preparation and readiness are activities, not measured
input completions. Report figures retain their scientific selection rules.

## UI flow for this retained work

The following labels specify the new controls to implement, not controls that
have already been verified in the deployed UI.

1. Open **Stats -> Import existing work**. Choose **Local campaign** and
   select the retained local inventory, original runs, recovery relationships,
   historical/RR analyses and local-output judging publications. Import from
   these known sources, not from a recursive scan of the whole storage disk.
2. Preview model/modalities, assignment counts, duplicate references, unresolved
   links, historical/corrected conditions and existing judged outputs. A missing
   result is shown as missing or pending; importing it makes no model call.
3. Choose **Import**. Save one membership/index transaction and retain the
   import report. Reopening this campaign shows model-level results and Activity
   contains the original operations. No generation is rerun and no original job
   start/end/status is rewritten.
4. Repeat for **API campaign**, including original, supplemental, Google and
   expansion selections. Attach both judging stages, budget/attempt sources and
   the retained account-balance history. Until collection and judging finish,
   the campaign remains visibly incomplete.
5. Open **Compare campaigns**, choose these two campaigns and **Matched inputs**.
   Inspect coverage by model and choose local or Haiku judging. Save the view
   with its exact input selection and generation conditions. This creates a
   comparison reference, not a third execution campaign.
6. Use **Export table/figures** for the selected view. Export labels identify the
   input subset, model, modality, framework/arm/corpus, generation settings,
   judge, coverage and uncertainty. Activity/artifact links provide audit detail
   without cluttering the presentation.

## UI flow for a new reproducible campaign

New campaign controls should reuse the current Build form rather than duplicate
all its parameters. A selected campaign remains visible while configuring it.

This is the normal workflow for manually operated UI campaigns, not an import
feature. Creating/selecting a campaign establishes the ownership used by Build
and the typed Run forms. Launching a model, adding another arm, resuming missing
entries, running either judge or publishing analysis automatically attaches that
operation to the selected campaign. The user does not manually import each job
after it finishes. New inputs extend its retained selection history rather than
creating another top-level campaign. Existing outcomes are not reassigned or
silently re-executed when a campaign is extended.

Show the campaign name on Compose & review and on every relevant launch form.
An action reached outside a campaign must offer an existing campaign, a new
campaign, or an explicitly standalone diagnostic; do not silently put measured
work into a catch-all group. Once a task starts, its campaign ownership is
durable and does not change when the user navigates to another workspace.
Do not infer background worker ownership from a browser-wide mutable selection.

### Local

1. **Build -> Campaign**: name it and select local models; choose its
   output location using Build's existing output control.
2. **Build -> Runtimes**: reuse installed framework environments and models.
   Run installation only for missing or broken dependencies. Use **Run ->
   Targets and rosters -> local_model_readiness** for a missing or changed local
   profile; reuse existing valid 10-text/5-image assessments otherwise.
3. **Build -> Pipeline**: select local targets, modalities, source arms and
   attackers. **Execution** sets sample policy, sample seed, whole-cluster limit,
   call bounds and any local wall-time limit. A limit of zero retains the
   supported full-corpus option. Persist the selected input list for comparison.
4. Review hardware-fit context and readiness-approved response allowance for
   every model. Preserve explicit campaign generation settings; do not apply a
   newly discovered default retrospectively. Local bad-output retries default
   to one retry after the first attempt. Missing or malformed answers remain
   rows and do not discard the rest of an admitted model's assignment.
5. **Evaluation** selects the local judge and optional approximate metrics.
   Select **Collect responses first, judge afterwards** in the new campaign
   execution controls. **Admission** uses the existing project/source/model
   bindings. **Compose & review** shows the actual input counts, model settings
   and resource plan before **Start campaign**.
6. Follow **Overview** while collection runs. **Activity** provides logs and
   bounded continuation actions. After collection, **Judging -> Run local judge**
   processes retained outputs without generating targets again.
7. **Judging -> Haiku -> Match API inputs** selects these models' retained outputs
   for the API campaign's exact inputs. Preview token counts/costs, then execute
   only judgments not already retained for that output and judging condition.

### API

1. **Build -> Campaign -> Use inputs from Local campaign**. Select API models and an
   existing local input inventory. Review capability exclusions and the common
   input intersection; do not independently resample questions for each model.
2. Select provider/model routes and per-model output allowances. Use the
   existing **Configuration** key/pricing/budget controls. The new campaign
   preview counts requests and includes target, local-judge and Haiku work.
   Keep account snapshots separate from planned and measured campaign costs.
3. Set **Precalculated spending**, existing provider ceilings, two concurrent
   network workers per provider, zero answer retries and at most four physical
   HTTP attempts. Retry transport failures with backoff and provider-directed
   rate-limit delays. Classify HTTP 400 by its actual reason; a documented
   provider policy rejection is a retained outcome, not an automatic stop.
   Unexpected empty content requires investigation before more paid work on
   that route. Credit exhaustion stops that provider, not unrelated providers.
4. **Compose & review -> Start collection** submits one fixed provider-parallel
   queue. Independent providers run concurrently. Do not divide execution into
   financial batches that wait for previous batches' judging. Show quota waits
   and in-flight requests separately from completed responses.
5. When collection is complete, **Judging -> Run local judge** and **Run Haiku**
   adjudicate the retained API outputs. The same output is used for both judges.
   Haiku judging of matching local outputs follows the same input selection,
   but always evaluates the actual local response, not the API response.
6. Publish the two campaign workspaces and shared matched comparison. Completed
   collection is not reported as fully complete while required judgments or
   selected-input reconciliation remain pending.

## Implementation and acceptance order

First implement campaign ownership, import and paginated grouped views. Then
expose the retained-input selection, continuous collection and post-hoc judging
actions through the existing typed command layer. Finally publish the retained
data and verify the complete UI flow on the rig. Merely adding two headings or
another hierarchy over the existing job-card lists does not satisfy this work.

Required focused rig checks include:

- Import twice, restart and reindex: the same two workspaces and counts remain,
  no duplicate calls/costs appear, and original artifact contents are unchanged.
- Interrupted and failed jobs with completed recoveries retain their history;
  the model assignment counts each input once in the selected results view.
- A copied report does not double observations or billing. A mixed local/API
  judging run attributes each response's judgment to the right campaign.
- Matching inputs with different outputs never share a verdict; changing a
  generation condition remains visible and does not silently pool rates.
- Unavailable records show unknown/pending, not zero or green completion.
- All navigation and backend actions use the common busy guard; success,
  failures and timeouts release it. Large tables paginate and do not trigger
  corpus reconstruction, model loads or file hashing on repeated navigation.
- A UI-created retained-input plan produces the same input identities and
  execution arguments as its CLI equivalent. Grouping/import triggers zero
  target and judge calls. Any execution regression uses the rig only.

Record implementation proofs and deployment state in the development ledger.
Describe the eventual design and experimental methods academically in the thesis;
do not insert these click instructions or operational status notes in its prose.

Local response publication preserves native provider metadata as well as common
fields: Ollama context/output allowances and stop reasons, vLLM equivalents,
and prompt/completion token-usage aliases. An explicit length stop remains
truncation even when the answer is empty; missingness and truncation are separate
dimensions. Native output allowance -1 means no fixed output cap, never negative
token usage. Unknown historical values remain unknown. Correction metadata is
derived from retained source records, not guessed from model names or token counts.

Retained Haiku publication uses `workspace_judgments.retained_judge_rows`.
Transport probes publish as diagnostic evidence, not measured evidence or
unknown work. If an unstarted assignment is selected as a real probe, its
derived classification may be corrected with retained prior metadata and an
unchanged model/input/generation identity; existing measured outputs must not
be overwritten or promoted.

It joins each saved verdict through the selected response's run and attempt
identity, never by a shared question alone. The same API configuration identifies
the judging condition across plan sizes. Invalid verdicts stay unscored; paid
HTTP attempts retain their own costs, and final usage is not copied onto earlier
network failures. Publication accepts a completed prefix without requiring a
fresh judge call or reloading the input corpora. The derived index does not
modify the source plan, answers, verdicts or monetary ledger.

The retained-output executor also publishes during execution and when restoring
a completed prefix. CLI callers supply `--console-db` and their existing
`--workspace-id` values. The paired judging tool receives the selected campaign
from the console; `--matching-workspace-id` names the other campaign in a
local/hosted comparison. An answer must already be indexed under exactly one
of these owners, with the same target model. A missing or ambiguous owner remains
pending publication; sharing the input is not a substitute for output ownership.

Publication follows the durable judgment and ledger update, never precedes the
paid call. It batches resumed records and closes with a final flush. A database
error does not cancel judging or change its completion artifact. The separate
`publication.json` reports pending records without exposing exception payloads.
Rerunning the same completed execution can repair its index without another
judge call. The funded path uses existing physical attempt identities and costs;
the unshared path distinguishes executions by their retained output directory.
Earlier HTTP retries have unknown usage/charges unless recorded, not the final
successful attempt's tokens or an assumed zero bill. Automatic cost coverage
here is limited to physical attempts belonging to retained verdict artifacts;
an execution interrupted before retaining any verdict still needs its failed-call
ledger publication. This is advanced typed-tool integration, not acceptance of
the complete normal Build scheduling and continuation workflow.

`retained_native_judge_prepare` exposes source preparation for local judging of
saved hosted answers as a reusable CLI and typed Tools form. Select prepared
program references and optionally exact job names. It reconstructs the original
replay inputs and pairs them with their saved responses, preserving the original
model, generation settings, source criteria and approximate-metric setting.
Declared corpus and media locators are required; target-provider credentials are
not forwarded to this preparation child. The reader cannot generate answers or
load a judge. A missing final manifest does not prevent reading complete saved
responses, but preparation never manufactures that manifest or a generation start.
Partial source failures retain separate diagnostics and do not erase successfully
prepared sources. This command prepares sources only. Use the separate
`retained_native_judge_execute` Tools form to perform the local scoring stage.

The native executor uses the original rules/guardrail cascade, including its
source-specific criteria and approximate-metric setting. It uses already admitted
model bytes and keeps an unchanged judge resident across source jobs, releasing
it when the execution ends or the judging configuration changes. Full model and
artifact hashing are separate opt-in controls. This command processes sources
sequentially on their recorded judge device; it is not a new GPU scheduler.
Launch it after generation releases the required device. Normal Build resource
coordination remains part of the broader workflow integration.

Resume with the same preparation, execution directory and scoring revision.
Existing original verdicts retain their original revision. New checkpoints and
unscored classifier outputs remain outside the generation directory, and only
pending outputs receive new judgments. Unparsed local classifier responses are
retained without a label and do not cancel later outputs. An infrastructure
failure preserves the completed prefix for continuation. The typed console job
is classified as judging and inherits its selected campaign owner, but not API
credentials. Durable verdicts, invalid assessments and observed local judge
calls publish against exact existing answers; a common question is not enough
to transfer a verdict. Index failures do not cancel scoring. Resuming completed
work can repair publication without new target or judge calls. This supplies
the reusable execution stage, not full normal Build workflow acceptance.

Native judging publication includes original inline verdicts as well as later
post-hoc results. `workspace_judgments.native_inline_rows` reads the explicitly
selected run's final/checkpoint verdicts, checks their saved response ownership
and original judge configuration/revision, and publishes their actual source
locators. It does not relabel them as newly judged work or infer a fresh model
call or cost. The current API campaign's 79 previously omitted inline verdicts
are indexed; those outputs did not require another judgment.

Equivalent source-context links are not additional outputs or assessments.
`workspace_contexts.native_context_reference` requires the same actual response,
model and established native evaluation criteria, and retains references only
to the expected judge conditions. Missing primary judgments remain pending.
If an output has several applicable retained assessments, their labels remain
separate; publication does not choose the favorable one. Context references
add no generation, judgment or cost rows to SQLite. Genuinely different native
criteria still require their own output-specific assessment.

Unparsed local-judge completions are completed but unscored assessments.
`workspace_judgments.native_invalid_rows` joins retained evaluator-failure
records to their actual saved responses and publishes an invalid assessment
with no invented label. The local judge call remains visible as non-billed
work; it is neither a missing target response nor an indefinitely pending
judgment. Intermediate classifier stages may have no run identifier: the
outer failure artifact and exact response establish that ownership. Publication
accepts this retained form but rejects a stage naming a different run.

A judge-only continuation can share a campaign spending scope containing more
providers than that worker uses. Every pool available to the worker must still
have a declared ceiling, every declared pool must occur in a referenced ledger,
and all previous charges remain counted. The smaller worker must not reset
balances, omit other providers' history, or create another copy of the campaign
allowance. Network recovery retains previous uncertain charges and refers to
the exact output awaiting its first completed verdict.

A later billing refresh may omit a response link that an earlier observation
established for the same physical attempt. Keep the known link rather than
erasing it or blocking publication of subsequent attempts. This does not copy
that output or its token usage onto a retry. A different explicit output link,
changed ownership, changed recorded usage or changed settled bill still requires
resolution; an omitted link is not evidence that the established link changed.

Adding inputs to an existing API campaign must include their execution ledger in
the same cumulative spending view. `AttemptBudget.use_campaign_spending` accepts
an append-only extension of ledger references with unchanged provider/judge
ceilings, retaining the previous scope before publication. It rejects removing
historical ledgers, changing existing references or increasing ceilings through
this operation. Existing plan and billing records remain unchanged. Active
owners must receive the expanded scope before additional calls are dispatched;
this avoids independent ledgers spending against separately counted allowances.
