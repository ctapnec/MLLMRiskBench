# Campaign workspaces: current integration contract

This is the developer reference for the current UI/backend boundary.
Use [Small campaigns](SMALL_CAMPAIGNS.md) for operator instructions and
[Results and analysis](SMALL_CAMPAIGNS.md#8-optional-examine-and-compare-your-results) for optional analyses.
The [complete previous document](HISTORICAL_CAMPAIGN_WORKSPACES.md) preserves
earlier design proposals, numeric observations and technical notes. It is not
prescribed as current UI actions. Development findings remain in the ledger.

## Ownership and navigation

A campaign owns a scientific selection of models, arms/corpora and attackers,
its execution runs, judging, recoveries and analyses. A single run is one
independently executable Runner job and can contain multiple inputs.
Local/API/mixed is derived from models, never a second creation wizard.

Build is the experiment editor. Campaigns presents named studies. Jobs defaults
to Substantive work, with Technical - all jobs retaining preparation, diagnostics
and maintenance. Stats exposes campaign/job comparison and SVM results. Tools
contains advanced CLI equivalents, not required operator handoffs.

Campaign identity is captured at launch, not read later from the browser's current
selection. Changing a draft or opening another campaign cannot reassign a running
job. Source local runs keep their source ownership when their inputs are selected
for a hosted comparison. Unassigned external work is not silently treated as an
independent console run.

The retained thesis work is presented as Local campaign and API campaign.
Their phases, dated batch names and controller scripts are not system concepts
or new campaign types. New UI demonstrations have separate owners.

## Definitions and reviewed execution

Definitions preserve validated non-secret settings and required file locators.
The path-redacted job representation is not substituted for an editable draft.
Credentials are not stored in these definitions or exposed in HTML.

For named measured campaigns, Review campaign creates/reuses a durable parent
operation over the existing direct or matched preparation. Required model/source
setup, input extraction, forecasting and token counting are internal stages.
Preparation does not generate answers or verdicts. Token counting may use the
selected provider's counting endpoint.

Start campaign authorizes the reviewed diagnostics, collection and selected
local/Haiku assessment. Diagnostic cases remain separate from measured evidence.
The same progress page owns every handoff. Child operations remain inspectable
under technical details, not additional Review and start tasks. The Guide follows
that parent even when a technical child is the newest indexed activity.

Settings are frozen before execution; later registry or draft edits do not alter
them. Duplicate confirmation cannot launch another copy. Stop prevents later
stages and stops owned active work. Resume preserves successful stages and uses
the existing output checkpoints. A lost launch with retained job files requires
reconciliation, not an assumed-safe duplicate.

Single runs and old saved preparations retain their own explicit review/start
and continuation actions. This compatibility does not reintroduce those internal
handoffs into the new campaign flow.

## Existing executors, not a second experiment engine

Direct work uses the configured Runner. Matched hosted work uses
`hosted_campaign_execute`, its provider-limited dispatcher and counted programs.
Local models and framework environments retain their installed isolated runtimes.

Saved-input preparation preserves whole clusters, original prompts/history,
media and model-specific request limits. Probes consume reviewed diagnostic
assignments; enough source capacity must remain for a separate measured cluster.
The executor can prepare missing runtime/transport bindings from installed models
without adding target inputs or reinstalling runtimes.

Providers can collect concurrently with bounded per-provider network workers.
Each program respects its own diagnostic prerequisites. Unrelated providers are
not held behind another provider's judging. Collection completion alone does not
establish requested assessment completion.

API answer retries are zero; transport retries retain their existing bounded
policy. Classify HTTP 400 by the actual error reason. Documented policy responses
are distinct from malformed requests or transport errors. Usable token-limit
text remains usable and separately truncated; an empty final answer is not
invented from reasoning text.

## Spending and costs

New hosted campaigns supply a collection ceiling and, if selected, an independent
Haiku ceiling. These are not provider account balances.

Direct Runner attempts use the campaign spending controller with frozen route
settings and prices. Admission counts the actual request and output allowance
before each paid attempt. Bridge callbacks and recycled Runner subprocesses keep
that same policy. Retries share the durable allowance; continuation does not
reset it. Conservative unused allowance is not reported as actual expenditure.

Matched preparation retains its counted selection and spending plan. Prepared
collection preserves the program's funded request identities. Independent Haiku
assessment counts the actual eligible saved outputs and stops before spending
if its selection exceeds the reviewed ceiling. The already collected answers
remain available for a smaller or differently funded assessment.

Costs indexes unique physical attempts, token reports and available monetary
records by provider/model/target-or-judge role. Unknown charges remain unknown.
Do not copy final-answer token usage onto earlier failed HTTP attempts.
Judging costs follow the exact assessed output's campaign, not every campaign
sharing its question. Local judging has no provider bill, not zero computing cost.

Historical funding transfers preserve original slots and physical-attempt
history; they do not create new credit or prove a valid verdict. In-flight
attempts reconciled to unknown charge must be republished as unknown, without
repeating the request. Account-purse updates remain a dated history separate
from attributed experiment costs.

## SQLite publication and retained artifacts

The operational index is `<state-dir>/console.db`. Retained result files remain
the scientific data source; model weights, images and secrets do not move into
SQLite. Campaign metadata, memberships, definitions, assignments, response
references, judging references and physical-attempt costs have distinct roles.

Logical assignments and physical calls are not interchangeable. Retry attempts
increase attempt/cost counts, not intended-input counts. A durable missing
response differs from an unissued input. Usable text may also be truncated.

New campaign-owned direct and prepared-hosted executions publish through the
same reusable index writers as explicit CLI imports. Source-row plans can record
planned, reached and not-reached rows before collection. Several trajectory turns
do not become independent source rows. Historical runs lacking such plans keep
that absence explicit.

Publication follows durable checkpoints and changed metadata. A partial final
export must not hide a longer checkpoint tail; locators follow actual stable
response identity, not an assumed row number. Re-importing an older empty outcome
must not clear a retained successor answer. Partial JSONL tails are not outcomes.

A publication error is separate from a generation failure. Saved work remains
recoverable without new target calls. Repeated publication is idempotent; a
billing-only change does not reread all answers. Ordinary page requests use
paginated SQLite queries, not corpus reconstruction or full-file hashing.

Startup does not scan every database page. An explicit maintenance check is
available with `experiments.rig_web --check-database`. An unreadable index is
reported as an error, not an empty campaign. Back up SQLite consistently, including
its WAL, before migration or historical import.

## Historical import and recovery

Import only explicitly selected retained inventories, programs and output roots.
`experiments.campaign_publish` supports hosted program publication; advanced
parameters and native import recipes are in
[Run and return](../experiments/RUN_AND_RETURN.md).
An import does not download models, reconstruct unrelated sources, generate
answers or judge them. Reindexing usage/reports preserves campaign ownership.

Keep real process origins, timestamps and terminal states. External tmux
registrations do not become fabricated console-owned jobs. Stop/resume controls
require actual process ownership. Linux console supervision can observe jobs
across console restarts without repeating them.

A continuation preserves input/model identities, original execution conditions,
spent attempts and successful checkpoints. A new call-start window is not new
funding or permission to regenerate completed answers. If original code is
required, use a separate historical checkout, without reinstalling runtimes or
changing the live console.

Explicit recovery links connect retained predecessor/successor outputs for the
same model/input/task. Conditions, original failures and physical costs remain.
A newer timestamp or more favorable judgment never silently chooses a winner.
Ambiguous historical ownership requires source resolution, not guessed metadata.

## Output-specific assessment

Every campaign exposes Evaluate saved answers. The shared new-campaign flow can
also schedule that assessment automatically. Local assessment restores/continues
the original local cascade; Haiku is independently configured and budgeted.
The selection covers eligible pending measured answers in the destination
campaign, including earlier pending answers, not all source-campaign answers.

Reuse requires the same exact answer and judging condition. Source-specific
inapplicability, missing context, missing outputs and invalid decisions remain
explicit dispositions. Image assessment through this saved-answer path uses a
text proxy; it does not claim pixel-level review.

Legacy paired/inventory judging still supports deliberately matched local/API
populations. It preserves exact output ownership and source context; equal
inputs do not imply equal answer totals when model rosters differ.
A slot owned by a judging executor is not proof that it produced a valid label.

Preparation and execution use the same frozen configuration. An intervening
completed assessment is reused rather than purchased again. Source changes,
ambiguous manifests or unavailable context must be reported, not papered over
with a different model or answer. Original files and judgments stay retained.

## Results, comparison and analysis

Overview and Results distinguish evidence class, model and generation condition.
Show effective context, output allowance, reported tokens, finish reason,
missingness and truncation separately. Advertised maxima do not fill unknown
runtime values. Historical and corrected conditions remain selectable.

Compare uses exact eligible input intersections. It reports matched, left-only,
right-only and ambiguous inputs before judgment/outcome differences. Multiple
assignments do not form a fabricated Cartesian paired sample. All models and
All generation conditions retain separate pairs; exploratory highest/lowest
rules preserve ties and disclose their selection.

Charts and exports keep their selected scope and denominators. Diagnostic work,
source-native metrics and approximate common metrics are not pooled. Report
benign judging coverage beside over-refusal. Page exports and full campaign cost
exports have different scopes and label them explicitly.

Compare exposes a page-scoped source-by-condition-pair difference heatmap and
paired percentage plots. Each measure uses a common denominator on both sides:
all matched assignments for outcome yield, jointly valid non-null labels for
exact label prevalence, or jointly known flags for truncation. Unknown evidence
is not drawn as zero. Labels are not aliased; not_applicable remains a recorded
label. Different labels across different target answers are not automatically
judge disagreement. Source strata and generation conditions are never pooled
into a global safety ranking. These are descriptive proportions, not native
benchmark success rates, significance tests or causal estimates.

The figures reuse the existing indexed comparison counts without extra SQL,
model loading, artifact scans or rescoring. Metric switching and selected SVG
export are browser-local and survive asynchronous comparison-form updates.
The vector chart and the original page CSV share the same selected count rows.
The All view remains bounded to twelve condition pairs per page. Both the
page scope and repeated-input caveat remain visible. Test common denominators,
missing/ambiguous inputs, replaced responses, source filters, pagination,
catalog coverage, escaping, narrow screens, all themes and downloaded SVG data.

Job comparison uses indexed measured outcomes and their recorded ownership;
a shared recovery output directory cannot be credited independently to two jobs.
SVM Stats presents retained studies, held-out metrics, baselines, class support
and input groups. It does not start training or judging. Human review preserves
personal versus independent ratings; neither SVM nor automated agreement replaces
actual independent raters.

## Acceptance and maintenance

Use [Operator regression audit](OPERATOR_REGRESSION_AUDIT.md) for the scenario
matrix and current verification state. Test fresh local, fresh API and retained
API work, single runs, restart, duplicate submission, stop/resume, changed drafts,
missing/invalid output, budget stops, publication, comparison, exports, Guide,
human review, SVM and narrow-screen behavior.

Tests run on the rig using existing runtimes and isolated campaign databases.
Fault injection supplements real retained data; synthetic ratings and diagnostic
calls are never thesis observations. Fix reversals must fail corresponding tests.
Passing bounded scenarios is not a claim that every framework/model combination
or remote-provider failure has been exhausted.
