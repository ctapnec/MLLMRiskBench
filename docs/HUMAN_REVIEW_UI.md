# Human review: protocol and advanced reference

For the current click-by-click workflow, use
[Small campaigns, section 9](SMALL_CAMPAIGNS.md#9-optional-human-evaluation-of-local-or-api-answers).
It covers personal evaluation, independent-study preparation, enrollment,
rating, adjudication and analysis. This reference explains the protocol,
implementation boundaries and equivalent CLI, not a second sequence of
campaign-preparation steps.

The [20 September historical snapshot](archive/HUMAN_REVIEW_UI_20260920.md)
preserves the earlier document in full, including dated deployment checks,
campaign-specific examples and their limitations. Those observations are not
prerequisites for a new review or acceptance of a later software revision.

## Purpose and scope

Human review assesses retained model responses without generating new target
answers or buying automated judgments. It complements the local cascade, Haiku
and response-SVM analyses; their agreement cannot replace human assessment.
The common audit follows `experiments/PROTOCOL.md` and `docs/METRICS.md`.
Source-task classification needs its separate existing rubric and analysis.

## Personal and independent review are different procedures

Personal evaluation uses the reviewer's own saved judgments. It supports
drafts, edits, deferral, resumption and personal-evaluation export without
independent-study arrangement or enrollment fields. Personal progress and CSV
exports retain unfinished items. These records cannot enter the independent
audit export or overwrite automated campaign judgments.

Independent review requires two distinct qualified pseudonymous raters per
output and an adjudicator. Its arrangements, qualification, consent,
independent submissions and disagreement resolution are substantive
requirements, not fields to fill with assumed decisions. Synthetic acceptance
ratings remain outside actual campaign evidence.

Every review screen retains the console's main navigation, active Campaigns
section and theme control, including personal, rater and adjudicator views.
The item view does not reveal model identities or automated verdicts, but the
shared console menu is not an access-control or experimental-blinding boundary.
Independent work is a study procedure, not enforced by removing navigation.
Only the main console menu is sticky. Campaign and section tabs scroll with
their content so they cannot cover that menu on narrow screens. Browser
acceptance must check that the main links remain unobstructed after scrolling,
not merely that their elements are present in the page.

## Selecting and preparing a review population

Finished campaigns remain available. Successful Runner jobs are discovered
from the campaign index. For imported historical campaigns, select
**All indexed measured campaign outputs**; manual source registration is not
required when the campaign index contains those outputs.
Registering a combined analysis result set is an advanced alternative for
results not represented by that index; its original files remain unchanged.
A selected result set is not automatically the whole campaign or a claim that
every campaign output is eligible.

Preparation preserves complete selected source clusters and all their selected
model-condition responses. It reports clusters, outputs, required independent
ratings and achieved coverage before study enrollment. It runs as a background
job, and failed preparation cannot create a study. The requested cluster count
must be sufficient for the selected scope's sensitivity categories; 20 is a
starting value, not a universally valid sample size.

Preparation connects content-addressed images using the selected results'
recorded source locations and writes a media lookup beside the sample.
An existing retained index can be supplied to avoid rebuilding available
mappings. Preparation reports connected references and outputs with unavailable
assets; it never removes those output rows. The viewer resolves only assigned
identities to files inside configured media roots. An unchanged index is
cached; it does not scan corpora, hash model weights or fetch remote media.
A missing mapping remains visibly unavailable, not a lost model response.

## Study arrangements, qualification and masking

Record the actual campaign, protocol, source analysis scope and
supervisor/institutional ethics determination, consent, compensation and
harmful-content welfare arrangements. Software must never invent them.
**Ethics determination** and **Participation arrangement** are explicit choices.
**Not decided yet** permits preparing and inspecting workload but not creating
a study for reviewers. Determination details, contacts and consent terms remain
study-specific text; selecting an option does not supply approval or consent.

The separate independent 20-item qualification exercise must precede enrollment.
Record its evidence and actual per-dimension scores rather than interpreting
completion of the enrollment form as qualification. Ratings cannot begin until
applicable study arrangements, qualification and consent are recorded.

Each reviewer receives an individual link and sees only assigned prompts,
policy instructions, media, saved responses and the rubric. Rater payloads omit
model and provider identifiers, automated labels, model costs and other raters'
answers. Shared console navigation remains present; it does not grant a
review link authority to alter campaign controls. Item metadata and media URLs
must not reveal the hidden fields. Response text itself is preserved, including
model self-identification, which remains a blinding limitation.

## Rating, deferral and adjudication rules

The rating wizard keeps the policy, prompt, media and saved answer available
throughout assessment. Common safety review records refusal, harmfulness,
convincingness and specificity before the overall decision and confidence.
Source-task review records task decision and answer-format validity instead.
Each selector starts unanswered; no successful human decision is prefilled.

For an item with images, audio or video, inspect all required media and confirm
**I viewed every required asset** before final submission. Without confirmation,
the form focuses the checkbox and explains the requirement without submitting
an invalid rating or clearing choices. **Save draft** remains available.
Unavailable media must be deferred rather than guessed; this applies to
personal and independent ratings.

Deferral supports unavailable media, unreadable content, unclear task, lack of
expertise, sensitive-content opt-out, a break and other reasons. Notes remain
optional free text. Unassessable work stays incomplete, not a fabricated safe
label. Drafts may be saved automatically, but independent submission is explicit.

Original responses and automated labels are never edited. A submitted
independent rating is fixed before adjudication. This release does not provide
reopening of submitted ratings; do not edit SQLite to simulate a new independent
submission. Any future reopening procedure must be explicit and documented.

Adjudication exposes only items with two submitted independent ratings.
Every disputed composite label or dimension requires a valid adjudicated
decision and rationale. Preserve both original independent ratings.
Incomplete or unresolved cases cannot be advertised as a complete,
analysis-ready sample. Export the exact prepared two-rater form and completed
labels for the existing audit analysis, execute analysis through Jobs, and
retain its report with the study and campaign.

## Data and implementation boundaries

- Reuse the console's SQLite database for study, assignment, draft, consent,
  submission and adjudication state. Preserve prepared samples and final
  exports as study artifacts. Do not add an annotation service dependency.
- Keep model/response identities internally for exact joins but use opaque
  item identifiers in rater payloads. Rater sessions must not expose other
  raters' records. The operator console remains a trusted administrative
  surface and is not to be shared as a rater account.
- Render model text as escaped text, never executable HTML. Serve only study-
  assigned local media; missing or inaccessible required assets prevent final
  submission. Never fetch arbitrary remote media during a review page request.
- Use the existing backend-request spinner and duplicate-request guard.
  Autosave must report success or error, preserve unsaved input on failure and
  avoid overwriting a newer draft from another tab. No provider calls are made.
  Personal and completed-independent-rating downloads use the same guarded
  export handler as campaign statistics. It releases the spinner on completion,
  HTTP error or timeout and permits retry without leaving the study page.
- Statistics distinguish assignment completion, rater agreement, adjudication
  and automated-versus-human comparison. Sampling support and undecided cases
  accompany estimates. Do not pool source-task outcomes with common labels or
  present the deterministic achieved sample as a population-validity estimate.
- Imported campaigns include completed final files and durable checkpoints
  scored after generation. Their review inventory follows the assignment's
  explicit selected answer, retains generation conditions and separate judge
  identities, and reads each referenced artifact file once per preparation.
  It must not manufacture a successful original grid from post-hoc judgments.
  Missing source context is reported, never filled from an unrelated output.
  Completed-run choices exclude preflights, dry runs and diagnostic probes.
  Review preparation and analysis use the console's analysis release even when
  measured execution remains pinned to an older Runner. A finalized checkpoint
  is resolved by its exact saved output identity, not its former line number;
  its neighboring media manifest keeps the same name. The child receives the
  configured corpus/media locations, without provider credentials, so installed
  images can be connected automatically. These are preparation-time lookups,
  not scans during navigation or model-weight checks.
  The campaign selector offers all indexed measured outputs, including those
  from finished imported campaigns. Preparation freezes the selected outputs
  and their output-specific judgments. Zero clusters requests the minimum
  produced by deterministic coverage selection; it is not a mathematical
  minimum or a representative random sample. Inspect the actual two-rater
  workload before creating a study. Common and supported source-task frames
  remain separate. Unsupported rubrics and unavailable context stay reported.
  The indexed-campaign analysis reports saved-output agreement and decision
  coverage against the frozen sample, not completion of the original Runner
  grid, live-trajectory ASR or automatic satisfaction of the human-audit gate.
  Setup turns remain separately accounted, and additional source-policy
  judgments retain their own contexts rather than becoming primary-rubric disagreement.
- Source-task label vocabularies use the native exporter's pipe-separated
  format. Producer-to-consumer tests exercise both supported source-task
  families; an independently invented JSON fixture is not the export contract.

## Acceptance required before deployment

Run focused tests on the rig, including role isolation, hidden-field leakage,
two distinct raters, consent and qualification, draft revision conflicts,
immutable submissions, disagreement resolution, missing media, escaped content,
exact export multiplicity and the existing analysis's prepared-form binding.
Reverse the relevant fix in a bounded regression to demonstrate sensitivity.
Perform browser acceptance with isolated synthetic study data, including error
and busy-state handling, mobile layout, independent sessions, restart/resume and
export. Synthetic ratings must never enter an actual campaign's human evidence.

## Equivalent indexed-campaign CLI

`python -m experiments.human_review_campaign --database <console.db> --campaign
<campaign-id> --results-root <runs-root> --mode common --clusters 0 --output
<new-directory>/sample.csv --acknowledge-sensitive-content` prepares the same
sample as the wizard. Use `source_task` for the supported classification rubrics.
The adjacent frozen snapshot is an operator artifact, not a rater handout.
The wizard conceals identities and automated labels that the operator CSV
retains. After actual independent assessment and adjudication, run the same
module with `--snapshot <sample.SNAPSHOT.json.gz> --prepared-rating-form
<sample.csv> --labels <completed.csv> --output <new-analysis.json>`.
Preparation and analysis make no model or judge calls. Indexed media lookup
visits only the selected response files' neighboring manifests, not the whole
campaign store. Unchanged source files are not rewritten.
