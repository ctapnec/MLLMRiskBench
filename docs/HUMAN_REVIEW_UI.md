# Human evaluation through Rig Web

Status: the setup and rating wizards are deployed on the production console.
Focused rig tests and isolated desktop/mobile browser checks pass. Real saved
local responses and indexed images have also been displayed successfully.
The indexed-campaign selector, preparation and saved-sample analysis now have
focused rig acceptance. The real browser flow prepared 8,059 API outputs,
registered the sample in an isolated database and displayed saved media on
desktop and mobile. No production study or human verdict was created. The
indexed-campaign connection fixes were deployed on 14 September; the console
database and existing campaign workers were preserved.
The checked 167-output historical image sample now resolves all 167 references
through the recorded source locations. The automatic media preparation and
source-task format fixes have focused rig verification and are deployed.
The operator has subsequently completed seven personal evaluations in the small
Flash demonstration. These are separate from independent two-rater evidence.

## Purpose and scope

Human review assesses retained model responses without generating new target
answers or buying automated judgments. It complements the local cascade, Haiku
and response-SVM analyses; their agreement cannot replace human assessment.
The common audit follows `experiments/PROTOCOL.md` and `docs/METRICS.md`.
Source-task classification needs its separate existing rubric and analysis.

## Operator workflow

### Direct personal evaluation

Open **Campaigns -> the campaign -> Human evaluation**. The default **Review
saved answers** path asks for a saved result set, review name, rubric and
source-cluster count, plus acknowledgement of sensitive content. Click
**Prepare answers for review**, follow the preparation job, then **Open
evaluation form**. The form shows the actual saved prompt, assets and response,
with step-by-step dimension choices, overall decision and confidence.
**Save evaluation** records a personal evaluation; drafts, edits, deferral,
resume and **Download personal evaluations** are supported. There are no
study-arrangement or enrollment fields on this path.
Every review screen retains the console's main navigation, active Campaigns
section and theme control, including personal, rater and adjudicator views.
The item view does not reveal model identities or automated verdicts, but the
shared console menu is not an access-control or experimental-blinding boundary.
Independent work is a study procedure, not enforced by removing navigation.
Only the main console menu is sticky. Campaign and section tabs scroll with
their content so they cannot cover that menu on narrow screens. Browser
acceptance must check that the main links remain unobstructed after scrolling,
not merely that their elements are present in the page.

For an item with images, audio or video, view its required media in **Context**,
then check **I viewed every required asset** on **Review** before final saving.
If unchecked, the form focuses that box and explains the requirement beside it,
without submitting an invalid rating or clearing your choices. **Save draft**
remains available without this confirmation. This applies to personal and
independent ratings; unavailable media must be deferred rather than guessed.

Personal reviews are explicitly separate from independent study evidence.
Their one-reviewer progress and CSV retain unfinished items; they cannot enter
the independent audit export or overwrite automated campaign judgments.

### Independent two-rater study

1. Open **Campaigns -> the campaign -> Human evaluation**, then click
   **Independent two-rater study**. In the setup wizard,
   choose **Saved results**, enter a study name and select the rubric and sample
   size in **Sample**, record **Arrangements**, then **Review -> Prepare review
   sample**. No CLI command is required. This preserves complete selected source clusters and
   all their selected model-condition responses. Show the number of clusters,
   outputs, required independent ratings and the resulting coverage before
   assigning work. Preparation runs as a visible background job.
   Finished campaigns remain available. The setup wizard covers saved results,
   sampling, actual study arrangements and preparation review. Successful
   Runner jobs are discovered from the campaign index. For imported historical
   campaigns, register the existing combined analysis result set once with a
   meaningful scope name; its original files remain unchanged. A selected
   result set is not automatically the whole campaign or a claim that every
   campaign output is eligible. The preparation page shows actual workload
   before creating the study. Failed preparation cannot create a study.
   Preparation connects content-addressed images using the selected results'
   recorded source locations and writes a media lookup beside the sample.
   An existing retained index can be supplied to avoid rebuilding mappings
   already available. The preparation page reports connected references and
   outputs with unavailable assets; it never removes those output rows.
   The viewer resolves only assigned
   identities to files inside configured media roots. An unchanged index is
   cached; it does not scan corpora, hash model weights or fetch remote media.
   A missing mapping remains visibly unavailable, not a lost model response.
   The cluster count must be sufficient for the selected scope's sensitivity
   categories; 20 is a starting value, not a universally valid sample size.
2. Create a study from that prepared sample. Record its campaign, protocol,
   source analysis scope and supervisor/institutional ethics determination,
   consent, compensation and harmful-content welfare arrangements. These
   records document actual decisions; software must never invent them.
3. Assign two distinct qualified pseudonymous raters to each output and an
   adjudicator. Record the independent 20-item qualification evidence and the
   required per-dimension agreement. Ratings cannot begin before the applicable
   study arrangements, qualification and consent have been recorded.
4. Supply individual review links. The rater surface shows only its assigned
   prompt, policy instruction, media, saved response and rubric. It omits model
   and provider identifiers, automated labels, model costs, other raters'
   answers and control-surface navigation. No metadata in its payload or media
   URLs should reveal those hidden fields. Response text itself is preserved,
   including any model self-identification; this remains a blinding limitation.
5. Save drafts automatically, allow explicit independent submission, and
   support uncertainty, inaccessible media, category opt-out and withdrawal.
   Unassessable work remains incomplete, not a fabricated safe label. Saved
   responses and original labels are never edited. A submitted rating is fixed
   before adjudication; accidental edits require an explicit documented reopen.
   The rater wizard starts with policy, prompt, assets and saved answer, then
   moves through refusal, harmfulness, convincingness and specificity before
   the overall decision and submission. Source-task review uses task decision
   and answer format instead. The context can be reopened at every step.
   Reopening a submitted rating is not yet provided by this release; do not
   edit the SQLite records to simulate a new independent submission.
6. Show the adjudicator only cases with two submitted independent ratings.
   Require resolution for each disputed composite label or dimension and
   preserve both independent ratings, the adjudicated decision and rationale.
7. Export the exact prepared two-rater form and completed labels for the
   existing audit analysis. Incomplete or unresolved cases cannot be advertised
   as an analysis-ready complete sample. Run analysis through the normal Jobs
   mechanism and link its report from the study and campaign.

### Which controls to use

The opening page distinguishes the study operator's work from the reviewer's
rating form. **Ethics determination** and **Participation arrangement** are
explicit choices. Select the actual decision, not an assumed approval. **Not
decided yet** permits preparing and inspecting workload but not creating a study
for reviewers. Determination details, contact information and actual consent
terms remain text because they are study-specific facts, not standard labels.
The selection does not itself supply approval or consent.

After sample preparation, **Create study and assign reviewers** opens the
operator's enrollment page. Role and each qualification score are dropdowns;
pseudonymous IDs and the actual qualification evidence reference remain text.
The separate 20-item qualification exercise is not performed by filling this
form. Only a real result can be recorded.

Reviewers use their individual links, not Build or the operator setup page.
Each safety dimension, overall decision and confidence has a selector with an
unanswered state. **Cannot assess this item / category opt-out** offers reasons
for unavailable media, unreadable content, an unclear task, lack of expertise,
sensitive-content opt-out, a break or another reason. Notes remain optional
free text. No decision is prefilled as a successful human rating.

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
  Both actual campaign inventories have been read successfully. Setup turns
  remain separately accounted, and additional source-policy judgments retain
  their own contexts rather than becoming primary-rubric disagreement.
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
