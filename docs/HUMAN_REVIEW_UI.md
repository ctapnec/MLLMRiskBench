# Human evaluation through Rig Web

Status: implementation under focused rig and browser acceptance; not yet
published on the production console. No actual human ratings have been collected.

## Purpose and scope

Human review assesses retained model responses without generating new target
answers or buying automated judgments. It complements the local cascade, Haiku
and response-SVM analyses; their agreement cannot replace human assessment.
The common audit follows `experiments/PROTOCOL.md` and `docs/METRICS.md`.
Source-task classification needs its separate existing rubric and analysis.

## Operator workflow

1. Open Human evaluation from a campaign. Prepare a fixed sample with the
   existing audit command, preserving complete selected source clusters and
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

## Acceptance required before deployment

Run focused tests on the rig, including role isolation, hidden-field leakage,
two distinct raters, consent and qualification, draft revision conflicts,
immutable submissions, disagreement resolution, missing media, escaped content,
exact export multiplicity and the existing analysis's prepared-form binding.
Reverse the relevant fix in a bounded regression to demonstrate sensitivity.
Perform browser acceptance with isolated synthetic study data, including error
and busy-state handling, mobile layout, independent sessions, restart/resume and
export. Synthetic ratings must never enter an actual campaign's human evidence.
