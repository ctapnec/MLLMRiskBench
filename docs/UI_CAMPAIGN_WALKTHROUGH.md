# Running and examining campaigns in the web UI

For exact models, field values and clicks, use
[Your first small campaign: local or API](SMALL_CAMPAIGNS.md).
For comparison, exports, human evaluation and SVM, use
[Results and optional analysis](SMALL_CAMPAIGNS.md#8-optional-examine-and-compare-your-results).
This page explains navigation and interpretation, without a second setup recipe.
The [previous detailed record](archive/HISTORICAL_UI_CAMPAIGN_WALKTHROUGH.md) preserves
its dated examples, technical notes and original sequences for historical use.

## Create a campaign or a single run

**Build** is the experiment editor. Choose **Campaign** for coordinated
collection and assessment, or **Single run** for one independent Runner job.
Local, API and mixed describe the selected models, not separate creation wizards.

A named measured campaign follows **Save campaign -> Review campaign ->
Start campaign**. General owns the fresh/saved input choice, assessment options
and applicable spending ceilings. Pipeline owns models, modalities, corpora and
attackers; Evaluation owns scoring and defenses; Execution owns sampling and
resource limits. Admission defaults to automatic technical setup.

Saving keeps Build open. Review prepares the experiment without generating
answers or verdicts. It can contact a provider to count tokens. One Start then
executes the reviewed connection diagnostics, collection and selected assessment.
The progress page owns all handoffs; Technical jobs is for inspection.
Existing installed runtimes and compatible preparation are reused.

Single runs retain **Compose & review** and their own explicit execution start.
Offline runs have mock outputs, not measured model evidence. Older saved
preparations retain their original continuation controls, but their separate
preparation actions are not the recipe for new campaigns.

Modality scope persists across save/reopen. A selected corpus is required before
its sample-size controls become active; the exact range slider needs a matching
no-call projection. A per-arm sample limit, output allowance and wall-time limit
are distinct controls. Model-weight checksums remain optional and off by default.

## Fresh inputs or saved local inputs

**General -> Campaign workflow -> Input selection** offers installed
corpora/frameworks or reuse of saved local inputs for hosted comparison.
For reuse, choose the source campaign, click **Show saved runs**, select measured
runs and set per-model request caps. No question, image or original answer is
regenerated during input preparation. Whole source clusters stay together.

Both choices use Review campaign and Start campaign. The saved-input executor
can collect across providers concurrently, with bounded per-provider workers.
This does not imply arbitrary direct Runner jobs are parallelized.
Diagnostics remain separate from measured cases and need enough input capacity.

Equal seeds or equal counts do not establish identical inputs. Match actual
rendered prompts, media and attack conditions. Different model caps can produce
overlapping rather than identical subsets. Live adaptive trajectories are not
transferable unless their actual delivered prompts are replayed.

## Return, stop and resume

Open **Campaigns -> your campaign -> Overview -> Prepared and active work**,
or return through **Configure in Build -> General**. Follow the parent campaign,
not separate internal preparation tasks. The active workflow is listed first,
with its current stage and running/waiting job links; recent finished history
follows. This summary reflects the page load. **View progress** opens the
automatically updating parent page. Job links inspect work without restarting it.

**Stop campaign** stops active work and prevents later handoffs.
**Resume campaign** continues the affected stage using saved checkpoints.
Completed collection is not repeated because judging needs recovery.
If assessment exceeds its spending ceiling, use **Evaluate saved answers** to
choose a smaller pending selection or another allowance.

On Linux, console jobs have a separate process supervisor. Restarting the
console observes a surviving job instead of launching another copy. Lost work
without a terminal record is interrupted, not successful. A failed original
job remains failed even when a later recovery succeeds.

Historical hosted jobs can offer **Review continuation -> Start job**.
That continuation retains original programs, spending history and software
conditions. Its new call-start window does not reset consumed calls or charges.
Imported external workers are read-only unless a real control adapter owns them.

Do not update a checkout while jobs use it. Deployment uses a separate clean
console checkout or the existing execution lock; this is process coordination,
not a model checksum scan. A UI-only update need not change the measured Runner.

## Inspect the retained studies

Open **Campaigns -> Local campaign** or **API campaign**. These are distinct
retained study workspaces, not hard-coded creation types.

- **Overview:** choose the evidence population, model and generation condition.
  All conditions includes historical failures and recoveries; it is not a
  best-answer selection.
- **Results:** inspect the saved answer and **Generation settings and usage**.
  Context, output allowance, reported usage and truncation are separate.
  Recovery history links explicit predecessors and successors without erasing
  either execution or copying its verdict.
- **Judging:** inspect each answer's judging condition and valid coverage.
  Missing, invalid and inapplicable assessments are not safe labels.
- **Costs:** physical attempts and available charges are not account balances.
  Unknown charges are not zero; local computation is not free merely because
  it has no API invoice. Full cost export is campaign-wide, not a Results filter.
- **Activity / Campaign jobs:** inspect actual executions, logs and artifacts.
  The saved Build draft does not describe every historical recovery condition.

Charts and CSV/SVG exports preserve their displayed selection. Inspect
denominators before comparing rates. Diagnoses, preparation and completed jobs
alone are not measured safety evidence.

## Compare and assess saved answers

Compare loads dependent model, generation and judging choices automatically.
Wait for the busy indicator. All models and All generation conditions retain
separate model/condition pairs, never pooled scores. Highest/lowest allowance,
recorded-context and usable-response-rate rules are optional exploratory
selections, not universal safety rankings. Missing metadata stays unknown.

Match the judging condition on both sides when comparing judgments. Haiku must
judge each distinct output; an identical input does not authorize verdict reuse.
Valid existing decisions can be reused for the same retained answer and condition.

Every campaign, including imported historical work, has **Evaluate saved
answers**. Choose the original local evaluator or Haiku, a pending-answer limit,
and Haiku's ceiling when applicable. Prepare/review, then start assessment.
This is for additional or recovered judging; selected assessment in a new
campaign already runs automatically.

Human evaluation and SVM are optional analyses. Personal reviews do not constitute
independent two-rater evidence. SVM predicts recorded teacher labels and requires
adequate class and input-group support. See the
[analysis guide](SMALL_CAMPAIGNS.md#8-optional-examine-and-compare-your-results) for exact actions and limits.

## Guide and common interface behavior

**Guide me through this campaign** enables the contextual modal; save to retain
that preference. It links to the relevant controls, reveals their section and
scrolls to them. It does not fill example values, change scientific selections
or start work. The [small-campaign guide](SMALL_CAMPAIGNS.md) provides the recipe.

The busy indicator covers backend requests and blocks duplicate interaction.
Success, error and timeout release it. A failed comparison refresh hides stale
counts; retry through **Update choices / compare**. Ordinary page reads use
indexed data, not repeated reconstruction of the campaign.

Theme offers Slate, Parchment, Midnight, Ash and Harbor. Selection is local to
the browser. Shared navigation remains present on operator and review pages;
review links do not grant authority to mutate campaign controls. Wide tables
scroll within their cards. Action rows and checkbox labels wrap with consistent
spacing. UI maintenance and regression scope are recorded in
[Campaign workflow contract](CAMPAIGN_WORKSPACES.md) and
[current UI flow acceptance](UI_FLOW_ACCEPTANCE.md). Dated earlier results remain
in the [regression record](archive/OPERATOR_REGRESSION_AUDIT.md).

## Historical demonstration is evidence, not a new recipe

The retained **UI demonstration - Flash matched text and images** is inspectable
without starting anything. Its September 14 selection had seven measured and
five diagnostic inputs. Seven new Flash answers received Haiku assessment;
matching local answers already had their own verdicts. One invalid Haiku verdict
remains explicitly invalid. These dated counts and conditions are not a promise
for a new selection or evidence for every model/framework combination.

CLI recipes and advanced historical imports remain in
[Run and return](../experiments/RUN_AND_RETURN.md). Use explicit retained sources;
never fabricate console-created jobs for externally executed work.
