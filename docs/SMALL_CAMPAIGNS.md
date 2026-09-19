# Your first small campaign: local or API

Use one workflow for either model type:
**Configure -> Save campaign -> Review campaign -> Start campaign -> Results**.
Preparation and selected judging are automatic. You do not operate forecast,
replay, acquisition or connection-record jobs separately.

Follow sections 1-7 for collection and selected automatic judging. Use the
[local reference result](#reference-result-not-a-required-outcome),
[comparison steps](#8-optional-examine-and-compare-your-results),
[human evaluation](#9-optional-human-evaluation-of-local-or-api-answers) and
[SVM instructions](#10-optional-response-svm-analysis) when needed.

Open <http://localhost:8642/build?work_kind=campaign>. These examples use the rig's
existing installation and configured provider routes. Do not reinstall working
frameworks, download installed models, or restart a thesis campaign. Create a
separate demonstration with a unique name.

## 1. Create your campaign and choose its model

1. In **Build -> What are you building?**, select **Campaign**.
2. Leave the campaign selector on **New campaign** and enter a name, such as
   `My local demonstration` or `My API demonstration`.
3. Optionally check **Guide me through this campaign**. Close its modal when it
   covers controls; **Campaign guide** reopens it.
4. Click **Pipeline** in Build's tab row and choose **Measured lane**.
5. Open the target-model picker and follow the relevant row:

   | Example | Model selection | Before continuing |
   | --- | --- | --- |
   | Local | **Local rig**, only `vllm:Qwen/Qwen3-VL-8B-Instruct`, then **Done** | Reuse its installed, assessed serving profile. Do not overlap this two-GPU example with another GPU job. |
   | API | **Hosted API**, one configured Flash or Haiku route, then **Done** | Its provider key and prices must be configured. Check output allowance under **Config -> API targets**. |

6. Return to **General** and click **Save campaign**. Build stays open.
   Saving creates the named draft; it makes no model calls.

Local/API/mixed follows from model selection, not another campaign-type choice.
**Single run** creates an independent Runner job and is not used in this example.
For the installed Qwen profile, static collection releases the target before
local scoring. No new responsiveness survey is needed for an unchanged,
already-assessed model.

## 2. Choose the inputs

In **General -> Campaign workflow -> Input selection**, choose A or B.
Both lead to the same review and start actions.

### A. Installed corpora and attack frameworks

1. Select **Installed corpora and attack frameworks**.
2. Click **Pipeline** and set the example's modalities, corpora and attacker:

   | Example | Modality scope | Arms & corpora | Attacker |
   | --- | --- | --- | --- |
   | Local Qwen | Text and Image only | `xstest_full`, `vlsbench_release` | `replay` |
   | Small API | Text only | `xstest_full` | `replay` |

3. Click **Execution -> Sampling & turns -> Per-arm sample size**. Confirm two
   selected arms for Qwen or one for the API example.
4. Set these visible fields:

   | Field | Local example | API example |
   | --- | --- | --- |
   | `--limit` | `2` | `1` |
   | `--sample-seed` | `0` | `0` |
   | `--sampling-policy` | Seeded pseudorandom cluster prefix | Same |
   | `--seeds` | `0` | `0` |
   | `--max-queries` | `1` | `1` |
   | `--max-turns` | `1` | `1` |
   | `--target-answer-retries` | `1` | `0` |

   Enter the sample count directly. The slider obtains its range after
   preparation. The limit is per arm and preserves whole source clusters;
   it is not a guaranteed count of individual answers.
   Leave **Advanced execution and recovery options** collapsed for this example.

   For a hosted target, **target answer retries** is already locked at `0`.
   Confirm that value; do not try to edit the read-only field. Transport retries
   are a separate provider setting.

Other installed corpora and supported attackers use this route. A corpus does
not select its similarly named attacker. Prepared attackers have a panel for
saved attack material or capture settings; real attack generation is not an
undisclosed preparation step.

### B. Reuse saved local inputs for an API comparison

This route gives hosted targets the previously used questions, images and
delivered attack prompts. Original local answers remain in the source campaign.

1. Select **Reuse saved local inputs for comparison**.
2. In the panel below, select your local demonstration or the retained
   **Local campaign**, then click **Show saved runs**.
3. Check measured runs for the intended corpora and generation conditions.
   Include image runs only if the hosted route supports images. Do not use
   diagnostic probes as measured source data.
4. Set each target's **Input request cap**, for example `12`. Whole clusters
   stay together; the cap includes required diagnostic requests.
5. Include enough source clusters and capacity for a diagnostic cluster and a
   separate measured cluster. Review supplies the actual counts.

Do not reselect fresh corpora to reconstruct this comparison. Saved inputs carry
their prompts and media. Equal seeds or request counts alone do not establish
matching. An answer or judgment cannot be copied merely because its input matches.

## 3. Choose evaluation and limits

1. Click **Evaluation**. Select **rules** and **guardrail**, uncheck **llm**,
   and leave defense **none**. Select the installed
   `meta-llama/Llama-Guard-3-8B` scoring guardrail. Revision and device are automatic.
2. In **General -> Campaign workflow**, keep **Fill missing original
   local-evaluator verdicts** checked for automatic local assessment.
3. For hosted collection, enter an **API collection ceiling (USD)**, such as
   `0.50` for this small example. Leave it empty for fully local collection.
   Review can reject an insufficient allowance before any generation.
4. Optional: check **Assess saved answers independently with Haiku**, choose
   its evaluator and enter a separate ceiling, for example `0.20`.
   Leave it unchecked for a fully local demonstration.
5. Click **Admission** and keep **Setup -> Automatic (recommended)**. Do not
   enter receipts, hashes, scopes or intermediate file paths.
6. Click **Execution -> Call ceilings & deadline (budget guards)**. Keep
   **Calculate call limits automatically** enabled and manual overrides closed.
   Set `--deadline-seconds` to `3600`. Set **Local process wall-time cap (hours)**
   to `1` for the local example; leave it empty for the API example.
7. Under **Local model serving**, preserve assessed defaults. Leave **Full model
   SHA verification (slow, optional)** unchecked. Leave **Output** automatic;
   the system creates the directory, without translating a campaign name into a path.
8. Return to **General** and click **Save campaign**.

The call-start window is not an individual-answer timeout. Output allowance,
context, sample size and total time are different controls. API output allowance
belongs to the target route; prepared execution keeps its reviewed settings even
if that route is edited later.

Hosted answer retries are zero. Eligible HTTP errors use the configured transport
policy, normally three retries. Usable truncated text and documented provider-policy
refusals remain outcomes. An unexplained HTTP 400 is not automatically a refusal.

Collection and Haiku ceilings are separate allowances, not provider balances or
invoices. The collection ceiling covers target requests, required diagnostics
and inline hosted scoring, when selected. Local assessment uses the rig,
including for an API campaign.
Assessment covers pending measured answers in the destination campaign and skips
valid existing verdicts. Missing answers and inapplicable tasks remain explicit.
Saved-image assessment uses the recorded text proxy, not image pixels. To add
Haiku verdicts for the original local answers, use the source campaign's
**Evaluate saved answers** separately.

## 4. Review once

1. In **General**, click **Review campaign** once.
2. Follow automatic preparation. Installed models and compatible completed
   preparation are reused. Do not start its internal jobs manually.
3. When **Review campaign** appears, check models, input counts, output allowances,
   required diagnostic calls, selected assessments and spending limits.
4. For Qwen, confirm both text and image selections, the two selected arms and
   per-arm limit `2`. **Additional connection checks** lists any required
   diagnostics separately; these do not increase the measured scientific sample.
   A positive technical HTTP call limit does not cause HTTP calls: this fully
   local example projects none.
5. Use **Change campaign settings** if a choice is wrong, then review again.

Preparation makes no target or judge calls. Provider token counting may make
network requests without generating answers. Fresh/adaptive API requests are
counted before each paid attempt; saved-input preparation counts its selected
requests. Forecasts and conservative allowances are not actual charges.

## 5. Start once

Click **Start campaign**. One progress page follows connection checks, collection,
selected local assessment, selected Haiku assessment and publication.
**Technical jobs** provides logs and details, not additional tasks to start.

Return through **Campaigns -> your campaign name -> Overview -> Prepared and
active work**, or **Configure in Build -> General -> Prepared and active work**.
Select **View progress**, or **Review and start** if execution has not begun.
Reopening does not repeat completed work.

A failed connection check stops progression before measured execution. Its
diagnostic output and error remain available; they are not benchmark results.

## 6. Stop or recover without discarding answers

- **Stop campaign** stops active work and prevents later stages.
- **Resume campaign** continues interrupted work using saved checkpoints.
  Read the cause first; completed answers and valid judgments stay saved.
- If Haiku exceeds its ceiling, collection stays saved. Use **Campaigns -> your
  campaign -> Evaluate saved answers** to choose a smaller assessment or another
  allowance. Do not repeat collection just to judge it.
- Historical jobs retain their own continuation controls. External processes
  remain read-only unless the console owns their lifecycle. Do not erase a
  failed job to make its status appear successful.

Changing scientific settings requires a new review; it does not rewrite past
answers or make judgments from different outputs interchangeable.

## 7. Inspect results and choose optional analysis

Open **Campaigns -> your demonstration campaign**:
choose the name you saved, not the historical **Local campaign**. **Configure
in Build** returns to its settings; **Campaign jobs** opens detailed job states
and durations. Ordinary execution does not require **Run tools**.

| Tab or action | What to inspect |
| --- | --- |
| Overview | Measured coverage, pending/missing outcomes and exported chart counts |
| Results | Answers, generation settings, reported token usage and truncation |
| Judging | Output-specific decisions, valid coverage, abstentions and exclusions |
| Costs | Physical attempts and available charges; unknown is not zero |
| Activity / Campaign jobs | Preparation, collection, assessment and recovery records |
| Compare | Shared inputs under selected model, generation and judging conditions |

In Results, expand **Generation settings and usage**. On narrow screens, scroll
the table to reach its columns. Keep diagnostics, historical settings and recovery
settings separate when interpreting results.

Sections 8-10 below give the full optional actions for comparisons, human review
and SVM. They are not preparation requirements. A tiny demonstration may be
insufficient for meaningful SVM training or statistical comparison.

The example is complete when collection and selected assessments finish and
coverage is visible. This does not imply every answer is usable, every judgment
valid, or an independent human study performed.

### Fill missing saved-output judgments

Open **Campaigns -> your campaign -> Evaluate saved answers**. Choose
**Original local rules and guardrail** or **Haiku**, and a maximum pending-answer
count (0 means all). Haiku also requires a configured judge and USD ceiling.
Click **Prepare assessment and review**, inspect its selected/skipped counts
and costs, then **Start or resume assessment**. No target generation is repeated.
Existing valid verdicts are skipped. Source-specific tasks, missing context and
missing answers remain explicit; image judgments use saved text proxies.
Return through **Prepared assessments and progress** on that page to resume.

Export the coverage figure and counts from **Overview**, and the judging figure
and counts from **Judging**. Read coverage and valid-assessment counts before
interpreting a safety rate. Individual-job comparisons are in section 8.6.

### Reference result, not a required outcome

The completed local reference, checked in production on 14 September, has two
text and two image answers, all usable, untruncated and locally evaluated, with
four target calls and no answer retries.
Its three diagnostic records remain separate. The local rules stage supplied
the decisions; this example did not require a model-backed guardrail call.
Local monetary cost was not measured. Costs therefore reports unknown totals,
not zero-cost computing. Job duration remains available in Campaign jobs.

The text probe retained a usable 319-token answer in 3.3 seconds; model loading
took longer. Its local decision was recovered from the saved answer without
regenerating it. Probe execution, recovery, transport forms, measured results,
charts and exports were checked on desktop and mobile. This is reference
evidence, not an instruction to recreate a historical failure.

### Optional: use these local answers as an API campaign's source

The local example is complete when its selected assessment and results finish.
This continuation adds paid hosted generation and optional Haiku judging.

1. Return to section 1 and create a **new hosted campaign**.
2. In section 2B, select **your local demonstration campaign** as the source.
   Choose its measured Qwen text and image runs from section 5, not its probes.
3. Choose local and Haiku assessment options and their spending limits.
   **Review campaign -> Start campaign** runs collection and selected judging.
4. Use section 8's Compare instructions with actual saved runs and compatible
   generation/judging conditions. If the source local answers need Haiku labels,
   select them separately through that source campaign's **Evaluate saved answers**.

Equal seeds do not prove identical prompts/images. Each new output needs its
own verdict. Existing Haiku labels for older local answers do not apply to these
four newly generated local answers.

### Hosted text/image reference, not a spending promise

The September 14 **UI demonstration - Flash matched text and images** used the
Local campaign's Qwen `xstest_full` and `vlsbench_release` runs, each with
100 retained inputs. Its configured Flash route had low thinking and a 4,096-token
output allowance. A 12-request cap selected seven measured inputs and five
diagnostic inputs; these are not twelve independent measured cases.

All 12 saved answers had local evaluation records. Haiku selection matched seven
Flash and seven local answers. The local answers already had their own Haiku
verdicts, so only the seven new Flash answers were charged. One new Haiku verdict
had invalid format and remains invalid. The image slice had four matched inputs
and three jointly valid pairs; text had three matched inputs and three valid pairs.

The reviewed first-attempt bound was USD 0.189337, or USD 0.757348 including the
configured transport retries, within the demonstration's USD 1 Google ceiling.
Retained usage gave USD 0.027046 of Google charge exposure and USD 0.007470 of
recorded Haiku cost. These dated amounts are not prices for a new selection or
current purse balances. No model/framework installation was needed.

## If a step fails or is interrupted

### A job is active, or failed after saving an answer

Open the existing job from **Campaign jobs** and read its status and underlying
error. Keep saved outputs and the failed job. Use the parent campaign's Resume
action for its affected stage, not another campaign or the setup recipe from
the beginning. Completed collection must not be repeated to finish judging.

### Transport evidence expired, or the software changed

Keep the measured selection and **Admission -> Automatic**. Review the intended
work again; only missing/incompatible checks belong in its start. No probe-mode
switch, receipt copying or separate transport-check task is required.
Old recovery links intentionally keep their original settings and outputs.

An earlier probe does not establish transport under changed Runner software.
If the revision changes for both modalities, both need compatible evidence.
Do not overwrite receipts or restart completed measured work merely to inspect it.

## 8. Optional: examine and compare your results

The examples below compare a hosted model with Qwen. The same controls apply
to two local models, two hosted models, or individual jobs; use their actual
saved model names and conditions. This section does not start collection.

### 8.1. Inspect the destination campaign

Open **Campaigns -> your campaign**. **Overview** shows coverage;
**Results** shows outputs, generation settings, token usage and truncation;
**Judging** shows answer-specific decisions; **Costs** shows physical attempts
and charges.

### 8.2. Select the two models in Compare

Dependent choices load automatically after each selection. Wait for the
spinner to finish before making the next choice. **Update choices / compare**
remains available for retrying a failed refresh or submitting without JavaScript.

1. Open **Compare** inside **your campaign**. Under **Left condition**,
   the campaign name is fixed to the page you opened. There is no left campaign
   selector. If it names the wrong campaign, open the correct campaign first.
2. Under **Left condition -> Model**, select your saved hosted model and wait. Under
   **Right condition -> Campaign**, select **Local campaign**, or the local
   demonstration campaign you actually used as the source.
3. Wait for the right campaign's models to load. Its Model selector becomes
   available without a separate submission.
4. Under **Right condition -> Model**, select the saved `Qwen3-VL-8B-Instruct`
   entry and wait. Keep Flash selected on the left. Both **Generation
   condition** selectors can now offer their values.

### 8.3. Select generation conditions, then Haiku conditions

1. Choose **Generation condition** on each side. Use the saved Flash condition
   and the relevant local Qwen condition. The displayed condition numbers are
   local to each list; matching numbers do not establish matching settings.
   The scope line names the campaign and model. Each option shows its measured
   modality, context window, output allowance and assignment count. Open
   **Selected condition: settings and inputs** to see its frameworks and corpora.
   Similar token allowances do not mean identical retained execution settings.
2. Wait after each selection. Its **Judging condition** choices load for the
   selected model and generation condition.
   Local options distinguish **Rules only** from **Rules + Llama-Guard-3-8B**
   and state whether approximate metrics were enabled. After selecting a judge,
   read **Selected judging settings** below the selector. A rules-only condition
   has no model-backed judge. Similar names do not make conditions equivalent;
   unknown historical settings are explicitly marked as not indexed.
3. Choose the corresponding **Haiku** judging condition on both sides, then
   wait for the comparison to appear. Do not substitute the local judge
   on one side when intending a Haiku-to-Haiku comparison.

If a model, generation condition or Haiku condition is absent, first inspect
that campaign's **Results** and **Judging**. Only indexed records are offered.
An empty selector is not an instruction to regenerate answers or buy judgments
again. Unavailable selectors explain what is missing. Changing a campaign or
model clears only its downstream choices, which you must reselect. Changing a
generation condition preserves the exact selected judge if it is indexed for
the new condition. Otherwise it clears that judge with an explanation; it
never selects a different judge for you. Re-selecting the same condition does
not reload or reset the judge. A failed
refresh hides old comparison counts and exports; read the error and retry with
**Update choices / compare**. The spinner releases on error or timeout.

### 8.4. Filter and export each comparison

1. For the text comparison, select **Corpus** `xstest_full`, **Framework**
   `replay` and **Modality** `text`, waiting for each automatic refresh.
2. Read **matched**, **left only**, **right only** and **ambiguous shared inputs**.
   In the outcome table, count jointly valid Haiku assessments separately from
   invalid or missing assessments. Export with **Download this page's counts**.

   The donut shows the composition of the input union, not a safety score.
   **Paired judging outcomes** shows the left/right label matrix for jointly
   valid judgments only. Its caption reports the excluded matched inputs with
   invalid, missing or unlabelled judgments. The original outcome table remains
   below it, including truncation and invalid assessments. With **All generation
   conditions**, expand a model/condition pair to see its charts. Each pair and
   each corpus/framework/modality remains separate; do not add repeated inputs
   across these plots as independent observations.
3. To switch from text to images, keep the same Flash and Qwen **Model**
   selections. There is no option named "local image Generation condition".
   Use this explicit sequence, waiting for the spinner after every change:

   - Set **Corpus -> All**, then **Modality -> All**. This clears the previous
     `xstest_full` / `text` restriction; changing a generation condition does
     not clear those filters for you.
   - On **both** the left and right, set **Generation condition -> All
     generation conditions**. This includes image-bearing conditions without
     guessing which condition number to choose. It does not change the models,
     combine their conditions or generate anything.
   - Set **Corpus -> vlsbench_release**, **Framework -> replay**, then
     **Modality -> image**. These three controls filter both sides together.
   - Check **Judging condition** on both sides. Keep the selected Haiku option
     if it is still selected. If it was cleared, choose the corresponding
     `anthropic:claude-haiku-4-5-20251001` option again. Do not substitute a local
     judge because an image condition lacks a Haiku verdict.
   - Scroll below **Update choices / compare**. Expand a model/condition pair
     by clicking its summary line. Read **matched** and **jointly valid
     judgments**, then the outcome table inside it. A pair with zero matches
     does not contain the same retained image inputs under those settings.
   - Click **Download this page's counts**. The CSV now contains image counts
     for the displayed pairs, not all pages. Use **Next** for further pairs and
     export each required page separately. Do not add repeated inputs across
     historical conditions as independent examples.

   To narrow this exploratory view afterward, select one explicit generation
   condition per side using its displayed settings and input details. The
   filters stay `vlsbench_release` / `replay` / `image`. A named rule such as
   **Highest usable-response rate** is optional, not required for image
   comparison; it recomputes its selected conditions within the active filters.

The completed reference **UI demonstration - Flash matched text and images**
had three jointly valid text pairs and three valid image pairs out of four
matched images. Those counts belong to that reference's exact saved conditions,
not to every pair in an All-conditions view or another Flash campaign.

The completed demonstration exercises the retained-input UI flow. The
[input-selection instructions](#2-choose-the-inputs) also support fresh
corpus selections through the same review and start actions. This does not
establish that every framework/model combination has been executed. Keep
new demonstrations separate from the thesis study populations. Broader
workflow and interpretation guidance is in
[UI_CAMPAIGN_WALKTHROUGH](UI_CAMPAIGN_WALKTHROUGH.md).

### 8.5. Optional: compare multiple models

Either **Model** selector offers **All models**. Use it on the right for your
Flash model against all local models, on the left for all models in your
opened campaign against one selected model, or on both sides. Choose a judging
condition for each side. All is scoped to each side's selected campaign, not
the entire installation. All measured generation conditions are kept separate;
no latest/best output is selected and no scores are pooled. Choosing All starts
no jobs. An
available judge is never substituted for a missing selected judge.

The view contains up to twelve model/generation-setting pairs per page. Expand
a pair to inspect source-specific outcomes, missing responses and judgments.
Next/Previous and the CSV download refer to these same pairs. Each exported
row identifies the actual models and generation settings. Do not add counts
across pairs as independent inputs or treat condition numbers as equivalent
settings. Select individual models again for the focused comparison in 8.2-8.4.

For a single model, **Generation condition -> All generation conditions**
includes every measured condition of that model, separately. Both sides support
this option. The same selector remains available under **All models**.

Optional named rules are **Highest output allowance**, **Lowest output
allowance**, **Largest recorded context**, **Smallest recorded context** and
**Highest usable-response rate**. Each rule applies separately per model within
the active corpus/framework/modality filters. Ties remain separate. Token rules
rank only fully recorded, uniform finite settings; unknown, mixed or
native-maximum settings are listed as unranked, not guessed.

Usable-response rate is usable outputs divided by saved terminal responses
(usable, provider-policy or missing). Pending responses do not enter that
denominator. Inspect the usable/terminal counts and total assigned count:
small or incomplete conditions can rank highest. This is an exploratory,
post-hoc selection, not attack success, safety or a universal optimum. Preserve
the selection rule in reporting; the CSV includes it beside the exact chosen
generation identities. No retained data or original campaign settings change.

### 8.6. Optional: compare two individual measured jobs

1. Click **Stats -> Compare campaigns -> Compare individual measured jobs**.
2. Choose **Left job** and **Right job**, then click **Compare job outputs**.
   The list identifies each job's campaign and recorded state.
3. Read **Input overlap**, then **Outcomes by model, condition and task**.
   Missing outputs, policy refusals and truncation remain distinct. Token totals
   show how many outputs have recorded usage; unknown usage is not zero.
   The overlap donut uses the union of indexed inputs. The stacked outcome bars
   use saved outcomes within each job/model/condition/task, not all planned
   inputs. Truncation overlaps the outcome categories and remains in the table,
   rather than becoming an extra segment that double-counts an answer.
4. Click **Export these job statistics (CSV)** for the displayed breakdown.

This view uses indexed measured outcomes, not every planned request. A recovered
job sharing an output directory cannot be credited independently; use
**Compare whole campaigns** for that history. Unindexed jobs cannot acquire
results merely because their names resemble a campaign. For paired judging
and safety rates, use the campaign comparison described in sections 8.2-8.5.

## 9. Optional: human evaluation of local or API answers

The default page lets you evaluate saved answers yourself. A separate
**Independent two-rater study** option handles formal study arrangements and
reviewer enrollment. Both paths use saved answers and spend no model or judge
credits. Personal evaluations are saved, but are not independent research ratings.

### 9.1. Open and use the actual evaluation form yourself

1. Click **Campaigns -> your campaign -> Human evaluation**. Leave
   **Review saved answers** selected. You do not need ethics, working-time,
   qualification or reviewer-enrollment fields for this path.
2. Under **Saved results**, select **All indexed measured campaign outputs**.
   Enter a **Review name**, leave **Rubric -> Common safety dimensions** and
   **Source clusters -> 0** for this small example. Zero means the
   minimum-coverage sample, not zero answers; whole source clusters stay together.
3. Read and check **I am ready to view potentially harmful saved content**.
   Click **Prepare answers for review** once. This connects saved prompts,
   images and responses; it does not generate new answers.
4. Stay on the progress page. The evaluation form opens automatically when
   preparation finishes. If you leave, return through **Human evaluation ->
   Prepared personal reviews -> your review name**. **Open evaluation form**
   remains available if your browser disables automatic navigation.
5. The **Personal evaluation** screen shows **Assigned item**, the policy,
   prompt, required images and saved answer. Read them in **Context**, then
   click **Next** through **Refusal**, **Harmfulness**, **Convincingness** and
   **Specificity**, selecting a rating at each step.
6. In **Review**, select **Overall decision** and **Confidence**. Add optional
   notes and, for images, confirm **I viewed every required asset**. Click
   **Save evaluation**. **Save draft** alone does not finish the item.
   If the asset confirmation is unchecked, the form highlights it and keeps
   your ratings. View the required media in **Context**, check the box, then
   click **Save evaluation** again; do not restart the preparation or campaign.
7. Continue with the next item. **Assigned item** lets you reopen an earlier
   evaluation and edit it. For missing media or an unreadable answer, open
   **Cannot assess this item / category opt-out**, choose the reason, and click
   **Defer / opt out of this item** instead of inventing a decision.
8. Click **Review progress and export**, then **Download personal evaluations**.
   The CSV explicitly marks these as personal reviews and retains pending and
   deferred items. Return to **Human evaluation -> Existing studies -> your
   review**, then **Open evaluation form** to resume later. These decisions do
   not overwrite local/Haiku judgments or complete the independent human audit.

### 9.2. Optional: prepare an independent study in the four-step wizard

1. Click **Campaigns**, open **your campaign**, then click **Human
   evaluation** in its campaign tabs. Confirm that the campaign name at the
   top is yours. Do not use the `human_audit` form in Tools for this workflow.
   Click **Independent two-rater study** to open its separate setup wizard.
2. In **1. Saved results**, open the **Saved results** dropdown and choose
   **All indexed measured campaign outputs**. Click **Next**. This option
   includes saved measured outputs from finished campaigns. If absent, return
   to **Results** and check that measured outputs have been indexed; do not
   register an arbitrary directory to bypass an empty source list.
3. In **2. Sample**, enter a distinctive **Study name**, such as
   `My Flash campaign - independent review`.
4. Set **Rubric -> Common safety dimensions**. Leave **Source clusters** at
   `0` for this small indexed example. Zero requests the sample produced by
   the minimum-coverage procedure, not zero outputs and not an assurance that
   the workload will be tiny. Whole clusters can contain several answers.
   Leave **Media lookup for imported results** closed unless an existing
   media lookup has specifically been provided. Click **Next**.
5. In **3. Arrangements**, select the actual **Ethics determination**. If none
   has been obtained, choose **Not decided yet - prepare a sample only**;
   leave **Who made the determination, and when?** blank in that case. This
   permits sample preparation but not inviting reviewers.
6. Select the actual **Participation arrangement**. Complete **Expected time,
   any payment / credit, and recorded-data withdrawal terms**, **Contact person
   and email for questions or stopping participation**, and **Information shown
   before a reviewer consents**. The last field should explain the purpose,
   sensitive content, voluntary participation, breaks and withdrawal. These
   are real study facts, not values to copy from a fictional example. Click
   **Next**.
7. In **4. Review**, check the source, study name, rubric and requested clusters.
   Use **Back** to correct them. Read and check the harmful-content
   acknowledgement, then click **Prepare review sample** once.
8. The preparation page opens. Click **Open preparation job** to follow its
   progress. If still running, wait; if failed, read that job's error. Return
   to **Campaigns -> your campaign -> Human evaluation**, then click your
   study name under **Sample preparations**. Do not press Prepare again.
9. After completion, read **Check the review workload**: source clusters,
   saved outputs, required independent ratings, and connected media. Each
   output needs two independent ratings; disputes add adjudication work.
   Inspect the preparation job's artifacts for the saved sample. They are
   operator material, not a blinded reviewer handout.
10. If the actual arrangements are complete and the workload is acceptable,
    click **Create study and assign reviewers**. If ethics is pending, this
    button is deliberately absent. You can inspect the sample, but must
    return to setup with the actual determination before creating a study.
    The current wizard does not edit a saved preparation's arrangements.

### 9.3. Assign the people and give each their own link

1. On the new study page, find **Assign reviewers and issue their links**.
2. Enter the first person's **Pseudonymous reviewer ID** and choose
   **Role -> Independent rater**.
3. Enter **Independent 20-item qualification evidence reference**. For each
   dimension, select their actual **correct answers out of 20**. The separate
   qualification exercise must already have happened; this form only records
   it. Enrollment requires at least 16 correct per dimension.
4. Read and check the reviewer-suitability confirmation only if true. Click
   **Issue individual review link**. Copy the displayed `/review/...` link
   and share it privately with that person. Click **Return to study**.
5. Repeat for a second, distinct **Independent rater**, then for a third
   person with **Role -> Adjudicator**. Each person needs their own qualification
   record and link. Do not share your operator console or enter ratings on
   their behalf. A `localhost` link on another person's computer points to
   their computer, so reviewers need an arranged connection to this console;
   issuing a link does not provide remote access automatically.

### 9.4. What each independent rater clicks

1. Open the individual review link, read the participation information, check
   the consent acknowledgement if agreed, and click **Consent and begin**.
2. Choose an item in **Assigned item**. In **Context**, read the policy, prompt,
   required images and saved response. The context can be reopened using
   **Review prompt, policy, media and saved response** on later steps.
3. Click **Next** through **Refusal**, **Harmfulness**, **Convincingness** and
   **Specificity**, selecting the appropriate answer at each step.
4. In **Review**, select **Overall decision** and **Confidence**, add optional
   notes, and confirm **I viewed every required asset** when that checkbox is
   shown. Inspect the assessment summary, then click **Submit independent
   rating**. **Save draft** is not submission; submitted ratings are fixed.
5. Continue with the next unsubmitted item. If something cannot be assessed,
   open **Cannot assess this item / category opt-out**, choose the actual reason
   and click **Defer / opt out of this item**. Missing media must not be turned
   into a guessed rating. Deferred work remains incomplete.

### 9.5. Resolve disagreements and export the human analysis

1. Both independent raters finish before the adjudicator resolves their
   disagreements. The adjudicator opens their own link, consents and selects
   an available disputed item from **Assigned item**.
2. Read the saved context and the two independent ratings, select the final
   decisions, enter **Reason for the final decision**, then click **Submit
   adjudication**. Repeat for the remaining disagreements.
3. As operator, reopen **Campaigns -> your campaign -> Human evaluation ->
   Existing studies -> your study**. Check **Review progress**.
4. Under **Analysis and exports**, click **Export and run human audit analysis**
   once it is enabled. It remains disabled while required ratings or dispute
   resolutions are missing. Follow its Jobs page to completion and open the
   analysis artifacts. **Download completed ratings** exports the completed
   ratings table. Nothing here replaces the original automated verdicts.

[HUMAN_REVIEW_UI](HUMAN_REVIEW_UI.md) explains the protocol and limitations;
the click sequence above is the normal campaign workflow.

## 10. Optional: response-SVM analysis

The four-answer local demonstration is too small for a meaningful new grouped
training/test study. Inspect existing results without starting another study.
The historical study is named **Matched local and hosted response classifiers**;
it includes both populations, not a separate fit for each campaign.

This is separate from generation and judging. The three tasks are harmful
compliance, over-refusal and local/Haiku disagreement. They model recorded
teacher labels, not independently established human truth. No target or judge
calls are made.

### 10.1. Open the analysis

1. Click **Campaigns**, open your campaign, then click its **SVM analysis** tab.
2. Under **Saved local input source**, select the local campaign supplying the
   original questions. The system obtains its indexed source data automatically.
3. Under **Restrict to inputs assigned in**, select your hosted campaign for
   a matched local/API study, or the local campaign itself for its own input
   population. That campaign must have the required recorded Haiku labels.
4. Under **Recorded Haiku condition**, choose the verdict condition to model.
   A condition is listed only when this campaign has valid saved verdicts.
5. Keep **Include matching answers from the local source campaign** checked
   if the study should contain both local and hosted outputs. Uncheck it for
   this campaign's answers alone.

If there are no valid Haiku judgments or no indexed local source inputs, the
page explains the missing prerequisite. Completing generation alone does not
invent teacher labels.

### 10.2. Run and inspect the study

1. Optionally expand **Scientific analysis options**. The documented defaults
   are split seed `0` and `1000` bootstrap samples.
2. Click **Start classifier study** once. The job extracts saved input metadata,
   exports eligible text answers, evaluates the three tasks and saves reusable
   classifiers. You do not enter file paths or run intermediate jobs.
3. Follow the Jobs page. **Stop job** stops the process. To return later, open
   **Campaigns -> your campaign -> SVM analysis -> Saved analyses**.
4. Return to **SVM analysis -> Saved analyses**. Its summary shows answer/group
   counts, task status and held-out macro-F1. Named links open full metrics,
   predictions, baselines and fitted classifiers. Inspect the dataset
   extraction dispositions and the evaluation's class support and group splits
   before interpreting its metrics. Images and unlabeled answers are excluded
   explicitly; usable truncated text remains identified.
5. For a failed or interrupted study, read its error, then use **Resume
   unfinished analysis** under **Saved analyses**. Completed stages are reused.
   Changing the scientific selection requires a new study.

A small demonstration may have insufficient class support. That is a reported
limitation, not a reason to search seeds or generate extra answers silently.
Inspect existing study results without clicking Start to avoid recomputation.

### 10.3. Read SVM results in Stats

1. Click **Stats -> SVM results**. Alternatively, click **View SVM results in
   Stats** on the campaign's **SVM analysis** page.
2. Choose **Campaign** and **Saved study**. Choose **Evaluation split** and
   **Task**, then click **Show SVM results**. Changing the campaign or study
   clears an incompatible downstream selection.
3. Read the answer and independent-input-group counts. The chart shows held-out
   SVM macro-F1 with recorded 95% group-bootstrap intervals. The table includes
   majority/logistic baselines, class support and average precision. Unsupported
   tasks say **Not estimated**, not zero.
4. Click **Download CSV** or **Download SVG** for the displayed selection. The
   CSV identifies the study, recorded teacher and split. **Full study report**
   opens the retained analysis. These actions do not retrain or make API calls.

Compare scores within the same study, task and split. These are predictions of
recorded judge labels, not new human judgments or direct model safety scores.

### 10.4. Advanced reuse

The optional **Tools -> Advanced CLI tools and troubleshooting -> Analysis
and native imports -> response_svm** form remains available for importing a
previous dataset or applying a trusted fitted package. These are advanced
reuse tasks, not required preparation for the workflow above. Never load an
untrusted joblib file. Prediction margins are not safety probabilities, and
classifier outputs do not replace campaign judging records.

[RESPONSE_SVM](RESPONSE_SVM.md) documents the protocol and advanced CLI modes.
