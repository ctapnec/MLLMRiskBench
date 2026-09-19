# Campaign results, comparison and optional analysis

This reference applies after either a local or hosted campaign. Collection and selected automatic judging are described in [the API walkthrough](SMALL_API_CAMPAIGN.md) and [the local walkthrough](SMALL_LOCAL_CAMPAIGN.md). Comparison, personal review, independent studies and SVM analysis are optional, not preparation stages.

## 1. Examine and compare your results

### 1.1. Inspect the destination campaign

Open **Campaigns -> your Flash campaign**. **Overview** shows coverage;
**Results** shows outputs, generation settings, token usage and truncation;
**Judging** shows answer-specific decisions; **Costs** shows physical attempts
and charges.

### 1.2. Select the two models in Compare

Dependent choices load automatically after each selection. Wait for the
spinner to finish before making the next choice. **Update choices / compare**
remains available for retrying a failed refresh or submitting without JavaScript.

1. Open **Compare** inside **your Flash campaign**. Under **Left condition**,
   the campaign name is fixed to the page you opened. There is no left campaign
   selector. If it names the wrong campaign, open the correct campaign first.
2. Under **Left condition -> Model**, select your saved Flash model and wait. Under
   **Right condition -> Campaign**, select **Local campaign**, or the local
   demonstration campaign you actually used as the source.
3. Wait for the right campaign's models to load. Its Model selector becomes
   available without a separate submission.
4. Under **Right condition -> Model**, select the saved `Qwen3-VL-8B-Instruct`
   entry and wait. Keep Flash selected on the left. Both **Generation
   condition** selectors can now offer their values.

### 1.3. Select generation conditions, then Haiku conditions

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

### 1.4. Filter and export each comparison

1. For the text comparison, select **Corpus** `xstest_full`, **Framework**
   `replay` and **Modality** `text`, waiting for each automatic refresh.
2. Read **matched**, **left only**, **right only** and **ambiguous shared inputs**.
   In the outcome table, count jointly valid Haiku assessments separately from
   invalid or missing assessments. Export with **Download this page's counts**.
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

The completed route-2a exercise demonstrates that retained-input UI flow.
Section 2b describes the separate direct Runner controls; documenting them is
not evidence that every framework/model combination has been executed. Keep
new demonstrations separate from the thesis study populations. Broader
workflow and interpretation guidance is in
[UI_CAMPAIGN_WALKTHROUGH](UI_CAMPAIGN_WALKTHROUGH.md).

### 1.5. Optional: compare multiple models

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

### 1.6. Optional: compare two individual measured jobs

1. Click **Stats -> Compare campaigns -> Compare individual measured jobs**.
2. Choose **Left job** and **Right job**, then click **Compare job outputs**.
   The list identifies each job's campaign and recorded state.
3. Read **Input overlap**, then **Outcomes by model, condition and task**.
   Missing outputs, policy refusals and truncation remain distinct. Token totals
   show how many outputs have recorded usage; unknown usage is not zero.
4. Click **Export these job statistics (CSV)** for the displayed breakdown.

This view uses indexed measured outcomes, not every planned request. A recovered
job sharing an output directory cannot be credited independently; use
**Compare whole campaigns** for that history. Unindexed jobs cannot acquire
results merely because their names resemble a campaign. For paired judging
and safety rates, use the campaign comparison described in sections 1.2-8.5.

## 2. Human evaluation: review answers yourself or organize an independent study

The default page lets you evaluate saved answers yourself. A separate
**Independent two-rater study** option handles formal study arrangements and
reviewer enrollment. Both paths use saved answers and spend no model or judge
credits. Personal evaluations are saved, but are not independent research ratings.

### 2.1. Open and use the actual evaluation form yourself

1. Click **Campaigns -> your Flash campaign -> Human evaluation**. Leave
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

### 2.2. Optional: prepare an independent study in the four-step wizard

1. Click **Campaigns**, open **your Flash campaign**, then click **Human
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

### 2.3. Assign the people and give each their own link

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

### 2.4. What each independent rater clicks

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

### 2.5. Resolve disagreements and export the human analysis

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

## 3. Optional: response-SVM analysis

This is separate from generation and judging. The three tasks are harmful
compliance, over-refusal and local/Haiku disagreement. They model recorded
teacher labels, not independently established human truth. No target or judge
calls are made.

### 3.1. Open the analysis

1. Click **Campaigns**, open your campaign, then click its **SVM analysis** tab.
2. Under **Saved local input source**, select the local campaign supplying the
   original questions. The system obtains its indexed source data automatically.
3. Under **Restrict to inputs assigned in**, select your hosted campaign.
4. Under **Recorded Haiku condition**, choose the verdict condition to model.
   A condition is listed only when this campaign has valid saved verdicts.
5. Keep **Include matching answers from the local source campaign** checked
   if the study should contain both local and hosted outputs. Uncheck it for
   this campaign's answers alone.

If there are no valid Haiku judgments or no indexed local source inputs, the
page explains the missing prerequisite. Completing generation alone does not
invent teacher labels.

### 3.2. Run and inspect the study

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

### 3.3. Read SVM results in Stats

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

### 3.4. Advanced reuse

The optional **Tools -> Advanced CLI tools and troubleshooting -> Analysis
and native imports -> response_svm** form remains available for importing a
previous dataset or applying a trusted fitted package. These are advanced
reuse tasks, not required preparation for the workflow above. Never load an
untrusted joblib file. Prediction margins are not safety probabilities, and
classifier outputs do not replace campaign judging records.

[RESPONSE_SVM](RESPONSE_SVM.md) documents the protocol and advanced CLI modes.


