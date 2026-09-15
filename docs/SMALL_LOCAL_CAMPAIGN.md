# A small local campaign through Build

This guide uses the installed Qwen3-VL model and Llama Guard on the rig. It does
not require a framework installation, a model download or a hosted API call.
The destination is a **new demonstration campaign**, not the thesis Local
campaign. The measured example requests **two text and two image inputs**,
followed by local evaluation. Diagnostic probes are kept separate.

### Before you begin

- Use a new campaign name and output directory. The example below uses
  `My Qwen demonstration` and `my-qwen-demonstration`; replace them consistently
  if you have already used them.
- Do not start this work alongside another GPU job. The installed Qwen profile
  uses both GPUs. Static collection releases the target before local scoring.
- Keep the assessed model settings. Do not repeat the responsiveness survey,
  reinstall the runtimes, download the models or enable full model SHA verification.
- You can inspect the
  [completed reference campaign](http://localhost:8642/campaigns/f082ba4833644521b51eade324ccf94d)
  without restarting it. Its results are described in section 7, not targets
  your new run must reproduce exactly.

### Workflow

| Stage | Sections | Result |
| --- | --- | --- |
| Configure | 1-2 | One saved campaign draft with small, explicit bounds |
| Establish text and image transport | 3-5 | Completed probes and two transport receipts |
| Collect and evaluate | 6 | Four requested measured inputs with local evaluation |
| Inspect | 7 | Results, coverage, charts and exports |
| Optional hosted comparison | 8 | A separate Flash campaign using saved local inputs |

Whenever a step says **return to Build**, open **Campaigns -> your demonstration
campaign -> Configure in Build**. Continue in that same saved campaign. After
clicking a preparation or execution button, follow the opened job until it
finishes; do not launch a second copy while the first is active.

## 1. Create the draft and select the installed models

### 1.1. Create the campaign and select Qwen

1. Open <http://localhost:8642/build?work_kind=campaign>.
2. Leave **Campaign** selected under **What are you building?**. In the campaign
   dropdown choose **New campaign**. Enter `My Qwen demonstration` as its name.
   Optionally check **Guide me through this campaign** to open the in-app guide.
   It suggests steps and links to the controls without starting work. Close it
   whenever you want to configure the page; **Campaign guide** reopens it.
3. Open **Pipeline**. Choose **attestation probe**. Enable Text and Image and
   disable Audio, Video and Tool. Select only `xstest_full` initially.
4. Open the target-model picker, choose **Local rig**, select only
   `vllm:Qwen/Qwen3-VL-8B-Instruct`, then click **Done**.

### 1.2. Configure local evaluation

1. Open **Evaluation**. Keep **rules**, uncheck **llm**, and select **guardrail**.
2. Leave the defense **none**.
3. Set the **scoring** guardrail model to `meta-llama/Llama-Guard-3-8B`, not
   the similarly named defense guardrail model.

Revision and device are automatic, without selection fields. Preparation records
the installed revision; the judge is placed using available GPU memory when it
loads. Saved verdicts retain its actual placement.

## 2. Set the text probe's bounds

### 2.1. Set Admission

1. Open **Admission**. Leave the current project and source receipts supplied
   by the console unchanged.
2. Set **--execution-scope-id** to `my-qwen-demonstration`.
3. Leave the live-attestation rows and maximum-age field empty for this probe.

### 2.2. Set Execution

In **Execution**, set:

| Field | Value |
| --- | --- |
| Per-arm limit | `1` |
| Sampling policy | `seeded_pseudorandom_whole_cluster_prefix_v1` |
| Sample seed / generation seeds | `0` / `0` |
| Maximum queries / turns | `1` / `1` |
| Target answer retries | `1` |
| Target / judge / HTTP ceilings | `16` / `16` / `1` |
| --deadline-seconds | `3600` |
| Local process wall-time cap | Leave empty during probes |
| Output directory | `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-text` |

Uncheck **Exclude tool-conditioned inputs** and leave full model SHA
verification unchecked. The exclusion applies to the standalone synthetic dry
run, not this real probe. HTTP's positive ceiling does not initiate network
calls; the actual local projection should report zero HTTP attempts.

### 2.3. Save and review the draft

1. Return to **General** and click **Save campaign**. This opens **Definition**.
2. Click **Configure in Build -> General -> Compose & review**.
3. Check Qwen, `xstest_full`, probe mode, the bounds and the `probe-text`
   output directory. Saving and reviewing make no model calls.

## 3. Complete preparation, then run the text probe

### 3.1. Run the no-call preflight

1. On the review page, click **Plan & acquire models for no-call preflight**.
   Wait for the plan job to pass.
2. On that job, click **Acquire sealed models**. Wait for completion. This
   reuses the installed store; it is not a request to reinstall the models.
3. Click **Start no-call preflight** and wait for it to pass. The demonstrated
   text projection contains one trajectory, at most two target attempts, one
   local guardrail evaluation and zero HTTP attempts. These are projected
   counts, not calls already made.
4. On that job click **Review this exact lane in the builder**. It opens the
   execution review directly. Check that the projection fits the entered caps.

### 3.2. Start the real text probe

1. Click **Plan & acquire models for this job**. Wait for its plan to pass.
2. Click **Acquire sealed models** and wait for acquisition to pass. This
   prepares the execution, separately from the preceding no-call preflight,
   using the same installed store.
3. Check that the command still shows **--attestation-probe**. Click **Start
   reviewed measured job**. Despite its generic label, this starts the probe,
   not the measured study. **This is the first real target-generation action.**
4. Wait for **passed**. A saved response alone is not completion; local scoring
   and the final result must also finish. The job and its outputs belong to the
   named demonstration campaign.

## 4. Derive the text transport receipt

1. From the demonstration campaign, click **Run tools**.
2. Filter for `live_attestation` and open its form. Keep the demonstration
   campaign selected so this preparation job remains grouped with it.
3. Set **--probe-root** to the text probe output directory from section 2.2:
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-text`.
4. Set **--execution-scope-id** to `my-qwen-demonstration`.
5. Set **--out** to
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/attestation-text.json`.
   This is a new file name, not a directory. Leave **--validate** and **--sha256**
   empty when deriving it.
6. Click **Start job**. When it passes, keep the output path and the `sha256`
   value printed in its result for the measured lane's Admission tab.

Deriving this receipt makes no additional target or judge call. It establishes
the observed transport path, not benchmark performance or human validity.
Keep the software revision unchanged until the measured run. If it changes,
follow the transport-recovery instructions at the end of this guide.

## 5. Repeat for one image input

### 5.1. Change only the corpus and output directory

1. Return to Build and open **Pipeline**. Uncheck `xstest_full` and select only
   `vlsbench_release`.
2. Keep **attestation probe**, Qwen, Text and Image, the scope, seed, bounds and
   evaluation settings unchanged. Keep the live-attestation and maximum-age
   fields empty, as for the text probe.
3. In **Execution**, change Output to
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-image`.
4. Click **General -> Save campaign**, then return to Build and click
   **General -> Compose & review**.

### 5.2. Run the image probe and derive its receipt

1. Follow sections **3.1-3.2** for this image selection. Wait for the real probe
   and its local evaluation to pass before proceeding.
2. Open **Run tools -> live_attestation** as in section 4. Use:

   | Field | Value |
   | --- | --- |
   | --probe-root | `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-image` |
   | --execution-scope-id | `my-qwen-demonstration` |
   | --out | `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/attestation-image.json` |
   | --validate / --sha256 | Leave empty when deriving the receipt |

3. Click **Start job** and wait for it to pass. Keep the new image receipt's
   path and printed digest alongside the text receipt's details.

You now have separate text and image transport receipts. These are preparations
for the measured run, not measured results themselves.

## 6. Configure the small measured run

### 6.1. Change from diagnostic to measured work

1. Return to Build. In **Pipeline**, choose **measured** and select
   `xstest_full` and `vlsbench_release`. Keep only Qwen selected as a target.
2. In **Admission**, enter the text receipt path and its printed digest. Click
   **Add receipt row** for the image receipt and digest. Keep the same scope and
   set maximum age to `24` hours. Refresh only receipts that have actually
   expired or changed.
3. In **Execution**, change the per-arm limit to `2`, set the local process
   wall-time cap to `1` hour and change Output to
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/measured`.
   Keep the other bounds and the one-answer-retry policy unchanged.
4. Click **General -> Save campaign**, then return to Build and click
   **General -> Compose & review**.

### 6.2. Prepare, review and start the measured run

1. Follow **section 3.1** for this new measured selection. Confirm that the
   no-call projection contains the intended text and image inputs and fits
   the caps. Use **Review this exact lane in the builder** after preflight.
2. Click **Plan & acquire models for this job**, wait for the plan, then
   **Acquire sealed models** and wait for completion.
3. Review the command again. It must now use **measured** mode, not
   **--attestation-probe**, and retain both transport receipts.
4. Click **Start reviewed measured job**. This starts real collection on the
   measured selection, followed by local evaluation.
5. Wait for both stages and the final result to finish. A target answer saved
   while local evaluation is still running is not a finished job.

## 7. Inspect results, judging and exports

1. Open **Campaigns -> your demonstration campaign**.
2. Inspect each tab below. Keep diagnostic probes separate from measured cases.

   | Tab | What to inspect |
   | --- | --- |
   | Overview | Measured coverage, missing responses, truncation, charts and their exported counts |
   | Results | Each saved answer; its generation settings, usage and separate Truncated column |
   | Judging | Local decisions, abstentions or inapplicable results; the judging figure and exported counts |
   | Costs | Available usage and cost accounting; an unknown local cost is not zero-cost computing |
   | Campaign jobs | Preparation, collection and evaluation job states and durations |

3. In **Results**, open a row's **Generation settings and usage** to inspect
   context, output allowance, actual token usage and finish reason. On a narrow
   screen, scroll the table horizontally to reach these columns.
4. Export the coverage figure and counts from **Overview**, and the judging
   figure and counts from **Judging**. Read the coverage and valid-assessment
   counts before interpreting a safety rate.

### Reference result, not a required outcome

The completed reference, checked in production on 14 September, has two text
and two image answers, all usable, untruncated and locally evaluated, with four
target calls and no answer retries.
Its three diagnostic records remain separate. The local rules stage supplied
the decisions; this example did not require a model-backed guardrail call.
Local monetary cost was not measured. The Costs page therefore reports unknown
totals, not zero-cost computing. Job duration remains available in Campaign jobs.

The text probe retained a usable 319-token answer in 3.3 seconds; model loading
took longer. Its local decision was recovered from the saved answer without
regenerating it. Probe execution, recovery, transport forms, measured results,
charts and exports were checked on desktop and mobile. This is reference
evidence, not an instruction to recreate a historical failure.

## 8. Optional: compare these answers with a hosted model

The local demonstration is complete after section 7. This optional continuation
uses paid hosted generation and Haiku judging; neither has run merely because
you finished this guide.

1. Open [the small Flash guide](SMALL_API_CAMPAIGN.md) and create a **new hosted
   campaign**. Choose **route 2a - Reuse local inputs**.
2. Select **your demonstration campaign** as its source. Choose the measured
   Qwen text and image runs created in section 6, not the probes or the
   historical run IDs printed in the Flash guide's example.
3. Follow the Flash guide's workload forecast, preparation and reviewed paid
   start. Use the counts for your four-input selection, not its historical
   12-request reference counts or cost.
4. Follow its local and Haiku judging stages, then **Compare** with the actual
   saved runs and compatible generation/judging conditions.

Selecting the same seed independently does not by itself prove identical
prompts and images. Haiku must assess every new selected answer separately;
another model's verdict cannot be copied onto it. Existing Haiku verdicts in
the completed Flash reference belong to its original local counterparts, not
to the four answers you just generated here.

## 9. Human evaluation of your saved local answers

### 9.1. Review the answers yourself

1. Click **Campaigns -> your local demonstration campaign -> Human evaluation**.
   Leave **Review saved answers** selected. This path has no ethics, working-time,
   qualification or reviewer-enrollment fields.
2. Select **Saved results -> All indexed measured campaign outputs**. Enter a
   **Review name**, keep **Rubric -> Common safety dimensions**, and set
   **Source clusters -> 0** for the small indexed example. Zero requests the
   minimum-coverage sample, not zero answers. Whole clusters stay together.
3. Check **I am ready to view potentially harmful saved content**, then click
   **Prepare answers for review** once. The preparation connects existing
   prompts, images and responses without generating or judging anything.
4. Follow **Open preparation job** if needed. When it completes, return to
   **Human evaluation -> Prepared personal reviews -> your review name**.
   Inspect the output count, then click **Open evaluation form**.
5. In **Personal evaluation**, choose an **Assigned item**, read the policy,
   prompt, required assets and saved answer in **Context**, then click **Next**.
6. Select a rating in **Refusal**, **Harmfulness**, **Convincingness** and
   **Specificity**, clicking **Next** after each. In **Review**, select
   **Overall decision** and **Confidence**, add optional notes and confirm
   **I viewed every required asset** when shown. Click **Save evaluation**.
7. Continue through the remaining items. To postpone an unreadable or
   inaccessible item, open **Cannot assess this item / category opt-out**,
   select its reason and click **Defer / opt out of this item**. Do not guess
   a judgment for an image you cannot see.
8. Click **Review progress and export -> Download personal evaluations**.
   Pending and deferred items remain in that export. Reopen the review under
   **Human evaluation -> Existing studies**, then **Open evaluation form** to
   resume or edit your saved personal ratings.

Personal evaluations are labelled as such. They do not overwrite the local or
Haiku verdicts and do not complete the independent two-rater assessment.

### 9.2. Organize a separate independent study when you have actual raters

1. On the same Human evaluation page, click **Independent two-rater study**.
2. In **Saved results**, select the indexed outputs and click **Next**. In
   **Sample**, fill **Study name**, select **Common safety dimensions**, set
   **Source clusters** and click **Next**.
3. In **Arrangements**, record the actual ethics determination, participation
   arrangement, time/withdrawal terms, contact person and reviewer information.
   **Not decided yet - prepare a sample only** allows inspection, not enrollment.
4. Click **Next**, check the acknowledgement in **Review**, then **Prepare
   review sample**. Follow its job, return through **Sample preparations**,
   inspect the workload and click **Create study and assign reviewers** when
   the arrangements permit it.
5. Under **Assign reviewers and issue their links**, enter each person's
   **Pseudonymous reviewer ID**, **Role**, actual **Independent 20-item
   qualification evidence reference** and per-dimension scores. Confirm
   suitability and click **Issue individual review link**. Use **Return to
   study** and repeat for two distinct independent raters and one adjudicator.
   The qualification exercise is separate; at least 16/20 per dimension is
   required. Never invent scores or enter ratings for other people.
6. Each rater opens their own link, clicks **Consent and begin**, evaluates
   items through the dimension wizard, and clicks **Submit independent rating**.
   The adjudicator uses their link for disagreements and clicks **Submit
   adjudication** after entering final decisions and a rationale.
7. Reopen the study as operator. Once **Review progress** is complete, click
   **Export and run human audit analysis** under **Analysis and exports**.
   Follow its Jobs page; **Download completed ratings** supplies the labels.

[SMALL_API_CAMPAIGN sections 9.2-9.5](SMALL_API_CAMPAIGN.md#92-optional-prepare-an-independent-study-in-the-four-step-wizard)
spell out every enrollment/rating field; the controls are identical for local
campaigns. [HUMAN_REVIEW_UI](HUMAN_REVIEW_UI.md) explains the study protocol.

## 10. Optional: response-SVM analysis

These four demonstration answers are insufficient for meaningful SVM training
and held-out evaluation. SVM work is separate from campaign generation and has
no dedicated campaign tab. Use the **response_svm** form in Tools. It makes no
target or judge calls and does not classify images or replace human assessment.

### 10.1. Inspect the completed SVM work without running it again

1. Click **Artifacts** in the top navigation. Browse the results root's
   `engineering/response-svm-20260913-r-checkpoints/analysis` directory.
2. Open `result.json` for the completed grouped study and `predictions.json`
   for its held-out predictions. The three tasks are harmful compliance,
   over-refusal and judge disagreement. They predict recorded teacher labels,
   not independently established human truth.
3. The existing fitted package is at
   `/mnt/stor/data/ura-work/runs/engineering/response-svm-persistence-20260913/fitted/models.joblib`.
   Do not rerun training or packaging just to inspect these artifacts.

### 10.2. Apply that package through the UI

1. Click **Tools -> Analysis and native imports -> response_svm**. Its
   description starts **Retained response classifiers**. Direct link:
   <http://localhost:8642/commands?cmd=response_svm>.
2. In this form's **Save under campaign**, select your local campaign. This
   groups the analysis job; it does not select its input dataset for you.
3. Check **--predict** only. Uncheck **--export**, **--evaluate** and **--package**.
4. Supply **--dataset**, a prepared static-text `dataset.jsonl`, and set
   **--models** to the trusted package path in 10.1. Do not load an arbitrary
   downloaded joblib file. Choose **--features -> response**.
5. Set **--out** to a new directory, for example
   `/mnt/stor/data/ura-work/runs/ui-demos/my-local-svm-predict-01`. Leave the
   export/training fields blank. Click **Start job** inside this form.
6. Follow the job until complete, then open `result.json` for counts and
   `predictions.json` for decisions, uncalibrated scores and non-applicable
   cases. Scores are not safety probabilities. These derived outputs do not
   replace campaign judging records.

For a workflow-only demonstration, the already exported study dataset is
`/mnt/stor/data/ura-work/runs/engineering/response-svm-20260913-r-checkpoints/dataset/dataset.jsonl`.
Using it demonstrates reuse, not evaluation of the four new local answers and
not independent held-out accuracy. Name the job accordingly.

### 10.3. Use your new local outputs or fit a new study

The current **--export** mode needs a matching source-candidate file and valid
Haiku judgments on the selected outputs. Completing the local guide alone
does not supply those Haiku labels. If you completed the matched hosted
continuation in section 8, use **Tools -> response_svm -> --export**, set
**--campaign** to your local demonstration ID, and **--matched-campaign** to
its hosted counterpart's ID. Copy IDs from their `/campaigns/ID` addresses.
Use **Add another value** beside **--campaign** if including both populations.
Do not use the old thesis Local campaign ID as a substitute for your new one.

[SMALL_API_CAMPAIGN 10.2](SMALL_API_CAMPAIGN.md#102-export-the-small-campaigns-eligible-text-answers)
lists the database, candidates, judge-condition and output fields, including
the limits of the historical candidates file. A newly selected corpus may need
its own candidates; there is no automatic arbitrary-corpus exporter in this
form. Inspect the export's `dispositions` before predicting or fitting.

For a sufficiently supported new study, check only **--evaluate**, supply
**--dataset**, a fresh **--out**, **--seed -> 0**, **--max-feature-characters ->
20000** and **--bootstrap -> 1000**, then click **Start job**. Read its support,
group-split, baseline and held-out metrics in `result.json`. Optional
**--package** takes that same dataset plus **--study-result** and
**--study-predictions**, producing a new reusable `models.joblib`; it is not
required for an ordinary evaluation. See [RESPONSE_SVM](RESPONSE_SVM.md) for
the scientific protocol, not additional mandatory campaign stages.

## If a step fails or is interrupted

### A job is still active, or failed after saving an answer

Open its existing job from **Campaign jobs** and read its status and underlying
error. Do not create another campaign or repeat target generation just because
judging has not finished. Keep the saved outputs and the failed job. Use a
recovery action only for the affected stage; this guide's normal setup sequence
is not a recovery procedure for every possible failure.

### Transport evidence expired, or the software changed

1. Refresh only the affected text or image diagnostic probe, not both by default.
   Keep the same campaign and use a **new probe output directory**.
2. When switching back to **attestation probe**, clear both live-attestation
   path/digest rows and the maximum-age field in **Admission**.
3. Complete that probe and derive a receipt with a **new file name**, following
   section 4 or 5. Keep the original probe and receipt.
4. Return to the measured configuration in section 6. Restore the scope,
   maximum age and both receipt rows, replacing only the affected receipt.

An earlier probe does not establish transport under changed software. If the
revision changes for both modalities, refresh both. Do not overwrite receipt
files or restart a completed measured run merely to inspect it.
