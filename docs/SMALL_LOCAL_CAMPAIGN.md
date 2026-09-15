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

## 9. Optional: independent human evaluation

Open **Human evaluation** for this saved campaign, including after completion.
Choose **Saved results**, then use the wizard for the rubric, sample,
participation arrangements and preview. Actual independent raters must supply
the ratings. Follow [HUMAN_REVIEW_UI](HUMAN_REVIEW_UI.md) for assignment,
adjudication and export; preparing a study is not completed human assessment.

## 10. Optional: response-SVM analysis

The campaign guide's **SVM analysis** topic opens **Tools -> Retained response
classifiers**. [RESPONSE_SVM](RESPONSE_SVM.md) describes harmful-compliance,
over-refusal and judge-disagreement models, using supported static-text data
and matched Haiku labels. These four demonstration answers are insufficient
for meaningful training and held-out evaluation. Use a larger supported study
population or reuse an existing fitted package. This does not call a target
or judge, classify arbitrary images, or replace independent human assessment.

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
