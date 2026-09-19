# A small local campaign through Build

This guide uses the installed Qwen3-VL model and Llama Guard on the rig. It does
not require a framework installation, a model download or a hosted API call.
The destination is a **new demonstration campaign**, not the thesis Local
campaign. The measured example requests **two text and two image inputs**,
followed by local evaluation. Diagnostic probes are kept separate.

### Before you begin

- For a new campaign, choose an unused name. If you already created one,
  continue with it. Output directories and the execution scope are automatic;
  you do not need to invent, create or copy filesystem paths.
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

### Find your campaign, Build and Run tools

"Your demonstration campaign" means the campaign **you named in section 1**.
It is not a menu item named "Demonstration campaign", and it is not the historical
**Local campaign**. For the operator's current walkthrough its name is
**Qwen demonstration**.

1. Click **Campaigns** in the main navigation at the top of any page.
2. On the campaign list, click your campaign's **name**, not **Edit in Build**.
   For the current walkthrough, click **Qwen demonstration**. This opens a page
   with that name as its heading.
3. Immediately below the heading are three buttons: **Configure in Build**,
   **Campaign jobs**, and **Run tools**. They are above the campaign's Overview,
   Definition, Results and other tabs. On narrow screens the buttons may wrap
   onto separate lines. Close the campaign guide modal if it covers them.
4. **Configure in Build** reopens your saved settings. **Campaign jobs** lists
   this campaign's jobs. **Run tools** opens the command forms with this campaign
   already selected. It does not start a job.

For the current walkthrough only:

- [Open Qwen demonstration](http://localhost:8642/campaigns/02aa50eae1bc43f4be35dfc14d673f6d).
- [Open its Run tools page](http://localhost:8642/commands?campaign_id=02aa50eae1bc43f4be35dfc14d673f6d).

For a different campaign, use its name from the campaign list instead of these
example links. Whenever a step says **return to Build**, follow steps 1-3 and
click **Configure in Build**. After starting a job, follow its opened job page
until it finishes; do not launch a second copy while the first is active.

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
   **Save campaign** retains these modality choices. Older drafts that never
   saved a scope start with all modalities enabled; set Text and Image once
   and save. Switching Build tabs does not require another save.
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

Open **Admission** and leave **Setup -> Automatic (recommended)** selected.
No receipt rows, hashes, revision, execution-scope or output-path entry is
required. Build supplies the Runner's configured software/source records and
keeps an existing campaign scope, or assigns one for a new campaign. Probes
automatically omit prior transport checks. **Advanced overrides** is optional,
not a required step in this walkthrough.

### 2.2. Set Execution

These are controls in **Build**, not the campaign's Definition page, a job's
execution details or a Tools form. Keep your current draft open. If you already
saved it and left Build, use **Campaigns -> your demonstration campaign ->
Configure in Build**. Do not open a fresh Build link and lose unsaved selections.

1. At the top of Build, click **Execution**, in the same tab row as **General**,
   **Runtimes**, **Pipeline**, **Evaluation** and **Admission**. Close the campaign
   guide modal first if it covers the page. You should see **Sampling & turns**.
2. In its **Per-arm sample size** box, check that the badge says **1 arm selected**.
   If it says **0 arms selected**, use **Pipeline - Arms & corpora**, select
   `xstest_full`, and return to **Execution**. The sampling fields are disabled
   until a corpus is selected.
3. Set the following fields by their **literal on-screen labels**:

   | Location in Sampling & turns | On-screen label | Value |
   | --- | --- | --- |
   | Per-arm sample size | `--limit` | `1` |
   | Per-arm sample size | `--sample-seed` | `0` |
   | Per-arm sample size | `--sampling-policy` | **Seeded pseudorandom cluster prefix (default)** |
   | Below Per-arm sample size | `--seeds` | `0` |
   | Below Per-arm sample size | `--max-queries` | `1` |
   | Below Per-arm sample size | `--max-turns` | `1` |
   | Below Per-arm sample size | `--target-answer-retries` | `1` |

   Enter `--limit` directly in its number box. The **Sample-size range** slider
   is unavailable until a matching no-call preflight supplies the corpus size;
   no preflight is needed to enter the number now. The policy's CLI value is
   `seeded_pseudorandom_whole_cluster_prefix_v1`, but that is not its menu label.
4. Scroll down, still inside **Execution**, to **Aggregation, row admission &
   resume**. Keep `--group` unchanged and `--lock-stale-seconds` empty. Leave
   **Reset open circuits (--reset-open-circuits)** unchecked. In **attestation
   probe** mode, **Exclude tool-conditioned rows (--exclude-tool-conditioned)**
   is automatically unchecked and disabled; do not try to enable it.
5. Continue down to **Call ceilings & deadline (budget guards)**. Set each
   individual field; there is no combined "Target / judge / HTTP ceilings" control.

   | On-screen label | Value |
   | --- | --- |
   | `--max-total-target-calls` | `16` |
   | `--max-total-judge-calls` | `16` |
   | `--max-total-http-attempts` | `1` |
   | **Local process wall-time cap (hours)** | Leave empty for the probe |
   | `--deadline-seconds` | `3600` |

6. Continue to **Local model serving**. Leave **Full model SHA verification
   (slow, optional)** unchecked. Do not change `--dtype` or `--quantization`;
   keep the installed model profile.
7. The last card, **Output**, explains that the directory is assigned
   automatically. Leave it that way. Review execution and the resulting job
   show its actual location; no folder needs to be created by hand.
8. Continue with section **2.3** to save and review. Do not start a job yet.

The positive HTTP ceiling is required by the common bounds form; it does not
initiate network calls. This all-local projection should report zero HTTP attempts.

### 2.3. Save and review the draft

1. Return to **General** and click **Save campaign**. This opens **Definition**.
2. Click **Configure in Build -> General -> Compose & review**.
3. Check Qwen, `xstest_full`, probe mode and the bounds. The output directory is
   supplied automatically. Saving and reviewing make no model calls.

## 3. Complete preparation, then run the text probe

If an earlier planning job failed with **project checkout revision mismatch**,
keep it as history. Reopen the campaign in Build, keep **Admission -> Automatic**,
save and review again. Fresh review selects the configured Runner revision;
an already reviewed or launched job keeps its original settings. A console-only
update can retain the Runner checkout, so it need not invalidate existing probes.

### 3.1. Prepare automatically

1. **Compose & review** opens automatic preparation directly.
2. Stay on the progress page. Planning, reuse of installed models, the no-call
   workload check and final preparation happen automatically. Do not open or
   launch the internal child jobs.
3. When preparation finishes, the same page shows **Review prepared run**.
   Check the projected workload. Preparation has made no target or judge calls.

You can leave this page. Return through **Campaigns -> your campaign name ->
Configure in Build -> General -> Prepared and active work** and click **Review
and start** or **View progress**. The campaign's Overview also contains these
links. Refreshing does not start another preparation.

### 3.2. Start the real text probe

1. On **Review prepared run**, click **Start probe** once. This makes real Qwen
   calls and performs the selected evaluation.
2. The progress page follows the probe and saves its connection check
   automatically when it succeeds. There is no separate receipt-creation task.
3. Wait for **Probe and connection check complete**. Use **View the probe result**
   to inspect the answer and job. A saved answer alone is not completion.

## 4. Check readiness without copying technical fields

After the completed probe, return to the saved campaign in Build. Its connection
check is retained automatically and will be selected for compatible measured
work. Leave **Admission -> Automatic** selected. Do not copy paths, digests or
receipt rows, and do not repeat a successful probe.

A connection check establishes the observed transport, not benchmark performance.
An expired or incompatible probe may need renewal, but an unrelated console-only
update does not require rerunning it. Historical probes created before automatic
completion can still be selected through **Tools -> Advanced CLI tools and troubleshooting -> live_attestation -> Use a
completed probe**; that is a compatibility path, not part of a new campaign.

## 5. Repeat for one image input

### 5.1. Change only the corpus

1. Return to Build and open **Pipeline**. Uncheck `xstest_full` and select only
   `vlsbench_release`.
2. Keep **attestation probe**, Qwen, Text and Image, seed, bounds and evaluation
   settings unchanged. Automatic setup handles the probe's technical settings.
3. Leave **Admission -> Automatic** selected. The changed corpus receives its
   own output directory automatically; leave **Output** unchanged.
4. Click **General -> Save campaign**, then return to Build and click
   **General -> Compose & review**.

### 5.2. Run the image probe

1. Follow **3.1-3.2** with the image selection: **Compose & review**, then
   **Start probe** after checking the workload.
2. Wait for **Probe and connection check complete**. Connection bookkeeping
   happens automatically. No tool form, filename or receipt row is required.

The text and image checks support measured execution; neither probe is itself
a measured benchmark result.

## 6. Configure the small measured run

### 6.1. Change from diagnostic to measured work

1. Return to Build. In **Pipeline**, choose **measured** and select
   `xstest_full` and `vlsbench_release`. Keep only Qwen selected as a target.
2. In **Admission**, leave **Automatic (recommended)** selected. Build finds
   this campaign's saved text and image checks, keeps its scope and applies a
   24-hour maximum age. Do not enter receipt rows or digests. If no matching
   check is found, use **Select a completed probe**; do not rerun a successful
   probe merely to create its missing check.
3. In **Execution -> Sampling & turns -> Per-arm sample size**, change **--limit**
   to `2`. In **Call ceilings & deadline (budget guards)** set **Local process
   wall-time cap (hours)** to `1`. The measured output directory is automatic.
   Keep the other bounds and the one-answer-retry policy unchanged.
4. Click **General -> Save campaign**. Build stays open with the saved draft.
   Continue below; do not start preparation twice.

### 6.2. Prepare, review and start the measured run

1. Stay in **Build -> General**. If you left, return through **Campaigns ->
   your campaign name -> Configure in Build**.
2. Check **measured**, Qwen, `xstest_full,vlsbench_release` and per-arm limit
   `2`. Click **Compose & review** once.
3. Wait on the single progress page. The console reuses matching completed
   preparation and installed models. Any needed planning, no-call preflight and
   execution preparation happen automatically.
4. On **Review prepared run**, check the calculated call ceilings and selected
   experiment, then click **Start run**. This starts real generation and local
   evaluation. Follow the opened job until it finishes.

There is no requirement to choose between acquisition jobs or coordinate
preparation stages. Internal job details are available for diagnosis
but are not operator steps. Do not repeat the completed text/image probes.

If you leave preparation, reopen it from **Prepared and active work** in Build
General or campaign Overview. **Stop preparation** prevents later stages.
After a failure, inspect the reported cause and use **Continue preparation** to
retry the unfinished stage with the same settings. If the scientific settings
must change, edit them in Build and prepare the changed selection. Completed
work and earlier errors remain in history.

Older job pages and their reviewed start buttons still work. If you already
have a fully prepared measured job from the previous interface, continue that
job instead of creating a second measured execution.

## 7. Inspect results, judging and exports

1. Open **Campaigns -> your demonstration campaign**.
2. Inspect each tab below. Keep diagnostic probes separate from measured cases.

   | Tab | What to inspect |
   | --- | --- |
   | Overview | Measured coverage, missing responses, truncation, charts and their exported counts |
   | Results | Each saved answer; its generation settings, usage and separate Truncated column |
   | Judging | Local decisions, abstentions or inapplicable results; the judging figure and exported counts |
   | Costs | Available usage and cost accounting; an unknown local cost is not zero-cost computing |
   | Activity | Preparation, collection and evaluation activity; use the **Campaign jobs** button above the tabs for detailed job states and durations |

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
4. Stay on the progress page; the evaluation form opens automatically when
   preparation finishes. If you leave, return through **Human evaluation ->
   Prepared personal reviews -> your review name**. **Open evaluation form**
   remains available if automatic navigation is disabled in your browser.
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

These four demonstration answers are insufficient for a meaningful new grouped
training/test study. Classifier analysis is optional, makes no target or judge
calls, and does not replace human assessment.

### 10.1. Inspect existing results

1. Click **Campaigns -> your campaign -> SVM analysis**.
2. Under **Saved analyses**, open an existing study if present. Its Jobs page
   links the dataset, evaluation and fitted classifiers.
3. Historical thesis analysis remains available under **Artifacts ->
   engineering/response-svm-20260913-r-checkpoints/analysis**. Open
   `result.json` and `predictions.json`; do not start training just to read them.

### 10.2. Start a new study when scientifically appropriate

1. On **SVM analysis**, choose this local campaign under **Saved local input
   source**.
2. Choose the hosted counterpart under **Restrict to inputs assigned in** when
   studying matched inputs. Choose this campaign for its own input population.
3. Choose the **Recorded Haiku condition**. The local guide alone does not
   supply Haiku labels; the page explains this prerequisite when none exist.
4. Review **Include matching answers from the local source campaign** and,
   optionally, **Scientific analysis options**.
5. Click **Start classifier study**. Source metadata extraction, dataset export,
   grouped evaluation and model packaging run together. No campaign IDs,
   database paths or intermediate output paths need entering.
6. Inspect extraction dispositions, class support and held-out metrics on the
   resulting Jobs page. Missing labels and unsupported modalities are not
   invented. For interruption, reopen **Saved analyses** and click **Resume
   unfinished analysis**; completed stages are reused.

The three tasks are harmful compliance, over-refusal and local/Haiku
disagreement. They predict recorded teacher labels, not independent human
truth. A small sample can be insufficient for one or all tasks. For advanced
prediction from a trusted existing package, see
[RESPONSE_SVM](RESPONSE_SVM.md); that is not another required campaign stage.

## If a step fails or is interrupted

### A job is still active, or failed after saving an answer

Open its existing job from **Campaign jobs** and read its status and underlying
error. Do not create another campaign or repeat target generation just because
judging has not finished. Keep the saved outputs and the failed job. Use a
recovery action only for the affected stage; this guide's normal setup sequence
is not a recovery procedure for every possible failure.

### Transport evidence expired, or the software changed

1. Return to the same campaign in Build. In **Pipeline**, choose **attestation
   probe** and only the affected text or image corpus. Keep **Admission ->
   Automatic**. Do not repeat the unaffected modality's probe.
2. Save and compose a fresh review. After an earlier execution has ended,
   automatic setup assigns the next output location without overwriting it.
   Review or recovery links on an old job intentionally keep its old location.
3. Complete the probe through section 3. Its connection check is saved
   automatically; do not run a separate transport-check job.
4. Return to the measured configuration in section 6. Automatic setup selects
   the newer check and retains any other still-valid modality check. Nothing
   needs to be copied or cleared.

An earlier probe does not establish transport under changed software. If the
revision changes for both modalities, refresh both. Do not overwrite receipt
files or restart a completed measured run merely to inspect it.
