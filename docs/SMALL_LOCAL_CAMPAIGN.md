# A small local campaign through Build

This walkthrough creates a new campaign with the installed Qwen3-VL model,
two text and two image inputs, and local evaluation. It needs no hosted calls,
framework reinstall or model download. The ordinary flow is **configure ->
save -> compose -> review -> start**. Required connection checks are automatic
parts of the reviewed execution, not separate setup tasks.

## 1. Create the campaign and choose its experiment

1. Open <http://localhost:8642/build?work_kind=campaign>.
2. Leave **Campaign** selected under **What are you building?**. Choose
   **New campaign**, then enter a unique name such as `My Qwen demonstration`.
   If you already created **Qwen demonstration**, select it instead.
3. Optionally enable **Guide me through this campaign**. Close the guide when
   it covers controls; **Campaign guide** reopens it.
4. Open **Pipeline** and select **Measured lane**. Enable **Text** and **Image**;
   disable Audio, Video and Tool. Select only `xstest_full` and
   `vlsbench_release` under **Arms & corpora**, and **replay** under attacks.
5. In the target-model picker, choose **Local rig**, select only
   `vllm:Qwen/Qwen3-VL-8B-Instruct`, and click **Done**.
6. In **Evaluation**, select **rules** and **guardrail**, uncheck **llm**, and
   leave defense **none**. Select `meta-llama/Llama-Guard-3-8B` as the
   **scoring** guardrail. Its installed revision and device are automatic.

Do not start alongside another GPU job. The installed Qwen profile uses both
GPUs; static collection releases the target before local scoring. Reuse the
assessed serving profile. No new responsiveness survey is needed for an
unchanged, already-assessed model.

## 2. Set the small workload

### 2.1. Admission

Keep **Admission -> Setup -> Automatic (recommended)**. Do not enter receipt
rows, hashes, execution scopes or paths. Build finds matching connection checks.
When checks are missing or expired, it derives the necessary diagnostics from
your measured selection and includes them in the final reviewed start.
Your measured settings remain unchanged.

### 2.2. Execution

1. Click **Execution** in Build's top tab row. Under **Sampling & turns ->
   Per-arm sample size**, confirm **2 arms selected**.
2. Set these on-screen fields:

   | Field | Value |
   | --- | --- |
   | `--limit` | `2` |
   | `--sample-seed` | `0` |
   | `--sampling-policy` | Seeded pseudorandom cluster prefix (default) |
   | `--seeds` | `0` |
   | `--max-queries` | `1` |
   | `--max-turns` | `1` |
   | `--target-answer-retries` | `1` |

   Enter the sample count directly; the slider acquires its corpus range after
   preparation. The limit is per arm and preserves whole source clusters.
3. Leave **Advanced execution and recovery options** collapsed.
4. Under **Call ceilings & deadline (budget guards)**, enable **Calculate call
   limits automatically**. Do not fill **Manual call-limit overrides**.
   Set **Local process wall-time cap (hours)** to `1`; leave
   `--deadline-seconds` at `3600`. These are resource bounds, not a required
   duration or individual-response timeout.
5. Under **Local model serving**, keep the assessed defaults. Leave **Full model
   SHA verification (slow, optional)** unchecked.
6. Leave **Output** automatic. No folder needs to be created, and the campaign
   name does not need translating into a filesystem path.

### 2.3. Save

Click **General -> Save campaign**. Build stays open with the saved draft.
Saving does not start preparation or model calls. Continue with section 3.

## 3. Prepare automatically

1. In **Build -> General -> Campaign workflow**, keep **Installed corpora and
   attack frameworks** selected. Keep local assessment checked; leave Haiku
   unchecked for this fully local example. No API collection ceiling is needed.
2. Click **Review campaign** once.
3. Stay on the progress page. The system plans the workload, reuses installed
   models, checks the selection without generation and prepares any required
   connection checks. Do not open or launch its internal jobs.
4. Wait until the page presents the execution review. No target or judge call
   has been made by this preparation.

To return later, open **Campaigns -> your campaign name -> Configure in Build ->
General -> Prepared and active work**. Select **View progress** or **Review and
start**. Refreshing this page does not launch a duplicate.

## 4. Review the complete workload

The page is **Review campaign**, with required checks and selected assessment
shown together.

Check Qwen, both selected arms, per-arm limit 2 and the measured workload.
Call ceilings are calculated from the actual projection. A positive technical
HTTP limit does not create network calls; this local workload projects none.

Missing text/image checks appear under **Additional connection checks**, each
with its own small diagnostic workload. They make real model calls only after
the start below and remain separate from measured results. You do not change
the campaign into probe mode, copy receipts or restore settings afterward.

## 5. Start once

1. Click **Start campaign**.
2. Follow the single progress page. Required checks run first, their records
   are saved automatically, and then the original measured experiment starts.
3. Stay on campaign progress while collection and any pending selected local
   assessment finish. **Technical jobs** exposes details without requiring
   operator handoffs. Do not start another copy while work is active.
4. Continue to section 7 to inspect saved answers and verdicts.

A failed connection check stops progression before the measured run; its
diagnostic output and error remain available. That failure is not silently
converted into benchmark evidence.

## 6. Return, stop or continue

Open **Campaigns** in the main header, then your campaign's **name**. This is
your named demonstration, not the historical **Local campaign**.
**Configure in Build** reopens its draft; **Campaign jobs** opens its jobs.
Ordinary execution does not require **Run tools**.

**Prepared and active work** in Build General or campaign Overview reopens the
current operation. **Stop campaign** stops active work and prevents later
stages. If it is interrupted, inspect the cause and use **Resume campaign**.
Completed stages are
reused. A failed real diagnostic has its own retained job and recovery action;
do not repeatedly start it as if it were a no-call preparation.

Changing scientific choices requires a new review. A finished measured run is
not restarted merely to inspect results. Older manually prepared jobs remain
in history and can still use their own continuation controls.

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

### Fill missing saved-output judgments

Open **Campaigns -> your campaign -> Evaluate saved answers**. Choose
**Original local rules and guardrail** or **Haiku**, and a maximum pending-answer
count (0 means all). Haiku also requires a configured judge and USD ceiling.
Click **Prepare assessment and review**, inspect its selected/skipped counts
and costs, then **Start or resume assessment**. No target generation is repeated.
Existing valid verdicts are skipped. Source-specific tasks, missing context and
missing answers remain explicit; image judgments use saved text proxies.
Return through the same page's **Prepared assessments and progress** to resume.

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

For individual measured runs, open **Stats -> Compare campaigns -> Compare
individual measured jobs**. Choose **Left job** and **Right job**, then click
**Compare job outputs**. The input-overlap chart and per-condition table keep
missing outputs, refusals, truncation and known token usage separate. **Export
these job statistics (CSV)** downloads that selection. Shared recovery output
directories require whole-campaign comparison; saved outcomes do not represent
all planned inputs. See [the API guide's job-comparison steps](SMALL_API_CAMPAIGN.md#86-optional-compare-two-individual-measured-jobs).

## 8. Optional: compare these answers with a hosted model

The local demonstration is complete after section 7. This optional continuation
uses paid hosted generation and Haiku judging; neither has run merely because
you finished this guide.

1. Open [the small Flash guide](SMALL_API_CAMPAIGN.md) and create a **new hosted
   campaign**. Choose **route 2a - Reuse local inputs**.
2. Select **your demonstration campaign** as its source. Choose the measured
   Qwen text and image runs created in section 5, not the probes or the
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
2. Under **Saved analyses**, read the study summary: selected answers,
   independent input groups, task status and held-out macro-F1. Named links
   open the complete metrics, predictions, baselines and fitted classifiers.
3. Click **Stats -> SVM results** to inspect historical and UI-created studies.
   Choose **Campaign**, **Saved study**, **Evaluation split** and **Task**, then
   click **Show SVM results**. The historical study is named **Matched local and
   hosted response classifiers**. It contains both populations, not a separate
   fit for each campaign.
4. Read the held-out score chart and its group-bootstrap intervals alongside
   the baseline table, class counts and independent input groups. **Not
   estimated** means insufficient/unrecorded evidence, not zero performance.
5. Use **Download CSV**, **Download SVG** or **Full study report**. No training,
   target generation or judging is started by inspecting or exporting results.

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
6. Return to **SVM analysis -> Saved analyses** for its summary and named
   reports. Inspect extraction dispositions, class support and held-out metrics.
   Missing labels and unsupported modalities are not
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

Keep the intended measured selection and **Admission -> Automatic**. Compose
a fresh review; only missing or incompatible checks are included in its start.
No mode switch, receipt copying or separate transport-check job is required.
Old job recovery links intentionally keep their original settings and outputs.

An earlier probe does not establish transport under changed software. If the
revision changes for both modalities, refresh both. Do not overwrite receipt
files or restart a completed measured run merely to inspect it.
