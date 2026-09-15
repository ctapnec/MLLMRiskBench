# Your first small API campaign on the rig

This is a click-by-click guide for the currently configured rig console at
<http://localhost:8642/>. It creates a **new, separate Flash campaign** with
either saved local inputs (section 2a) or a fresh selection of installed corpus
arms and attack frameworks (section 2b). Neither route requires downloading a
hosted model or reinstalling the rig's frameworks. The saved-input route needs
no filesystem paths or terminal commands and does not regenerate local answers.
The direct route uses the ordinary Runner controls, including output paths and
transport evidence, as described in section 2b.

The completed reference is **UI demonstration - Flash matched text and images**.
You can inspect it without spending money. To execute your own example, follow
the steps below with a new name; do not start the completed reference again.

Choose one route after section 1:

- **2a - Reuse local inputs:** use **General -> Reuse local inputs for an API
  comparison**, then sections 3-8. Do **not** use **Compose & review** for this
  route; it has its own **Review prepared collection** action.
- **2b - Select arms and frameworks directly:** use **Pipeline**, then
  **General -> Compose & review**. Follow section 2b's preparation and execution
  instructions, not the retained-input preparation in sections 3-5.

## 1. Create the destination and select Flash

1. Open <http://localhost:8642/build?work_kind=campaign>.
2. Under **What are you building?**, leave **Campaign** selected.
3. In the **Campaign** dropdown select **New campaign**, not Local campaign or
   API campaign. Those names identify existing workspaces.
4. In **New campaign name**, enter `My first Flash campaign` (or a unique name).
   Optionally check **Guide me through this campaign** for explanations and
   links in a modal. Closing it does not disable the option; **Campaign guide**
   reopens it. Your choice is saved with the campaign and never starts calls.
5. Click the **Pipeline** tab. Open the target-model picker, choose **Hosted
   API**, and select only `google:gemini-3.8-flash`. Click **Done**. Do not select
   Haiku as a target unless you deliberately want Haiku to answer the questions.
6. Click **General**, then **Save campaign**. This creates a saved draft and
   opens the campaign's **Definition** page; it does not start calls.
7. Click **Configure in Build** on that page, then **General** to continue.
   Saving does not leave you in Build automatically.

Flash is already configured on this rig for text and images, low thinking and
4,096 output tokens. For route 2a, the forecast in section 3 shows the actual
output allowance; route 2b uses the configured API target directly.
If it is different or Flash is absent, inspect **Config -> API targets** before
proceeding; do not substitute a similarly named model. No API key needs to be
copied into Build. The configured Google credential is already available.

## 2a. Select the existing local inputs

1. Stay in **General**. Scroll below **Current pipeline** and the save/compose
   buttons to **Reuse local inputs for an API comparison**.
2. Set **Source campaign** to **Local campaign**. This is the source of your
   questions, not the destination of the new Flash answers.
3. Click **Show saved runs**. A checkbox list headed **Saved local runs** appears.
4. In **Find a model or corpus**, search `xstest_full`. Select the Qwen3-VL run
   with **100 saved outputs**, whose small Run label is
   `run-a66a37fef7443227d3ff1ce0`.
5. Replace the search with `vlsbench_release`. Select the Qwen3-VL run with
   **100 saved outputs**, Run `run-549b0f0db2a1cb24bcb80a85`.
6. Clear the search. Confirm **2 run(s) selected**. Search hides rows; it does
   not clear an already checked row. Do not check all runs with the same corpus.
7. Click **Prepare selected inputs**. Follow the preparation job until
   **complete**. It reads saved inputs and makes no model calls.
8. Return through **Campaigns -> My first Flash campaign -> Configure in Build**,
   then **General**. Do this after each preparation below. You are returning
   to the saved draft, not starting a new campaign.

## 2b. Select arms, corpora and attack frameworks directly

Use this alternative when you want Runner to read the installed datasets and
apply selected attacks, without choosing any previous local run. No existing
local generations are required. Keep the new destination from section 1, but
leave **Reuse local inputs for an API comparison** unused. If you already
prepared the 2a route, create a separate campaign for this example so its saved
preparation controls cannot be confused with the direct job.

### Choose the workload

1. Open **Pipeline -> Mode** and select **Measured lane**. **Offline dry-run**
   uses mock answers; it does not test Flash.
2. Under **Modality scope**, enable **text** only for the first small run.
   Under **Arms & corpora**, clear previous selections and select `xstest_full`.
   To test images afterward, enable **image** and select `vlsbench_release`
   in a separate job under the same campaign. Keep Flash as the only target.
3. Under **Attack frameworks**, select **replay** for the initial example.
   Here, replay sends the selected corpus's requests to Flash for new answers;
   it does not reuse local answers or require a previously executed campaign.
   A corpus arm and an attacker are separate choices: selecting a HarmBench
   corpus does not automatically run the HarmBench attack-generation framework.
4. To exercise another framework, select its enabled checkbox instead of, or
   alongside, replay. Read its modality and preparation notes. Selecting two
   attackers creates separate model/arm/attacker conditions, not a chain of
   attacks. Adaptive frameworks can make several target and attacker-model
   calls per input; do not assume the small replay bounds cover them.

| Framework control | What must be configured before its run |
| --- | --- |
| Enabled direct/bridge framework | Its displayed runtime and model settings; reuse its installed isolated environment |
| T3MP3ST | Its **Capture - Replay** panel and prepared planning bundle |
| HarmBench attacker | Its preparation panel and generated capture configuration |
| NanoGCG | Its precomputed suffix and source information; this UI route is suffix replay, not live optimization |
| IDEATOR | Its verified seed-pair manifest and optional pair limit; this route replays prepared pairs, not live IDEATOR generation |
| Disabled native-only or CLI-only entry | Read the displayed reason; checking a corpus with the same name does not enable that integration |

For the first example, stay with `xstest_full` and `replay`. Broader selections
use the same flow, but need their own compatible settings and cost assessment.

5. Open **Execution -> Per-arm sample size**. Set **--limit** to **2**,
   **--sampling-policy** to **Seeded pseudorandom cluster prefix (default)**,
   **--sample-seed** to **0**, and generation **seeds** to **0**. The alternative
   **Source-order cluster prefix** takes the first source clusters instead of
   using pseudorandom ordering. The exact slider range appears after a matching
   no-call preflight; enter the number directly until then.
6. Set maximum queries and turns to **1** for this replay example. Set target
   answer retries to **0**; retain **3** eligible HTTP/transport retries in the
   configured API route. Keep Flash's configured **4,096-token** output allowance.
   Uncheck **Exclude tool-conditioned inputs** and full model SHA verification.
7. Enter provisional target/judge/HTTP call ceilings of **16 / 16 / 64**, and
   **--deadline-seconds = 3600**. Leave the local process wall-time cap empty.
   Use a new output directory, for example
   `/mnt/stor/data/ura-work/runs/demonstrations/my-flash-direct/measured-text`.
   These are planning bounds, not a USD allowance or permission to spend the
   remaining Google purse. The exact preflight and monetary review below must
   fit the intended small workload before any paid start.

The limit is **per arm, in whole source clusters**, not a campaign-wide request
cap. Sibling rows are retained, and models, attackers, seeds and framework
variants can multiply generations. Zero means the full selected release, not
zero work. This is different from section 3's total hosted request cap of 12.

### Set judging and establish the route

8. In **Evaluation**, select **rules** and **guardrail**, uncheck **llm**, keep
   defense **none**, and use the installed Llama Guard model from section 4.
   Its installed revision and placement are automatic.
   Ordinary Runner evaluates through this selected cascade as
   part of the job; it is not the retained collection's separate step-6 job.
9. In **Admission**, keep the current project/source receipts supplied by the
   console. Enter a new execution scope, such as `my-flash-direct`. Measured
   execution also needs a current transport receipt for each selected target
   and modality and a positive maximum age in hours, for example **24**.
   Do not copy the Qwen demonstration's receipts: those establish a different
   target, and a historical Flash receipt is usable only if its scope, route,
   settings and age actually match this run.
10. If there is no matching receipt, prepare a small **Attestation probe** first.
    Keep one target, one corpus, `replay`, one seed, one query and one turn;
    set limit **1**, clear live-attestation rows and maximum age, and use a
    separate `probe-text` output directory. Follow the preparation/start
    sequence below, then use **Campaign -> Run tools -> live_attestation**:
    enter that probe directory, the same execution scope and a new output file
    such as `attestation-text.json`. The job prints the receipt path and digest
    for the measured Admission fields. A live probe spends Google credits;
    deriving its receipt makes no additional target call. Repeat separately
    for an image route when needed, then restore **Measured lane**, limit **2**,
    the measured output directory and the receipt/maximum-age fields.

### Prepare, review and start the direct job

11. Click **General -> Save campaign**, then **Configure in Build -> General ->
    Compose & review**. Check that the command names Flash, `xstest_full`,
    `replay`, the selected sample policy/seeds and the correct mode.
12. Run the displayed **Run no-call preflight (projection, no calls)** action.
    With the local guardrail selected, the review instead starts with **Plan &
    acquire models for no-call preflight**, followed by **Acquire sealed models**
    and **Start no-call preflight**. These steps reuse the installed model store;
    they are not instructions to reinstall runtimes or download another target.
13. When the preflight passes, open **Review this exact lane in the builder**.
    Read **Calculated call ceilings** and the exact projected row/target/judge/
    HTTP counts. Confirm that they fit the selection and bounds. If not, revise
    the workload and reproject it before starting. This projection counts calls,
    not dollars: unlike 2a, it does not provide the matched collection's counted
    monetary forecast. Assess the selected provider's input/output prices,
    output allowance and possible transport attempts, including probes and any
    hosted attacker/judge, against the intended spending cap. The 2a reference's
    USD 0.757348 bound does **not** apply to this different selection.
14. Use **Plan & acquire models for this job** and **Acquire sealed models** if
    offered, then **Start reviewed measured job**. Without local acquisition,
    the final button is **Start campaign run**. This starts real calls; in probe
    mode the command must still show `--attestation-probe` despite the generic
    button label. Follow **Jobs** or the campaign's **Activity** until completion.
15. Inspect that campaign's **Results**, **Judging**, **Costs** and exports.
    Later arms/frameworks can be separate jobs in this same campaign, with their
    own output directories and reviewed settings. Do not relaunch a completed
    job to inspect its answers.

Sections 3-7 below describe the **2a retained-input route**, not additional
buttons required after this direct run. For a direct run, selecting **llm** and
the configured Haiku model in **Evaluation** is a different, paid judging
cascade and requires its own review and applicable transport evidence. A cascade
may decide a row before reaching Haiku; it does not establish independent local
and Haiku verdicts on every output. The paired post-hoc controls in sections 6-7
require their retained-source and prepared-collection prerequisites; they do
not automatically appear for an ordinary Runner job.

The result-inspection principles in section 8 still apply. A new direct sample
is not automatically matched to the historical Local campaign. Equal seed and
limit reproduce a selection only with the same arm, source release, conversion
and sampling policy; attack settings must also match for comparable prompts.
Check actual shared inputs and compatible conditions in **Compare** before
claiming a paired result. Otherwise report this as a separate campaign.

## 3. Choose the small workload and prepare its replay (route 2a)

1. In General, find the newly available **Forecast matched hosted work** panel.
   It appears only after input preparation. If it is absent, verify the saved
   source job is complete and that you reopened the same destination campaign.
2. The model table must contain only Flash and show **Output allowance: 4096**.
   If it lists no model or an old selection, use **Refresh selected models**.
3. Set Flash's **Input request cap** to **12**. This is the total small-program
   request cap, not 12 per selected corpus. Leave the pricing date at today's
   date, using the prices already configured on the rig.
4. Click **Prepare forecast**. Wait for its job to complete, then return to the
   saved campaign's General tab.
5. Below the forecast panel, find **Prepare matched replay inputs** and click
   **Prepare replay inputs**. This is **not** the earlier **Prepare selected
   inputs** button. Wait for the replay job to complete, then reopen this saved
   campaign through **Configure in Build -> General**. The **Count inputs and
   prepare collection** controls below replay preparation are now enabled.

The reference selection, with the retained seed-zero inputs, contains **seven
measured inputs (three text, four image) and five diagnostic inputs**. Twelve
requests does not mean twelve independent measured cases. Whole clusters stay
together, so other caps can leave unused room. Do not change the seed, query
counts or source selection halfway through preparation.

## 4. Set evaluation and the call-start window

1. Click **Evaluation**. Under judges, uncheck **llm** and select **rules** and
   **guardrail**. Keep the defense **none**. Target collection and retained-output
   judging are separate stages in this flow.
2. Use scoring guardrail `meta-llama/Llama-Guard-3-8B` (the default).
   Its revision is resolved from the installed model store and saved with the
   preparation. Its device is chosen automatically when the judge loads.
   There are no revision or device fields to select. Use the scoring model,
   not the separate defense guardrail model.
3. Click **Execution**. Under **Call ceilings & deadline (budget guards)**, set
   **--deadline-seconds** to **3600**. This allows one hour in which to start
   calls; it is not an hour-long timeout for an individual answer.
4. Hosted **answer retries** must be **0**. Eligible HTTP/transport errors have
   **3 retries**. A usable truncated answer or a documented policy refusal is
   not an empty-answer retry. Leave full model SHA verification unchecked.
5. Return to **General**. Leave the Admission paths already supplied by the
   console unchanged. The generic Current pipeline may still say `dry_run`;
   the matched collection uses its own explicitly prepared and reviewed inputs.

## 5. Count, review and start the paid collection

1. In **General**, below **Prepare matched replay inputs**, find **Count inputs
   and prepare collection**. Enable **Allow provider token counting for these
   selected inputs**. The panel stays visible after input preparation; while
   prerequisites are pending, it explains the next action and disables counting.
   If it says **Waiting for replay preparation**, use its **Go to replay
   preparation** link, click **Prepare replay inputs**, wait for completion and
   reopen the same saved campaign in Build. On an older open browser page,
   refresh the saved campaign to load the current controls. Do not repeat
   **Prepare selected inputs** or **Prepare forecast** for an unchanged selection.
2. Click **Prepare counted collection**. This constructs exact requests and
   counts their inputs; it does not generate answers. Wait for completion.
   If the scoring model is not installed, Build returns to **Evaluation** with
   that problem marked before counting. The CLI uses the same automatic
   revision resolution. Neither route downloads the model implicitly.
3. Return to the saved Build draft. Click **Review prepared collection**.
4. Check the destination name, Flash model, text/image selection and call count.
   Review the cost bound including transport retries, not just expected spend.
   The completed 12-request reference bounded Google exposure at **$0.757348
   including all three retries**, below its $1 cap. This is an example, not a
   guaranteed price for every future selection. Do not start a larger or
   differently configured selection under that assumption.
5. Click **Start prepared collection**. **This is the first target-generation
   action that spends Google credits.** Follow its job in Jobs or the campaign's
   Activity. Do not click another start because an answer is slow.
6. When complete, open **Campaigns -> your campaign -> Results**. The reference
   saved all 12 outputs. **Overview** distinguishes measured from diagnostic
   work; **Costs** shows reported usage/costs rather than your provider purse.

If execution was interrupted, reopen the same prepared collection and use its
continuation action. Do not create another campaign to recover that job. If a
preparation fails, open its job error first; an incomplete preparation is not
authorization to bypass it or switch to the ordinary compose button.

If an older collection failed during installed-runtime preparation because its
scoring model/revision was absent, run **Prepare counted collection** again in
the same campaign after the automatic-setup update. Reuse the saved source,
forecast and replay preparation; do not rebuild them. Review the new prepared collection
before starting it. Changing draft fields alone does not amend an already saved
program. Keep the original failed job as the record of that attempt. A runtime
planning failure is shown with its underlying Runner error on the job page.

## 6. Apply the local judge to the saved answers

1. Open your campaign's **Configure in Build -> General**.
2. Find **Judge retained outputs locally** and click **Prepare remaining source
   runs**. Wait for completion, then return to the same page.
3. Choose its completed **Saved judging preparation**, then click **Review
   local judging**.
4. Confirm the existing guardrail and automatic placement, then **Start or resume
   local judging**. Wait for completion. This scores saved Flash answers; it does
   not repeat Flash target calls or require a new framework installation.
5. Inspect the campaign's **Judging** tab. A local evaluation record can be an
   abstention or inapplicable result; coverage alone is not a valid safety score.

If step 6.4 failed before producing new assessments, keep the same saved judging
preparation. After the software correction, repeat **Review local judging ->
Start or resume local judging**. There is no device field to fill in for automatic
placement. Original judgments are reused, the failed execution revision remains
in its history, and Flash answers are not regenerated. Do not repeat collection
or source preparation to recover this failure.

## 7. Apply Haiku to each new eligible answer

Use this section after sections 5-6 of **route 2a**. You need the saved Flash
collection and its completed **Saved judging preparation**. Each new answer
needs its own verdict; a Qwen verdict cannot be copied onto a Flash answer.

The sequence is **check coverage -> check funding -> prepare Haiku -> start
judging -> inspect verdicts**. Only the explicit start in section 7.4 buys
judgments. Preparation may contact the provider's token-count endpoint, but
does not generate answers or verdicts.

After each preparation job completes, return through **Campaigns -> your
campaign -> Configure in Build -> General**. After a review, use **Return to
Build**. Always reopen the same saved campaign.

### 7.1. Check which saved answers will be included

1. In **Judge retained outputs locally**, keep the completed **Saved judging
   preparation** from section 6 selected.
2. Find **Same-input output coverage**. Set **Input limit (0 = all hosted
   inputs)** to **0** and **Input selection seed** to **0**. Zero includes all
   inputs in this small hosted selection, not the entire Local campaign.
3. Click **Prepare all-output coverage**. Wait for completion and return to Build.
4. Click **Review all-output coverage**. Check the counts for each local and
   hosted model, missing response text and inputs without a local record.
   Coverage is not proof that an answer has already been judged.
5. Click **Return to Build**.

### 7.2. Check which answers have judging funds

1. In **Same-input output coverage**, click **Prepare all-output judging funding**.
   Wait for completion and return to Build.
2. Click **Review all-output judging funding**. Read the four categories:

   | Category | What it means for this step |
   | --- | --- |
   | Funded and not yet started | These answers can proceed to Haiku preparation. |
   | Owned by existing judging executions | Check the original execution. Ownership alone does not mean a valid verdict exists. |
   | No matching funding in this selection | This preparation will not buy verdicts for these answers. Check any existing judgments separately. |
   | Missing response text | These outputs remain in coverage but cannot receive a text-based verdict. |

3. Click **Return to Build**. This review checks the collection's existing
   judging allocation; it does not allocate more money or start calls.

### 7.3. Select Haiku and prepare its requests

1. Scroll to **Haiku comparison of saved outputs**, below **Same-input output
   coverage**. In **Haiku judge**, select `anthropic:claude-haiku-4-5-20251001`.
2. Return to **Same-input output coverage** and click **Prepare all-output
   Haiku judging**. Wait for completion and return to Build.
3. Click **Review all-output Haiku judging**. Check the pending answer count,
   first-attempt cost estimate and any requests needing a funding review.
   The settings are **512 output tokens per assessment**, **0 answer retries**
   and **up to 3 HTTP-error retries**.

Use only the **Haiku judge** selector from the comparison panel for this flow.
Its **Maximum matched comparisons**, **Selection seed**, **Judging ceiling
(USD)** and **Prepare matched Haiku selection** belong to a separate paired
selection. They do not change this all-output selection or its existing funding.

Haiku judges the saved prompt text and each answer. For images, this flow uses
the retained text proxy, not the image pixels; keep that limitation in the
comparison's interpretation.

### 7.4. Start the paid judging

1. On the review page, click **Start or resume all-output Haiku judging**.
   **This spends Anthropic credits.** It does not regenerate Flash or Qwen answers.
2. Follow the opened job until it finishes. Do not start another copy while it
   is queued, running or waiting to retry a transport error.

If there is **no start button**, read the review's explanation. Either requests
need a funding review or no unstarted funded answers remain. Neither condition
proves that every saved answer already has a valid verdict.

### 7.5. Inspect the verdicts and costs

1. Open your campaign's **Judging** tab. Check valid, invalid and missing
   assessments separately. Inspect **Costs** for the recorded Anthropic usage.
2. For matching local answers, inspect the source **Local campaign** as well.
   Reuse a verdict only for the identical saved answer and judging condition.
3. Continue to [section 8](#8-examine-and-compare-your-results) for the paired
   comparison and exports.

### If preparation or judging was interrupted

- If a preparation is still active, open its existing job and wait. If it failed,
  read that job's error before retrying the affected preparation.
- If judging stopped after starting, reopen **Review all-output Haiku judging**
  for the same preparation and use **Start or resume all-output Haiku judging**.
  Completed judgments are retained without another paid call.
- If funding review assigns an answer to an earlier judging execution, inspect
  or resume that original execution. Do not create another selection to charge
  for it again. Invalid verdicts remain recorded; they are not automatically retried.

### Reference result, not a required count

The completed demonstration included seven measured Flash answers and seven
matching saved Qwen answers. Its diagnostic answers were outside this common
judging subset. Haiku assessed the seven new Flash answers for **$0.007470**:
six verdicts were valid and one had an invalid format. The seven Qwen answers
already had Haiku verdicts. Your counts and costs depend on your own selection.

## 8. Examine and compare your results

### 8.1. Inspect the destination campaign

Open **Campaigns -> your Flash campaign**. **Overview** shows coverage;
**Results** shows outputs, generation settings, token usage and truncation;
**Judging** shows answer-specific decisions; **Costs** shows physical attempts
and charges.

### 8.2. Select the two models in Compare

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
3. For images, choose the local image **Generation condition** if it differs
   from the text condition, wait, and reselect its Haiku condition as in 8.3.
   Change the filters to `vlsbench_release`, `replay`, `image`, wait and
   export that view separately. Old filter values persist until you change them.

The completed reference has three jointly valid text pairs and three valid
image pairs out of four matched images. These are reference counts, not a
promise that a newly generated selection will yield the same judgments.

The completed route-2a exercise demonstrates that retained-input UI flow.
Section 2b describes the separate direct Runner controls; documenting them is
not evidence that every framework/model combination has been executed. Keep
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

## 9. Optional: independent human evaluation

Open **Human evaluation** for the saved campaign, including a finished one.
Choose **Saved results** and follow the wizard to select a rubric and sample,
record actual participation and ethics arrangements, inspect the preview and
prepare the study. Qualified independent raters use their assigned review
links; setup alone supplies no ratings. Follow [HUMAN_REVIEW_UI](HUMAN_REVIEW_UI.md)
for assignment, adjudication and export. No new target generation is required.

## 10. Optional: response-SVM analysis

The campaign guide's **SVM analysis** topic opens **Tools -> Retained response
classifiers**. Follow [RESPONSE_SVM](RESPONSE_SVM.md) for dataset export,
grouped evaluation and optional model reuse. The three tasks are harmful
compliance, over-refusal and judge disagreement. The current study uses static
text with matched Haiku labels; it is not an image classifier or a substitute
for human ratings. This small demonstration is too small for meaningful
training and held-out evaluation. Use a sufficiently supported study population.
