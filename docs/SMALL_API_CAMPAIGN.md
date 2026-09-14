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
   defense **none**, and use the installed Llama Guard model, revision and device
   from section 4. Ordinary Runner evaluates through this selected cascade as
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
5. Click **Prepare replay inputs**. Wait for that job to complete, then return.

The reference selection, with the retained seed-zero inputs, contains **seven
measured inputs (three text, four image) and five diagnostic inputs**. Twelve
requests does not mean twelve independent measured cases. Whole clusters stay
together, so other caps can leave unused room. Do not change the seed, query
counts or source selection halfway through preparation.

## 4. Set evaluation and the call-start window

1. Click **Evaluation**. Under judges, uncheck **llm** and select **rules** and
   **guardrail**. Keep the defense **none**. Target collection and retained-output
   judging are separate stages in this flow.
2. Set the scoring guardrail model to `meta-llama/Llama-Guard-3-8B` and its
   scoring device to `cuda:0`. The installed revision on this rig is:
   `7327bd9f6efbbe6101dc6cc4736302b3cbb6e425`.
   Use the scoring guardrail fields, not the defense guardrail fields.
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

1. Find **Count inputs and prepare collection**. Enable the provider token-count
   option (the checkbox allowing network counting).
2. Click **Prepare counted collection**. This constructs exact requests and
   counts their inputs; it does not generate answers. Wait for completion.
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

## 6. Apply the local judge to the saved answers

1. Open your campaign's **Configure in Build -> General**.
2. Find **Judge retained outputs locally** and click **Prepare remaining source
   runs**. Wait for completion, then return to the same page.
3. Choose its completed **Saved judging preparation**, then click **Review
   local judging**.
4. Confirm the existing guardrail and `cuda:0`, then **Start or resume local
   judging**. Wait for completion. This scores saved Flash answers; it does
   not repeat Flash target calls or require a new framework installation.
5. Inspect the campaign's **Judging** tab. A local evaluation record can be an
   abstention or inapplicable result; coverage alone is not a valid safety score.

## 7. Apply Haiku to each new eligible answer

1. Return to **Configure in Build -> General**. Under **Same-input output
   coverage**, leave **input limit 0** and **seed 0**. Here, zero means all inputs
   in this small hosted selection, not the entire historical local campaign.
2. Click **Prepare all-output coverage**. Wait for completion, then return.
   The reference found seven measured Flash answers and seven matching saved
   Qwen answers. The diagnostic answers are outside this common judging subset.
3. Click **Prepare all-output judging funding**, wait, then **Review all-output
   judging funding**. Existing judgments on identical saved local answers do
   not need new funding or execution. New Flash answers need their own verdicts.
4. Select **Haiku** `anthropic:claude-haiku-4-5-20251001` in this judging panel.
   Click **Prepare all-output Haiku judging** and wait for completion.
5. Click **Review all-output Haiku judging**. Check which outputs are new,
   already judged or unfunded and the Anthropic cost limit. Then click **Start
   or resume all-output Haiku judging**. **This spends Anthropic credits.**
6. The completed reference executed seven new Flash assessments for **$0.007470**
   recorded cost. Six were valid and one had an invalid verdict format. All
   seven matching Qwen answers already had Haiku verdicts. A new run may differ;
   invalid results remain visible and are not silently changed into labels.

## 8. Examine and compare your results

1. Open the destination campaign. **Overview** shows coverage; **Results** shows
   outputs, generation settings, token usage and truncation; **Judging** shows
   answer-specific decisions; **Costs** shows physical attempts and charges.
2. Open **Compare**. Choose your Flash campaign/model on the left and **Local
   campaign / Qwen3-VL-8B-Instruct** on the right. Click **Update choices /
   compare** to load the dependent choices.
3. Select the relevant generation condition on each side and the same Haiku
   judging condition. Click **Update choices / compare** again if the condition
   or corpus choices have just changed.
4. For text, choose `xstest_full`, framework `replay`, modality `text`. For images,
   use a separate view with `vlsbench_release`, `replay`, `image` and the local
   image generation condition. Apply the choices.
5. Read the shared-input and jointly valid-verdict counts before comparing
   labels. The reference has three jointly valid text pairs and three valid
   image pairs out of four matched images. Export each view with **Download
   this page's counts**.

The completed route-2a exercise demonstrates that retained-input UI flow.
Section 2b describes the separate direct Runner controls; documenting them is
not evidence that every framework/model combination has been executed. Keep
new demonstrations separate from the thesis study populations. Broader
workflow and interpretation guidance is in
[UI_CAMPAIGN_WALKTHROUGH](UI_CAMPAIGN_WALKTHROUGH.md).
