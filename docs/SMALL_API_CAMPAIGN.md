# Your first small API campaign on the rig

This is a click-by-click guide for the currently configured rig console at
<http://localhost:8642/>. It creates a **new, separate Flash campaign** using
questions and images already given to Qwen in the Local campaign. You do not
need to download a model, install a framework, enter a filesystem path or run
a terminal command. The saved local answers are not generated again.

The completed reference is **UI demonstration - Flash matched text and images**.
You can inspect it without spending money. To execute your own example, follow
the steps below with a new name; do not start the completed reference again.

The important distinction: use **General -> Reuse local inputs for an API
comparison**. Do **not** use **Compose & review** for this retained-input route.
That button composes the ordinary pipeline, not the prepared matched collection.

## 1. Create the destination and select Flash

1. Open <http://localhost:8642/build?work_kind=campaign>.
2. Under **What are you building?**, leave **Campaign** selected.
3. In the **Campaign** dropdown select **New campaign**, not Local campaign or
   API campaign. Those names identify existing workspaces.
4. In **New campaign name**, enter `My first Flash campaign` (or a unique name).
5. Click the **Pipeline** tab. Open the target-model picker, choose **Hosted
   API**, and select only `google:gemini-3.8-flash`. Click **Done**. Do not select
   Haiku as a target unless you deliberately want Haiku to answer the questions.
6. Click **General**, then **Save campaign**. This creates a saved draft; it
   does not start calls. Keep working in this saved campaign.

Flash is already configured on this rig for text and images, low thinking and
4,096 output tokens. The forecast in step 3 shows the actual output allowance.
If it is different or Flash is absent, inspect **Config -> API targets** before
proceeding; do not substitute a similarly named model. No API key needs to be
copied into Build. The configured Google credential is already available.

## 2. Select the existing local inputs

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

## 3. Choose the small workload and prepare its replay

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

This exercise demonstrates the full UI flow. It stays separate from the thesis
study populations and does not claim that every framework/model combination has
been tested. Broader workflow and interpretation guidance is in
[UI_CAMPAIGN_WALKTHROUGH](UI_CAMPAIGN_WALKTHROUGH.md).
