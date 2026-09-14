# Running and examining campaigns in the web UI

For the exact rig-specific first campaign, use the
[click-by-click small Flash guide](SMALL_API_CAMPAIGN.md). It names each tab,
value, button, preparation wait and paid start action. The overview below is
not a substitute for that first-time walkthrough.

Build is the experiment editor. Campaigns groups related work; Jobs shows its
execution; Stats shows retained results. Local and hosted are model choices,
not separate creation wizards. The retained-input hosted flow has been exercised
through the browser: source selection, forecasting, prepared replay, collection,
local judging, Haiku judging and result/cost inspection. This bounded acceptance
used one diagnostic and one measured Terra input; it is not evidence that every
model/framework combination has completed a new UI campaign.

The production text/image example on 14 September also completed the full
hosted flow. Its reproduction details are below. It is a demonstration, not
an extension of the thesis study population.

## Inspect the retained studies

1. Open **Campaigns -> Local campaign** or **API campaign**. These are separate
   workspaces, not two names for the same collection.
2. In **Overview**, select a model and execution condition before interpreting
   historical failures and later recoveries. All conditions includes both; it
   does not automatically choose a model's best answer.
3. In **Results**, expand **Generation settings and usage** for context, output
   allowance, reported tokens, finish reason and the original artifact. A
   truncated answer can still contain usable text.
   **Recovery history** links explicitly recorded original outcomes to saved
   successor answers and their source artifacts. It preserves both executions
   and costs; it does not silently select the best output, merge generation
   conditions or copy a judgment between different answers.
4. Use **Judging** and **Compare** for output-specific decisions and matching.
   Missing, invalid and inapplicable decisions remain visible. One model's
   answer cannot inherit another answer's verdict on the same question.
   In **Compare**, choose each model's generation and judging condition, then
   use **Corpus**, **Framework** and **Modality** to narrow both sides. For a
   static comparison choose `replay`; keep adaptive frameworks separate. The
   filters remain in subsequent pages and CSV exports. An empty selection is
   shown as empty, not replaced with a different source.
5. **Costs** records physical attempts and charges. Unknown is not zero, and a
   provider purse update is not an invoice breakdown. **Activity** and
   **Campaign jobs** link to the original executions.
   **Download full campaign cost table** exports every model/role row, including
   rows on later table pages. It includes nominal charges, unresolved bounds,
   settlement coverage and reported token totals with missing-usage counts.
   Blank amounts mean unknown. The export is campaign-wide, includes historical
   and diagnostic work, and does not adopt the Results model/condition filters.
6. **Configure in Build** opens the saved draft. Editing it does not alter past
   or running jobs; that draft is not every historical recovery configuration.

Overview exports coverage and missing/truncation figures plus their matching
table. Model/condition filters are preserved. These are descriptive counts, not
a pooled safety ranking. Inspection and exports make no model calls.

## Create local work or a single run

1. In **Build**, choose **Campaign** and a name, or **Single run** for an
   independent Runner job. Select models once in the model picker.
2. Set sources and attacks in **Pipeline**, judges/defenses in **Evaluation**,
   source/model requirements in **Admission**, and sampling/resource limits in
   **Execution**. Reuse installed runtimes and assessed local-model settings.
3. Inspect **Current pipeline**, then **Save campaign** if applicable. Saving
   makes no calls. **Compose & review** shows the actual command and settings;
   execution requires the separate start action on the review page.
4. Follow the job in **Jobs** and its results in **Stats**. Offline runs contain
   mock outputs, not model evidence.

Input-selection limits, generation allowances and time limits are different
controls. Local answer retries default to one retry; paid campaigns use no
answer retry and up to three retries for eligible transport errors. Full
model-weight checksum checks are optional and off by default.

## Create a hosted comparison from saved local inputs

Keep the destination campaign's source and preparation choices saved. Later
controls appear after their prerequisite artifacts become available.

| Stage | Build action | Effect |
| --- | --- | --- |
| Sources | **Reuse local inputs for an API comparison -> Show saved runs -> Prepare selected inputs** | Prepares the retained local input inventory without generation |
| Workload | Select hosted models, then **Forecast matched hosted work -> Prepare forecast** | Applies per-model limits/settings and forecasts generation and judging costs |
| Inputs | **Prepare replay inputs** | Preserves prompts, media, seeds and whole source clusters |
| Preparation | **Count inputs and prepare collection -> Prepare counted collection** | Prepares programs and spending; may use token-count endpoints, not generation endpoints |
| Collection | **Review prepared collection -> Start prepared collection** | Runs the reviewed selection and publishes progress to the campaign |
| Continuation | Reopen the same review, then **Continue saved collection** | Reuses completed jobs, checkpoints and installed-runtime bindings |

Whole-cluster selection can leave room unused under a request limit. Different
model limits produce overlapping subsets, not identical sample sizes. Compare
actual shared inputs. Providers can collect concurrently; another provider's
judging need not delay generation. A recorded retry wait is not a model refusal
or an instruction to submit the same work again.

Matched preparation uses the saved replay inputs, even when the general draft
is still in offline mode. Its synthetic-only tool-input exclusion does not
filter or invalidate this retained selection. Keep defense set to **none**;
select **rules,guardrail** and the installed scoring guardrail in Evaluation.
In **Execution**, set a positive whole-number **--deadline-seconds** before
counted preparation. This is the durable window for starting calls, not a
per-answer timeout. The prepared programs retain this value; later draft edits
do not change an already prepared collection. If a preparation must be corrected
before any provider attempt, retain the old jobs and prepare a new version from
the same saved source, forecast and replay jobs. Do not edit retained programs.
Collection and output-specific judging remain separate stages.
For image inputs, launch the console with the same ordered `URA_MEDIA_ROOTS`
configuration as the CLI. Build preserves it for both cached/offline request
construction and network token counting. Enabling token counting forwards only
the selected providers' credentials; it does not grant access to other files.
The collection review includes the console's configured `URA_MODEL_STORE`
location when installed-runtime preparation is needed. No installation is
performed. A failed launch before collection initialization retries the same
prepared inputs and budget; an initialized collection resumes its saved state.

## Judge the actual saved answers

1. Under **Judge retained outputs locally**, use **Prepare remaining source
   runs**, choose a **Saved judging preparation**, then **Review local judging**.
   Start or resume on the recorded scoring device. After more collection jobs
   finish, prepare only newly completed sources.
2. Under **Same-input output coverage**, an input limit of zero includes all
   hosted inputs. Use **Prepare all-output coverage** and review the matching
   local/hosted answers, missing text and incomplete source preparations.
3. Use **Prepare all-output judging funding** and review ownership and uncovered
   outputs. An owned slot does not prove a valid verdict.
4. Select the Haiku model, then **Prepare all-output Haiku judging** and
   **Review all-output Haiku judging**. Check counts, allowance and funding
   before **Start or resume all-output Haiku judging**.
5. Inspect output-specific coverage in both campaigns. A finished selected job
   does not prove all campaign obligations complete. Reuse requires the same
   saved answer and judging condition, not merely a shared input or funding row.
   An output without funding in the new plan may already have a suitable verdict
   in its original campaign. Check **Compare** using the same judging condition
   and exact saved output before allocating or executing another judgment.

If the same logical request is independently funded in a different campaign,
Costs retains both physical executions. Reopening or republishing one execution
does not charge or count it twice, and a historical unknown charge stays unknown.
Results and cost publication can be repaired from saved artifacts without
repeating generation.

### Worked text/image example on the rig

Open **Campaigns -> UI demonstration - Flash matched text and images** to
inspect the completed example. Use **Configure in Build** to inspect its saved
choices. Do not press a collection or judging start button merely to view data.
To make another demonstration, save a separately named campaign first.

1. Choose **Local campaign** as the retained source. Under **Show saved runs**,
   select the Qwen3-VL-8B-Instruct runs for `xstest_full` and
   `vlsbench_release`. In this archive they are `run-a66a37fef7443227d3ff1ce0`
   and `run-549b0f0db2a1cb24bcb80a85`, each containing 100 retained inputs.
   Use **Prepare selected inputs**; this does not regenerate Qwen answers.
2. Select `google:gemini-3.8-flash` with text and image support, low thinking,
   a 4,096-token output allowance, selection seed 0 and a total request cap of
   12. Use **Prepare forecast**, then **Prepare replay inputs**. The achieved
   selection contains seven measured inputs and five separately labelled
   diagnostic inputs, not twelve independent measured cases.
3. In **Evaluation**, use **rules,guardrail**, no defense, and the installed
   Llama-Guard-3-8B scoring model on `cuda:0`. Preserve its installed revision.
   In **Execution**, set the call-start window to 3,600 seconds. Hosted answer
   retries stay at zero; eligible HTTP errors allow three retries.
4. Enable provider token counting and use **Prepare counted collection**.
   Review the actual text/image count results before **Start prepared
   collection**. This example's maximum was USD 0.189337 for first attempts,
   or USD 0.757348 including all transport retries, within the USD 1 Google cap.
   Counts and prices may differ for a later selection; these are not permanent
   per-campaign prices.
5. Follow the local and Haiku judging steps above. Here, all 12 saved answers
   received local evaluation records. All-output coverage found seven measured
   Flash answers and seven matching local answers. The seven local answers
   already had Haiku verdicts in **Local campaign**; their lack of new funding
   was not a missing judgment. Only the seven new Flash answers were charged.
6. Inspect **Overview**, **Results**, **Judging** and **Costs**. The example
   retained 12 usable responses without transport retries. Google token usage
   gives USD 0.027046 of bounded charge exposure, while seven Haiku assessments
   have USD 0.007470 of recorded cost. One Haiku output used an invalid verdict
   format; it remains visible and is not silently converted into a safety label.
7. In **Compare**, choose Flash on the left and **Local campaign / Qwen3-VL**
   on the right. Choose each saved generation condition and the matching
   Haiku judging condition, then filter to `replay` and one corpus/modality.
   The image slice has four matched inputs, three with valid verdicts on both
   sides. The text slice has three matched inputs, all jointly valid. Export
   each slice using **Download this page's counts**. Different local generation
   conditions are selected separately, not combined under a family label.

The example exercised the live browser controls and actual export downloads.
Its charts and costs are backed by the same saved responses as the comparison.
No model weights or framework environments were installed for this acceptance.

For partial historical runs and advanced imports, use the typed Tools commands
in [RUN_AND_RETURN](../experiments/RUN_AND_RETURN.md). Preserve original failed
runs and attach recoveries separately. External campaigns must not be presented
as fabricated console-created jobs.

## Analyze and export without repeating collection

1. Open the campaign in **Stats**. Choose the measured population, model,
   generation condition and judging condition before exporting a chart or table.
   Coverage diagrams describe assignments and outcomes; they are not pooled
   safety scores. A local evaluation record can contain abstention or a
   source-specific result rather than a common safety label.
2. For paired comparisons, open **Compare**, select the two exact conditions
   and keep corpus, framework and modality aligned. Check shared inputs and
   jointly valid judgments before interpreting differences. A sparse or empty
   intersection is reported as such, not filled with unrelated responses.
3. For source-specific metric tables, open **Tools**, select the owning campaign
   and `level2_report`, and enter the completed source results directory.
   Historical results also need the offered historical-code repository path.
   Set JSON, CSV and Markdown output paths inside the configured results root.
   Starting this analysis creates a campaign-owned job but makes no model or
   judge calls. The completed job exposes the resulting download links.
4. The Local campaign's source-classification example is `job-9238b9c4d1ab`;
   the static/adaptive comparison is `job-ebb5f0582d4b`. Their saved arguments
   and outputs provide concrete parameter examples. Do not combine their
   source-specific and common-response metrics into one score. Detailed
   analysis commands and denominator conventions are documented in
   [METRICS](METRICS.md) and
   [RUN_AND_RETURN](../experiments/RUN_AND_RETURN.md).

Keep a dated observation cutoff for each exported analysis. Later recoveries
or judge assessments can change available support; export a new analysis with
the revised selection rather than overwriting the earlier experimental condition.
Final reporting accounts separately for unissued inputs, missing responses,
truncation, invalid judgments and inapplicable scoring tasks. Human validity
requires independent ratings; neither completed jobs nor automated agreement
supplies them.

## Shared control layout

The scoring guardrail model has automatic revision and device configuration.
No revision or device selector is shown in Build. Preparation reads the installed
model's completion metadata and records its revision without downloads or weight
checksums. Existing explicit CLI pins remain supported for historical reproduction.
At loading time, automatic placement prefers one visible GPU with sufficient free
memory, or splits across visible GPUs when needed; it does not spill to CPU when
GPU capacity is insufficient. CPU-only hosts remain supported. Effective device
placement is retained with guardrail verdicts. The ordinary Runner and matched
hosted preparation share this revision resolution.

Standalone action rows have space above them and between buttons, and wrap on
narrow screens. This includes Stop job, prepared collection and judging starts,
and the saved-input preparation actions. Configuration editor actions also wrap.
In Collect prepared inputs, Review prepared collection has its own action row
below Workers per provider; preserve that separation when editing the panel.
Optional checkbox rows align the checkbox with the first line of their label;
the full label is clickable and long explanations wrap without overlapping.

For UI maintenance, reuse the shared `action-row` or `review-actions` classes
for these action groups and `checkrow` with a text `span` for standalone checkbox
labels. Keep compact model selectors and table actions in their existing layouts.
The spacing rules do not change defaults, submitted parameters or job actions.

These conventions apply across the console, not only to Build:

- Separate standalone actions from preceding fields by at least 1rem. Use
  0.75rem gaps between action buttons or button-like links, with wrapping at
  narrow widths. Paragraph action groups also keep space below them.
- Use the shared field layout for saved selections. Compare condition groups
  have padded borders and 1rem between successive selectors. Tools submit
  actions, repeatable-field controls and configuration actions use the same
  spacing scale.
- Provider-key editors use padded, theme-aware password fields. Keep Clear
  separated from Save, and never populate the field with a saved credential.
- Preserve action containers when the human-review wizard moves submission
  and deferral controls between steps. Desktop and mobile footers use the
  same action gap. Disabled prerequisites remain visibly disabled.
- Keep dismiss buttons clear of notice titles. Model search fields and
  funding cards must use the active light/dark palette.
- Compact navigation, filter chips and model-choice lists have their own
  deliberate spacing; review them for collisions and wrapping rather than
  treating them as standalone form actions. Wide result tables scroll inside
  their cards, not across the entire page.

For a styling acceptance pass, inspect Dashboard, every Build tab and expanded
framework panel, target and judge dialogs, Campaigns and all campaign sections,
Tools forms, Jobs and job details, Stats and its detail dialog, configuration
editors, provider keys, artifacts, and human evaluation. Check phone, tablet
and desktop widths, plus dark mode. Include ready, pending, failed, empty and
disabled states. Use isolated fixtures for rating/submission flows; inspecting
production styling must not create campaign work, paid calls or human ratings.
The rig-only browser checks in `test_rig_web_action_spacing.py`, the command,
cost and provider layout checks, `test_human_review_browser.py` and the shared
backend-wait checks cover these layout and interaction contracts. Verify new
regressions against the previous implementation as well as the corrected one.
