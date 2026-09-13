# Running and examining campaigns in the web UI

Build is the experiment editor. Campaigns groups related work; Jobs shows its
execution; Stats shows retained results. Local and hosted are model choices,
not separate creation wizards. Complete paid end-to-end acceptance remains open;
component tests and existing CLI results do not replace it.

## Inspect the retained studies

1. Open **Campaigns -> Local campaign** or **API campaign**. These are separate
   workspaces, not two names for the same collection.
2. In **Overview**, select a model and execution condition before interpreting
   historical failures and later recoveries. All conditions includes both; it
   does not automatically choose a model's best answer.
3. In **Results**, expand **Generation settings and usage** for context, output
   allowance, reported tokens, finish reason and the original artifact. A
   truncated answer can still contain usable text.
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
| Sources | **Prepare a matched follow-on -> Choose source runs -> Prepare selected inputs** | Prepares the retained local input inventory without generation |
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

For partial historical runs and advanced imports, use the typed Tools commands
in [RUN_AND_RETURN](../experiments/RUN_AND_RETURN.md). Preserve original failed
runs and attach recoveries separately. External campaigns must not be presented
as fabricated console-created jobs.
