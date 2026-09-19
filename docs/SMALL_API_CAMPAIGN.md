# Your first small API campaign

Local and hosted campaigns share one workflow: configure, review, start and
inspect results. The console handles preparation and selected judging.

Use the rig console at <http://localhost:8642/>. Create a new demonstration
campaign rather than restarting a completed thesis campaign.

## 1. Create the campaign and choose a model

1. Open **Build** from the main menu.
2. Under **What are you building?**, select **Campaign**.
3. Leave the selector on **New campaign** and enter a name.
4. Open **Pipeline -> Target models** and select one configured hosted model.
   A configured Flash or Haiku route is suitable for a small demonstration.
5. Choose measured execution. Check the model's output allowance in
   **Configuration -> API targets** before paid work.
6. Return to **General** and click **Save campaign**.

The provider key must already be configured. No hosted model download or
framework reinstall is needed. The optional Guide explains the same workflow.

## 2. Choose the inputs

In **General -> Campaign workflow -> Input selection**, choose one option.
Both options use the same review and start actions.

### A. Installed corpora and attack frameworks

1. Choose **Installed corpora and attack frameworks**.
2. In **Pipeline**, select the text modality, `xstest_full` and `replay`.
3. In **Execution**, set the per-arm limit to **1**, sample seed to **0**,
   trajectory seeds to **0**, maximum queries to **1** and turns to **1**.
4. Leave automatic call-limit calculation enabled and Admission on Automatic.

Other installed corpora and supported attackers use the same route. Prepared
attackers may require choosing attack material or capture settings in their
attacker panel. Reuse working installations. Selecting a corpus does not also
select its similarly named attacker.

### B. Reuse saved local inputs

1. Choose **Reuse saved local inputs for comparison**.
2. In the source panel below, choose the source campaign and click
   **Show saved runs**.
3. Check the local runs whose questions, images and delivered attack prompts
   you want to reuse. Their answers are not regenerated.
4. Set the displayed per-model **Input request cap**, for example **12**.
   This includes diagnostic requests; whole source clusters stay together.
5. Include enough inputs and capacity for a diagnostic cluster and a separate
   measured cluster. Review supplies the actual counts.

Reused inputs preserve their saved prompts. Fresh selections require matching
actual input identities and experimental conditions for paired comparison;
the same numerical seed alone does not establish this.

## 3. Choose evaluation and spending limits

Return to **General -> Campaign workflow**.

1. Enter an **API collection ceiling (USD)** for target requests, necessary
   diagnostics and inline hosted scoring.
2. Leave **Fill missing original local-evaluator verdicts** checked if you want
   automatic local assessment. Keep **Evaluation** on **rules** and
   **guardrail**. The installed scoring revision and device are automatic.
3. Optional: check **Assess saved answers independently with Haiku**, choose
   its evaluator and enter a separate **Haiku assessment ceiling**.
4. In **Execution**, use a **3600-second** call-start window for this example.
   It is not an individual-answer timeout.
5. Click **Save campaign**.

These are campaign limits, not the provider's current balance. Hosted answer
retries remain zero; eligible HTTP errors have the configured retry policy,
normally three retries. Usable truncated answers and documented policy
refusals remain recorded outcomes.

Assessment covers pending measured answers in this campaign, including earlier
pending answers. Valid existing verdicts are skipped. Missing answers,
unavailable context and source-specific tasks remain explicit exclusions.
Haiku assesses each model's own answer; an identical input does not allow
copying another model's verdict. Images use the saved text proxy, not pixels.

Matching answers in another campaign are not automatically all selected.
Use that campaign's **Evaluate saved answers** or the existing paired assessment
controls when the intended comparison also requires new source-side verdicts.

## 4. Review once

1. In **General**, click **Review campaign**.
2. Follow automatic preparation on its progress page. You can leave and return
   through **General -> Prepared and active work**.
3. When the review appears, inspect models, measured requests, additional
   diagnostic calls, output allowances and selected assessments.
4. Check collection and Haiku spending ceilings.

Preparation generates no answers or verdicts. Token counting may contact the
selected provider. Saved-input preparation counts its requests; fresh/adaptive
requests are counted before each API attempt. Forecasts and request allowances
are not provider invoices. Unused conservative allowances are not actual costs.

Do not start separate forecast, replay, acquisition or assessment-preparation
jobs. Those stages are internal.

## 5. Start once and follow progress

Click **Start campaign**. The same page follows connection checks, collection,
selected local assessment, selected Haiku assessment and published results.

**Technical jobs** exposes details without requiring operator handoffs. Returning
to the page does not regenerate completed answers or identical valid judgments.

If the actual Haiku workload cannot fit its ceiling, collection remains saved
and assessment pauses before spending. **Evaluate saved answers** lets you
explicitly choose a smaller assessment or a different allowance.

## 6. Stop, resume and inspect results

- **Stop campaign** stops active work and prevents later stages.
- **Resume campaign** continues interrupted work using its saved checkpoints.
  If settings must change, correct the reported choice and review again.
  Do not restart completed collection just to continue judging.
- **Results** shows answers, missingness, token usage and truncation.
- **Judging** shows output-specific decisions and assessment coverage.
- **Costs** shows recorded attempts and available charges, not account credit.

Detailed click-by-click instructions for comparison charts, exports, human
evaluation and SVM results are in
[Campaign results and optional analysis](CAMPAIGN_RESULTS_AND_ANALYSIS.md).
These are optional analyses, not preparation requirements.

Older saved preparations and interrupted jobs remain available through their
existing continuation controls. The new workflow does not restart them or
change their historical results.
