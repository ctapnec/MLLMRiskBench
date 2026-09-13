# Final matched-input supplement

Approved by the operator on 13 September 2026, after the 11:12 UTC campaign
snapshot. This is a bounded supplement to the existing API campaign, not a new
independent sample or permission to repeat completed target calls. Statistical
synthesis, complete UI-flow acceptance and academic thesis completion remain
the main closeout tasks. Aggregate reporting continues every thirty minutes.

## Baseline and purpose

The baseline contains 11,433 measured hosted assignments on 2,888 distinct
retained local inputs. There are 10,318 usable answers, 1,097 documented
provider-policy outcomes, 16 missing answers and two outstanding Pro inputs.
All retained outcomes have local evaluation records. The eligible hosted
Haiku-assessed population is 9,296 outputs, including 51 with only invalid
verdicts. These are assessment coverage counts, not human-validated decisions.

Marginal input counts differ from shared input support. Fable and Sol have
348 and 265 assigned inputs, respectively, but their raw input intersection is
166. Sol and Astra have 265 and 258 assigned inputs, with an intersection of
225. This supplement prioritizes gaps in shared input coverage. Source,
framework, modality, policy and judging compatibility remain necessary before
any paired estimate. Equal numbers of successful answers are not a selection
objective: refusals and missingness are outcomes, not reasons to resample.

## Approved spending allocation

The latest operator-reported provider purses total USD 32.90. They are a new
dated observation, not a replacement for earlier observations or an addition
to existing credit. Account changes can include other projects and are not
automatically attributed to this campaign.

| Provider or role | Current purse (USD) | Supplement ceiling (USD) | Priority |
|---|---:|---:|---|
| Anthropic targets | 16.15 shared with judging | 10.00 | Fable first, then Opus |
| Haiku judging | same Anthropic purse | 5.00 | Every new eligible answer and missing matched-local assessments |
| OpenAI targets | 4.59 | 4.00 | Sol and Astra matched gaps |
| Google targets | 8.03 | 7.00 | Pro on the selected shared inputs |
| Kimi targets | 1.45 | 1.00 | Matching gaps in the same comparison population |
| DeepSeek targets | 2.68 | 2.00 | Matching gaps in the same comparison population |
| Total new spending | 32.90 | 29.00 | 3.90 remains unallocated |

The unallocated amount accommodates outstanding requests, transport retries
and uncertainty; it is not silently converted into more target calls. In
particular, the two old Pro inputs remain separately owned and cannot be
scheduled again by this supplement. Every physical target or judge request
counts against its applicable spending ceiling. Available provider credit
and cumulative campaign accounting must not be counted twice.

Exact selected inputs, provider-specific input token counts, unchanged output
allowances, forecast costs and their uncertainty will be recorded before
generation. Output allowances are not reduced simply to equalize sample sizes.
Reported usage and actual charges remain separate from forecasts and bounds.
The approved allocations are spending ceilings, not a promise that every dollar
can or should be exhausted.

### Selected supplement

Input-only selection and request counting identified the following additions.
Forecasts use each model's historical mean output length; full-allowance costs
are shown separately and exclude judging and transport retries. Token counters
retain whether their result is provider-native or an explicitly named estimate.

| Model | Requests | Text / image | Output allowance | Mean-length forecast (USD) | Full-allowance cost (USD) |
|---|---:|---:|---:|---:|---:|
| Fable 5.1 | 34 | 30 / 4 | 8,192 | 1.04 | 14.00 |
| Opus 5 | 20 | 13 / 7 | 6,144 | 0.52 | 3.11 |
| Sol | 7 | 5 / 2 | 8,192 | 0.27 | 1.16 |
| Astra | 9 | 5 / 4 | 8,192 | 0.21 | 3.74 |
| Gemini Pro | 21 | 11 / 10 | 4,096 | 0.22 | 1.06 |
| Total issuable | 91 | 64 / 27 | model-specific | 2.26 | 23.06 |

Four further DeepSeek requests were counted but remain unissued: the eligible
matching population contains only one complete source cluster and cannot form
this execution path's separate whole-cluster pilot and measured groups. This
is a selection limitation, not a DeepSeek model failure. The earlier DeepSeek
campaign remains retained. No arbitrary replacement inputs are added to spend
the unused allocation.

The preliminary 116-request inventory also contained 21 prior assignments or
paid attempts outside the measured-only comparison frame. Repeat exclusion
therefore checks all evidence classes and prior physical attempts, not only the
measured comparator population. These 21 requests are excluded; both apparent
Kimi gaps were already assigned. A historical, unused funding slot is not itself
a paid attempt, while any still-owned queued assignment remains excluded.

The retained source inventory identifies 161 corresponding local answers.
Seventy-seven already have owned judging slots and 84 receive new slots.
Those are funding-ownership counts, not proof of completed or valid judgments.
Coverage reconciliation must also include the saved corrected local conditions.

The selected requests represent several source contexts where identical
rendered requests have been deduplicated. The larger preliminary input-identity
inventory is therefore not the number of paid requests. The full-allowance total
exceeds some provider allocations, so successful completion of every selected
request is not guaranteed by the mean-length forecast. Dispatch uses actual
tracked spending stops, with space for two in-flight maximum-cost attempts
below each approved ceiling. This is not a renewed maximum-cost reservation for
every unstarted input. Unissued budget-limited assignments remain explicit.

## Outcome-independent selection

1. Freeze the existing model-input assignment sets, including queued and
    unsuccessful, diagnostic and unclassified assignments, plus all earlier
   physical attempts. Use input identities and source metadata, never
   model answers, verdicts or response lengths, to construct the candidate pool.
2. Find whole source clusters already represented for at least one other focal
   model. Require retained local input provenance and the same rendered prompt,
   media, source policy, framework and sampling seed. Preserve related variants
   and source-specific grading contexts.
3. Exclude any cluster that would repeat an already assigned input for the
   proposed target. Previously generated answers are not regenerated to obtain
   a different outcome. Identical provider requests with several source contexts
   remain one generation, with each grading context explicitly represented.
4. Prioritize clusters that complete the largest number of existing focal
   comparisons. Within equal priorities, use a declared deterministic,
   source-stratified ordering. Record every exclusion and the final selection
   before paid generation. Retain separate target-specific additions rather
   than describing them as an identical new sample for every model.
5. Select only the affordable part of this population using exact input counts
   and documented output-cost assumptions. Publish planned and realized common
   support separately. A source whose complete cluster cannot fit is excluded
   explicitly, not partially sampled without disclosure.

## Execution and judging

- Use the deployed, tested provider adapters and existing isolated runtimes.
  Do not reinstall frameworks or run default model-weight checksum scans.
- Start independent providers concurrently, with at most two active request
  workers per provider across this supplement and existing work. Collection
  does not wait for another provider's judging.
- Respect the outstanding Pro retry time and any explicit provider retry
  delay. Other providers do not wait on Google. Do not remain idle solely to
  obtain its two older responses after other useful work has finished.
- No automatic answer retries. Recognized transient HTTP or connection failures
  allow up to three additional transport attempts with bounded backoff. Record
  every physical attempt. Preserve explicit security-policy rejections as
  outcomes; an unexplained HTTP 400 is not automatically a refusal.
- Credit exhaustion or a non-transient billing failure stops that provider's
  remaining work, records the budget-limited disposition and leaves independent
  providers running. Investigate a systematic empty-answer condition before
  continuing to spend under the same configuration.
- Judge each new eligible output with the local procedure and Haiku. Reuse a
  verdict only for the identical saved output under the identical judging
  condition, never merely because two models received the same input. Check
  the corresponding local outputs for that same input population and judge
  any eligible output missing the required Haiku assessment.
- Run local scoring after target collection or independently where resources
  permit. Keep all persistent workers in tmux and resume saved progress after
  connection loss. Publish new assignments, responses, costs and judgments to
  the existing API and local campaign workspaces.

## Completion and analysis

The execution record must account for every selected assignment as an observed
outcome, explicit unissued budget/quota remainder, or an unresolved transport
state. An unissued input is not a missing model response. Each applicable
judging obligation must likewise be completed or given its substantive
exclusion. Invalid verdicts remain invalid, not completed valid classifications.

Analyze this supplement as an explicitly selected matched extension. Preserve
its selection indicator and generation condition, and do not pool it with
earlier cohorts as an independent random sample. Report gains in shared input
and source-cluster support, response coverage, truncation and judge coverage.
Independent human assessment remains a separate requirement for validity claims.

The same prepared selections and execution configuration must be inspectable
through Build, Jobs and campaign Stats. Diagnostic Build acceptance alone does
not demonstrate the full collection, retrospective judging and publication flow.

## Observed completion update - 13 September 2026

All 70 selected non-Google inputs are collected: Fable 34, Opus 20, Sol 7 and
Astra 9. Each saved outcome has its required local evaluation record; the 29
new eligible Haiku assessments are valid. A separately accounted benign Astra
transport observation is diagnostic evidence, not an extra measured study input.
The 21 selected Pro inputs remain queued for the recorded provider retry time;
the two older Pro inputs remain a separate obligation.

Matching-local coverage was reconciled by actual saved output and judging
condition. The 112 represented source-input identities match 189 local
assignments: 162 have valid Haiku verdicts, 15 have no usable answer, three belong
to the retired model, and nine are source-specific tasks outside the common
rubric. No eligible local Haiku answer in this population remains unassessed.
The 84 newly owned funding slots did not imply 84 missing verdicts and were not
spent again. Historical and corrected conditions remain separate.

Live UI inspection confirms visible local/API charts, readable Results details,
working figure/table exports and loading guards. Later bounded end-to-end
Build acceptance completed two Terra calls, saved-output local evaluation and
one new output-specific Haiku assessment, then published their costs and
judgments without repeating the target calls. The matching local output's
existing same-condition Haiku verdict was reused. The separately accounted
acceptance cost is USD 0.026256, outside production cohort totals. Evidence:
`build-ui-closeout-20260913` and ledger RA-671/RA-672. This exercises the
collection-to-judging-to-publication flow, not every model/framework combination.

The completed statistical work now includes focal paired, local/hosted,
same-base support, static/adaptive, portfolio, source-classification and
same-response judge analyses, plus the approved response-SVM study. Their
limitations remain explicit in Chapters V and VI. The Google remainder,
independent human assessment and final thesis/reproducibility review are still
open; this update does not declare the full study complete.
