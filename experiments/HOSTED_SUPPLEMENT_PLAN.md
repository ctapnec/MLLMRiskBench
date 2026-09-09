# Additional hosted inputs from the retained local campaign

Status: no-call assessment, 9 September 2026. The original 941-input hosted
assignment and its matched judging are complete and published. This supplement
responds to the operator's checked account balances and request for additional
inputs. It is a new, non-overlapping cohort, not a restart of completed work.
No supplemental target, token-count or judge request has been sent.

Judging requirement clarified by the operator on 9 September: use exactly the
same input identities in local and hosted Haiku assessment. Judge all eligible
existing local answers to the selected hosted inputs, reusing completed verdicts
only for their exact original answers. Different model rosters need not yield
equal answer counts. Do not generate new local answers, duplicate observations,
or select replacement inputs to force equal totals. Invalid verdicts remain
unscored in their fixed cohorts. This local-coverage extension precedes the
additional API batch below, and its actual charges reduce that batch's available
Anthropic funding.

Capacity result, 9 September at 14:25 UTC: the 743 hosted answers cover 81
distinct matched input identities. The validated local view contains 304
eligible distinct answers for those same inputs, with 259 already assessed by
Haiku. Completing all existing same-input local coverage therefore requires 45
additional local judgments. Every hosted input already has at least one judged
local counterpart. The operator explicitly confirmed that these existing local
generations, not an artificially equal count of answers, are the intended
comparison. The 45-answer local-only judging worker started at 14:31 UTC under
`engineering/haiku-local-input-coverage-20260909/`. It preserves all 259 earlier
local and 743 hosted judgments and makes no target or hosted-answer judge calls.
The capacity proof is
`engineering/haiku-equal-coverage-preview-20260909/result.json`.

The extension completed at 14:45:31 UTC: 45 new local judge calls, all valid,
47,933 input tokens, 1,125 output tokens and USD 0.053558. All 1,002 earlier
judgment artifacts remain unchanged. The complete same-input cohort now has
304 local assessments (302 valid, two invalid) and 743 API assessments (740
valid, three invalid). Its combined known judging cost is USD 1.221041, with
the previous USD 0.014848 unknown-usage hold unchanged. No new target call was
made. Deduct the extension charge from the reported Anthropic balance when
funding the supplement; this gives an indicative USD 84.086442 balance before
other or delayed charges, not a newly checked provider balance.

## Funds and first-batch scope

The operator reported these account balances after the original judging run.
They are account-level observations, not per-request billing records. Preserve
the original 20 percent reserves, including Anthropic's reserve after its
earlier unrelated-project spending. Pending or delayed charges must reduce
new funding; do not rewrite unknown historical usage as zero.

| Provider | Checked balance, USD | Untouched original reserve, USD | Additional headroom before unposted charges, USD |
|---|---:|---:|---:|
| OpenAI | 37.34 | 8.00 | 29.34 |
| Anthropic | 84.14 | 18.00 | 66.14 |
| Kimi | 9.54923 | 3.00 | 6.54923 |
| DeepSeek | 9.61 | 2.00 | 7.61 |

The combined headroom is USD 109.63923. It is not an instruction to spend the
entire amount. The first additional batch has the following prospective caps.
Final quantities may be lower because source clusters remain whole and full
request token counts replace the 4,000-input-token planning assumption.

| Target | Additional input cap | Unchanged maximum output tokens | Conditional target reservation, USD |
|---|---:|---:|---:|
| GPT-6 Astra | 18 | 8,192 | 8.272800 |
| Claude Fable 5.1 | 20 | 8,192 | 8.992000 |
| Claude Opus 5 | 60 | 6,144 | 10.416000 |
| Claude Sonnet 5 | 150 | 4,096 | 7.344000 |
| Claude Haiku 4.5 | 140 | 2,048 | 1.993600 |
| GPT-5.6 Sol | 30 | 8,192 | 5.515200 |
| GPT-5.6 Terra | 50 | 6,144 | 4.186400 |
| GPT-5.6 Luna | 400 | 4,096 | 2.366080 |
| GPT-5.5 | 20 | 8,192 | 5.415200 |
| Kimi K3 | 40 | 8,192 | 5.395200 |
| DeepSeek V4-Pro | 180 | 8,192 | 6.789658 |
| Total targets | 1,108 | Model-specific | 66.686138 |

Reservations use retained effective-dated prices, the existing conservative
OpenAI input allowance and DeepSeek's peak tariff. These are conditional
maximum-token calculations, not expected charges or measured affordability
of an as-yet-unselected population. No output allowance or reasoning setting
is changed to make this new cohort appear cheaper or more stable.

The initial arithmetic allowed 2,216 Haiku requests for one local counterpart
and one hosted answer per additional input. At 12,288 input and 512 output
tokens, that conditional reservation is USD 32.903168. This is not a bound for
the clarified all-local-answers-on-the-same-inputs requirement: resolve the
actual local answer inventory, deduplicate it, and exclude exact completed
judgments before funding. Reduce target allocations if the actual judging
requirement exceeds the available reservation. The initial conditional combined
reservation is USD 99.589306. Anthropic accounts for
USD 61.648768 including judging, OpenAI for USD 25.755680, Kimi for USD
5.395200 and DeepSeek for USD 6.789658. This leaves USD 10.049924 inside the
additional headroom for counting differences, retry exposure and delayed old
charges, in addition to the untouched original reserves.

The no-call arithmetic is retained on the rig under
`engineering/hosted-supplement-assessment-20260909/result.json`. The original
budget, responses, local judgments and Haiku artifacts remain unchanged.

## Selection and execution requirements

1. Freeze the completed assignment by exact target condition and input identity.
   Exclude every earlier assigned pair, including failed inputs and diagnostic
   probes. Do not retry a policy rejection or choose replacements based on a
   favorable or unfavorable answer.
2. Extend the existing seed-0, balanced whole-source-cluster ordering. Prove the
   previous assignment is the corresponding prefix, then select only its new
   tail. Preserve cross-model nested inputs where modalities are compatible.
   Stop at a whole-cluster boundary if the next cluster exceeds the new cap.
3. Resolve every new prompt, image and recorded framework trajectory to its
   retained local source. Do not regenerate frameworks, resample images, use
   retired model outputs as counterparts or change generation parameters.
4. Derive complete request token counts and fund the selected first attempts,
   retry margin and judging before dispatch. Use explicit supplemental spending
   caps after the original reserves; do not reset the old campaign allowance
   or treat every existing unknown-cost reservation as a new charge.
5. Reuse verified installed runtimes and valid transport evidence. Refresh only
   genuinely expired or incompatible transport evidence. Any necessary paid
   readiness inputs consume this new batch's allocation and remain diagnostic.
6. Run the funded continuation on the rig in tmux. Preserve zero answer-quality
   retries and at most three retries for qualifying HTTP errors, each with its
   own reservation. Empty answers still require investigation before further
   paid execution; usable truncated answers remain retained and flagged.
7. Apply the local cascade or the source-authoritative evaluator to every
   applicable retained API answer. Then apply Haiku to eligible hosted answers
   and matching selected local answers, retaining invalid judge verdicts as
   unscored and unknown usage as unknown. Reuse completed local judgments only
   with exact answer, input, judge-configuration and evidence identity. Include
   all eligible existing local answers on those same input identities. Resolve
   this inventory before funding additional API inputs, and report input
   coverage, per-model answer counts and invalid-verdict counts separately.
8. Publish the supplemental cohort separately, with exact selection coverage,
   local/hosted model, framework, corpus, arm, input and generation counts,
   local/Haiku labels, token conditions, truncation and failed-output categories.
   Original and supplemental cohorts may have an explicitly deduplicated union;
   neither comparison links nor retries are independent new observations.

The original 941-input campaign remains available at
`/stats/job/hosted-haiku-outcome-recovery-20260909`. Its 743 matched comparison
links use 259 unique local answers and 743 hosted answers; they are not a
full-corpus ranking or independent human validation. The same limitation
applies to this prospective selected-input supplement.
