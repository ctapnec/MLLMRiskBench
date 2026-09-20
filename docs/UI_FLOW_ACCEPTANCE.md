# UI flow acceptance

This is the current coverage checklist, not a claim that every combination of
models, data and external failures has been proved correct. A page loading, a
Guide link resolving and a mocked stage transition are different checks. None
alone establishes that an operator can complete an experiment.

Use this checklist to select and document acceptance work for a change. Dated
executions, budgets, revisions and pass/fail findings belong in the
[archive](archive/README.md) and development ledger, not in the reusable checklist.
Previous acceptance covers its tested settings, not a newly reported boundary.

## Required coverage

For each applicable flow check valid inputs, omissions, invalid values, saved
state, repeated submission, errors, cancellation and reopening. Exercise real
form parsing and validation. Substitute external services only for controlled
fault injection; name that substitution in the evidence.

| Surface | Flows and boundaries | Evidence required |
| --- | --- | --- |
| Dashboard | System, campaigns, notices, job links, refresh | Live retained state; errors and busy-state browser tests |
| Build | Campaign/single run; create/save/reopen; model picker; modalities; sample; judges; budgets | Actual submitted fields; saved choices; validation before work starts |
| Local campaign | Installed text/image inputs, assessed model, preparation, start, local assessment | Isolated small campaign on a compatible installed model; real preparation and execution |
| Fresh hosted campaign | Installed corpus, configured route, no answer retries, price and output bounds | Isolated small campaign on an authorized route within the recorded cumulative test allowance |
| Matched hosted campaign | Saved local inputs, whole clusters, source/model changes, insufficient sample | New isolated comparison; match actual input identities; distinguish diagnostics |
| Mixed selection | Local/hosted constraints and incompatible wall-time or modality choices | Real validation; no silent change of submitted experimental settings |
| Standalone run | Dry run, no-call preflight, probe, canary, measured run | Route and launcher tests; actual no-call/dry path; explicit real-call start |
| Prepared attacks | Saved material selection, capture, missing runtime/material, automatic attachment | Installed-material checks; isolated capture and failure tests; no reinstall |
| Models and runtimes | Discovery, readiness, installation/pull controls, contention and errors | Read-only installed-state checks plus isolated lifecycle tests; no redundant downloads |
| Operations and Jobs | Work/technical views, completion/failure, stop, restart, resume, stale tabs | Real subprocess stop/recovery tests and saved checkpoint identities |
| Local/Haiku assessment | Original cascade, output-specific selection, limits, no pending answers, recovery | New eligible outputs, unchanged-verdict reuse and isolated failure tests |
| Results and costs | Planned, reached, missing, policy, truncated and replaced outcomes; token/cost coverage | Independent retained-row reconciliation and CSV exports; unknown is not zero |
| Compare | Campaign/job ownership; models; All; generation and judge selectors; selection rules | Real retained cohorts at desktop/mobile widths; figures agree with exported counts |
| Human evaluation | Personal form, drafts, defer, export; independent wizard, assignments, ratings, adjudication | Real preparation/media on QA outputs; synthetic ratings only in isolated test studies |
| SVM | Source/cohort selection, insufficient support, analysis, resume, reports and exports | Real saved study inspection plus isolated fit/predict/recovery regressions |
| Configuration | Keys, routes, prices, paths, validation, save/reload and conflicts | Isolated configuration writes; never alter production credentials to test a form |
| Common UI | Navigation, Guide anchors, themes/language, dialogs, padding, exports and loading states | Desktop/mobile browser checks including invalid hidden-tab controls and HTTP errors |
| Documents | All current guide actions, CLI counterparts, links, anchors, numbering and preserved qualifications | Follow the documented flows; mechanical checks supplement semantic review |

## Evidence and release discipline

- Run execution-dependent tests on the configured test host using installed
  environments. Do not scan model
  weights, reinstall frameworks or repeat historical campaigns as a regression.
- Keep new QA data outside research populations and preserve the operator's
  failed campaign. Do not manufacture human ratings in research records.
- Keep initial failures and corrected results separately. Add a regression that
  detects each fix when reversed. Repeat affected workflows after the fix.
- Distinguish a live read-only check, real execution, isolated integration test,
  injected failure and an untested case. A skipped test is not a pass.
- Record findings, exact evidence and release state in `Thesis-EN/Codex_Reaudit.md`.
  Detailed verification artifacts remain outside Git. Do not append operational
  chronology to academic chapters.
- Before paid acceptance, record the approved provider routes and cumulative
  test allowance. Report actual calls, known charges and unresolved exposure
  against that allowance; another regression round does not create new funding.

Retain evidence identifying the tested revision, configuration, input population,
environment and observation time. Record untested combinations and limitations
alongside successful cases. A corrected preparation or publication error does
not authorize repeating successful model calls.

## Regression map

| Workflow family | Maintained automated coverage | Acceptance evidence to collect |
| --- | --- | --- |
| Campaign and standalone choices | `test_campaign_validation_boundary`, `test_unified_campaign_flow`, `test_automatic_setup`, `test_builder_scope_browser` | Local text/image, fresh hosted text and saved-input hosted flows; standalone offline run; saved settings survive reopening |
| Preparation, capture, stop and resume | `test_operator_operations`, `test_automatic_analysis`, supervisor/lifecycle tests | Automatic handoffs; nested diagnostic stop/recovery; completed-work reopening and stale-tab reuse without new calls |
| Saved-output assessment | `test_campaign_assessment`, retained judging executor tests | Local and Haiku decisions on eligible saved outputs; unchanged-verdict reuse; no regeneration for later assessment |
| Results, comparison, costs and exports | `test_workspace_comparison*`, `test_comparison_insights*`, workspace publication/accounting tests | Matched-input comparison and supported chart measures; CSV/SVG and cost totals reconciled against indexed rows |
| Human review | `test_human_review*` | Saved prompt/image display, wizard navigation and personal CSV; synthetic ratings, roles and conflicts remain isolated tests |
| Response SVM | `test_response_svm*`, `test_automatic_analysis`, `test_svm_stats` | Saved-answer study, checkpoint recovery and insufficient-group outcome; inspection does not retrain |
| Shared UI and configuration | `test_rig_web_busy_browser`, `test_rig_web_language*`, `test_operator_navigation`, configuration tests | Guide/menu destinations, loading/error states and desktop/mobile tabs; failed-work and invalid-form controls |
| Documents | `test_operator_documentation` | Follow the combined guide; review current versus historical instructions and preserved qualifications |

The patterns above name tests in `tests/ura` unless the executor/lifecycle test
lives in `tests/experiments`. Focused changes use the affected acceptance suites;
they do not establish complete release acceptance. A complete release acceptance
requires the full suite with the installed test environment and browser dependency
available. Do not count a browser test as covered when the browser dependency
caused it to skip.

Destructive installation scenarios, third-party outages, provider error
responses, independent reviewer roles and conflicting submissions use isolated
integration/browser tests. They do not require reinstalling working runtimes,
spending on every provider or manufacturing human research ratings. Platform-specific
process and filesystem cases require the relevant platform; a skip on another
platform remains explicit. Small real runs establish workflows for their selected
models and inputs, not scientific coverage of every supported framework.

## Documentation maintenance and regression

[SMALL_CAMPAIGNS](SMALL_CAMPAIGNS.md) is the canonical local/API operator recipe;
[Campaign workspaces](CAMPAIGN_WORKSPACES.md) owns the current workflow contract.
The Guide, README, walkthrough, CLI runbook and technical references must agree
on current action names and responsibilities without maintaining competing
setup sequences. Advanced CLI and historical procedures may retain explicit
technical stages when clearly identified as such.

When consolidating or revising documentation:

1. Map previous sections and operator actions to their retained destinations.
   A link to a general overview is not a replacement for a missing click sequence.
2. Preserve local/API differences, reference outcomes and their qualifications.
   An observed price, answer count, timing or validity rate is not a required
   outcome or a current allowance for a new campaign.
3. Check links, anchors, heading numbering, step sequences and retained entry
   points. Moving an archive requires updating its relative links as well as
   incoming links; retired filenames require an explicit compatibility decision.
4. Follow the documented controls in the browser. Text matching alone cannot
   show that the action works, submits the stated values or preserves a draft.
5. Use omission/reversal tests for required actions and scientific qualifications.
   Deleting a required example, action or section link must be detected by its
   corresponding documentation regression.
6. Keep current instructions separate from dated executions. Historical amounts
   name their observation date; campaign completion claims require retained
   evidence. Preserve old technical records in the archive rather than editing
   them into an apparently current recipe.

The content-preservation review includes all of the following:

| Guide content | Required distinctions |
| --- | --- |
| Creation and selection | Campaign/single run, model picker, modality scope, local text/image arms, fresh versus retained inputs |
| Evaluation and limits | Local retries versus hosted transport retries, original cascade, separate collection/Haiku ceilings, output allowance, sampling and wall-time semantics |
| Review, start and recovery | Automatic paths/setup, explicit real-call start, return navigation, stop/resume, active/failed work and expired connection evidence |
| Results and references | Generation settings, diagnostics, missingness, truncation, valid assessment coverage, unknown local cost, dated local and hosted examples |
| Hosted follow-on | Actual saved prompts/media, available source capacity and output-specific judgments for new answers |
| Compare and exports | Model/generation/judge selection, All views, exploratory rules, individual-job comparisons, denominators and export scope |
| Human evaluation | Personal review, drafts, deferral and export; independent arrangements, enrollment, ratings and adjudication |
| SVM | Local-only or matched selection, recorded teacher labels, support/group limits, execution/resume, reports, Stats, baselines and trusted reuse |

`tests/ura/test_operator_documentation.py` checks maintained documents and their
links and anchors. Run it with the affected browser/backend regressions. Review
meaning and content preservation separately: automated string and link checks
cannot establish that documentation is complete or accurate.

## Operator documents

[SMALL_CAMPAIGNS](SMALL_CAMPAIGNS.md) is the click-by-click reference. The
[walkthrough](UI_CAMPAIGN_WALKTHROUGH.md) explains navigation and recovery.
[Human review](HUMAN_REVIEW_UI.md) and [SVM](RESPONSE_SVM.md) describe their
protocols and advanced routes. The [runbook](../experiments/RUN_AND_RETURN.md)
contains CLI procedures, not additional mandatory UI preparation tasks.
[Earlier audit results](archive/OPERATOR_REGRESSION_AUDIT.md), the
[previous acceptance record](archive/UI_FLOW_ACCEPTANCE_20260920.md) and the
[consolidation record](archive/DOCUMENTATION_MAINTENANCE.md) preserve dated evidence
and the original section mapping.
