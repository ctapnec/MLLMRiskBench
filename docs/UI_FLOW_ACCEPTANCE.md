# UI flow acceptance

This is the current coverage checklist, not a claim that every combination of
models, data and external failures has been proved correct. A page loading, a
Guide link resolving and a mocked stage transition are different checks. None
alone establishes that an operator can complete an experiment.

The 20 September audit was reopened after campaign review accepted an invalid
local wall-time setting and then reported an unnamed error in a background
operation. Prior acceptance remains historical evidence for its tested settings,
not acceptance of this newly reported boundary.

## Required coverage

For each applicable flow check valid inputs, omissions, invalid values, saved
state, repeated submission, errors, cancellation and reopening. Exercise real
form parsing and validation. Substitute external services only for controlled
fault injection; name that substitution in the evidence.

| Surface | Flows and boundaries | Evidence required |
| --- | --- | --- |
| Dashboard | System, campaigns, notices, job links, refresh | Live retained state; errors and busy-state browser tests |
| Build | Campaign/single run; create/save/reopen; model picker; modalities; sample; judges; budgets | Actual submitted fields; saved choices; validation before work starts |
| Local campaign | Installed text/image inputs, assessed model, preparation, start, local assessment | New isolated small Qwen campaign; real preparation and execution |
| Fresh hosted campaign | Installed corpus, configured route, no answer retries, price and output bounds | New isolated Haiku campaign within the existing total USD 5 test allowance |
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

- Run tests on the rig using its installed environments. Do not scan model
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
- Report actual calls and known charges against the existing USD 5 total
  Anthropic regression allowance, not a fresh allowance for every round.

Current execution evidence is under `runs/engineering/ui-flow-audit-20260920` on
the rig. Exact results and deployed revisions belong to findings RA-782 and
RA-783 in the development ledger, not to an unqualified assertion that every
possible model, source and external failure combination has been executed.

## Regression map

| Workflow family | Maintained automated coverage | Real acceptance in this audit |
| --- | --- | --- |
| Campaign and standalone choices | `test_campaign_validation_boundary`, `test_unified_campaign_flow`, `test_automatic_setup`, `test_builder_scope_browser` | New local text/image, fresh hosted text and saved-input hosted campaigns; standalone offline run |
| Preparation, capture, stop and resume | `test_operator_operations`, `test_automatic_analysis`, supervisor/lifecycle tests | Automatic handoffs in the three campaigns; failed SVM recovery and completed-work reopening |
| Saved-output assessment | `test_campaign_assessment`, retained judging executor tests | Local and Haiku assessment on each new measured answer; no regeneration for later assessment |
| Results, comparison, costs and exports | `test_workspace_comparison*`, `test_comparison_insights*`, workspace publication/accounting tests | New matched-input comparison, five chart measures, CSV/SVG downloads and cost totals reconciled against indexed rows |
| Human review | `test_human_review*` | Saved prompt/image display, wizard navigation and unrated personal CSV; synthetic ratings/roles/conflicts remain isolated tests |
| Response SVM | `test_response_svm*`, `test_automatic_analysis`, `test_svm_stats` | New study over saved answers, finalized-checkpoint failure recovery and an explicit insufficient-group outcome |
| Shared UI and configuration | `test_rig_web_busy_browser`, `test_rig_web_language*`, `test_operator_navigation`, configuration tests | Guide/menu destinations and tabs at desktop/mobile widths; actual failed campaign and invalid-form controls after deployment |
| Documents | `test_operator_documentation` | Follow the combined guide; review current versus historical instructions and preserved qualifications |

The patterns above name tests in `tests/ura` unless the executor/lifecycle test
lives in `tests/experiments`. Run the complete suite with the installed rig
environment and its Chromium browser dependency available. Do not count a
browser test as covered when the browser dependency caused it to skip.

Destructive installation scenarios, third-party outages, provider error
responses, independent reviewer roles and conflicting submissions use isolated
integration/browser tests. They do not require reinstalling working runtimes,
spending on every provider or manufacturing human research ratings. Windows-only
process/junction cases are not executed on the Linux rig and remain explicit
skips. The small real runs establish the documented workflows for their selected
models and inputs, not scientific coverage of every supported framework.

## Operator documents

[SMALL_CAMPAIGNS](SMALL_CAMPAIGNS.md) is the click-by-click reference. The
[walkthrough](UI_CAMPAIGN_WALKTHROUGH.md) explains navigation and recovery.
[Human review](HUMAN_REVIEW_UI.md) and [SVM](RESPONSE_SVM.md) describe their
protocols and advanced routes. The [runbook](../experiments/RUN_AND_RETURN.md)
contains CLI procedures, not additional mandatory UI preparation tasks.
[Earlier audit results](OPERATOR_REGRESSION_AUDIT.md) are dated evidence.
