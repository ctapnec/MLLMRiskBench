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
the rig. Completion of this checklist requires the recorded results; this file
does not assert that pending acceptance has passed.

## Operator documents

[SMALL_CAMPAIGNS](SMALL_CAMPAIGNS.md) is the click-by-click reference. The
[walkthrough](UI_CAMPAIGN_WALKTHROUGH.md) explains navigation and recovery.
[Human review](HUMAN_REVIEW_UI.md) and [SVM](RESPONSE_SVM.md) describe their
protocols and advanced routes. The [runbook](../experiments/RUN_AND_RETURN.md)
contains CLI procedures, not additional mandatory UI preparation tasks.
[Earlier audit results](OPERATOR_REGRESSION_AUDIT.md) are dated evidence.
