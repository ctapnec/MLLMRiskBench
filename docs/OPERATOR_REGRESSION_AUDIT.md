# Operator regression audit

## Scope and execution policy

The current audit covers complete operator workflows, backend execution,
restart and stop behavior, scientific accounting, performance and presentation.
Fix identified medium/high issues before declaring a tested workflow accepted.
Repeat affected real-world scenarios after each fix; a passing suite is not a
claim that every possible workflow is defect-free.

Tests run on the GPU rig, using installed environments. No default model-file
rehashing, framework reinstall or repeated full campaign is required. Synthetic
fault injection supplements real retained data and browser acceptance. Paid
Anthropic acceptance calls have a total additional ceiling of USD 5, not USD 5
per case. Record actual calls and charges; do not consume the allowance merely
to exhaust it. Verification artifacts stay outside version control.

## Acceptance matrix

This matrix began before the unified campaign flow. The subsequent real local,
fresh hosted and matched hosted acceptance is recorded in RA-756 and RA-757
of the development ledger. The broader 19 September re-audit began with a
complete rig suite that produced 5,251 passes, 136 failures and 10 skips.
Do not treat earlier focused acceptance as a clean result for that suite.
Failures and corrected reruns are retained separately; production campaigns
are not rerun to repair test fixtures.

Subsequent affected-file passes reduced failures to 67, then 11, then zero
(527 selected tests at the last of these passes). The second complete sweep
produced 5,396 passes, two failures and 10 skips. Both remaining failures were
test defects: the document numbering parser counted its section heading as an
action, and the raw Tools required-field count included a hidden internal
controller. A subsequent 41-test affected-file pass resolved both and checked
the corrected positive and negative cases. The failed sweep is preserved as
failed, not relabelled as one all-green full run. The skipped cases require
Windows job objects or junctions; they were not executed on Windows.

Test corrections retain the original boundaries: actual readiness
profiles precede local execution, paid answer retries remain zero, missing
database identity prevents an orphaned launch, and abstentions do not enter a
decision-rate denominator. The historical analysis self-test accepts a copied
unchanged configuration while retaining changed-content rejection.

| Workflow | Required checks | Current audit state |
| --- | --- | --- |
| Direct local campaign and single run | Automatic preparation, one start, stop/restart, retained scope | Rig suite reconciled; preceding live acceptance retained; Build visibility follow-up described below |
| Direct hosted campaign | Real route, bounded calls, failure classification, usage | Rig regressions passed; preceding fresh-input live acceptance retained |
| Matched hosted campaign | Same inputs, automatic handoffs, no repeated paid work | Rig regressions passed; preceding retained-input live acceptance retained |
| Saved-output judging | Output-specific labels, duplicate submissions, interrupted execution | Assessment and recovery regressions passed; raw internal controller no longer exposed |
| Jobs | Substantive work separated from technical stages, truthful state, recovery | Recovery, liveness, database failure and work/technical view regressions passed |
| Stats comparisons | Selected campaigns/jobs, denominators, conditions, exports | Scoped comparison and export regressions passed; both selector scopes inspected in production |
| SVM in Stats | Existing and new studies, held-out scores, baselines, class/group support, intervals | Rig regressions, real-data and deployed desktop/mobile acceptance passed |
| Human review and Guide | Evaluation form, return navigation, no lost state, accurate links | Synthetic workflow regressions and read-only production navigation passed; no research ratings fabricated |
| Common UI | Busy state, errors, stop handling, desktop/mobile, spacing | Desktop/mobile regressions and production sweep passed; visual visibility finding retained below |
| Performance | No repeated reconstruction/hashing, bounded readers, no unused workers | Cache and bounded-reader regressions passed; installed environments reused without model-file scans |

Track findings and evidence in the thesis project's development ledger. Thesis
chapters describe methods and findings academically, not audit chronology.

## Documentation preservation

The maintained [small-campaign guide](SMALL_CAMPAIGNS.md) contains both input
routes and the full optional analysis steps. The
[preservation map](DOCUMENTATION_MAINTENANCE.md) records where the earlier
sections moved. Historical workspace and walkthrough records are retained in
full, not silently replaced by shorter current instructions.

The rig document checks cover links, section anchors, numbering, redirects,
retained actions, reference results and qualifications. Deliberate removal of
seven required passages, one section link and one numbered-step correction is
detected. The current 13 document checks also cover the full numbered comparison,
human-review and SVM sections. These are supplemented by section-by-section
semantic comparison and browser regression. Exact comparison with the earlier
committed documents established that all 1,845 lines of the historical workspace
and walkthrough bodies were preserved. Automated phrase matching alone does not
establish completeness or usability.

The Jobs/Stats pass ran 122 focused regressions and eight detecting reversals.
Real-data Chromium acceptance inspected 7,541 retained answers in 397 SVM input
groups, filtering, CSV export, campaign-comparison navigation and Jobs at
desktop/mobile widths. This pass made no target or judge calls and did not
consume the additional acceptance allowance.

Production acceptance preserved existing campaign drafts, jobs, responses and
judgments. The retained mixed local/hosted classifier study is visible under
both campaigns. No production write request or model call was made by acceptance.

The post-deployment sweep checked 42 pages across desktop and mobile sizes,
including both historical campaigns, the saved Qwen draft, Jobs, Tools, Compare,
SVM and human evaluation. It found no JavaScript errors, horizontal page overflow
or stuck busy overlay. Database counts and saved draft values were unchanged:
seven campaigns, 154 jobs, 268 campaign memberships, five drafts, 66,398 responses
and 88,047 judgments. These checks do not establish that all possible UI states
are correct: subsequent screenshot inspection identified a hidden Save campaign
button made visible by shared button styling. The shared hidden-state correction
passed the remaining 104 selected browser/layout checks. Its new test initially
misstated which tabs carry the campaign action; the corrected 20-test affected
pass succeeded, and reversing the styling fix fails both desktop and mobile
cases. Console 7f63edd then passed another 42-page production sweep, including
run/campaign/run switching across Build tabs. The screenshots were inspected,
not just checked for page-load success.

There are no unresolved medium/high findings from these exercised scenarios.
This is a bounded acceptance statement, not a claim of universal correctness.

Audit records remain outside Git under runs/engineering/campaign-reaudit-20260919.
Keep initial failures and corrected results together. Do not add these operational
records to the thesis narrative or report repeated regression totals as unique
tests. No original campaign was rerun and no paid calls were made in this re-audit.

## Fresh guide acceptance, 19 September

A new complete offline rig suite passed 5,401 tests with ten platform-specific
skips at fa22774. This is a new successful run, not a relabelling of the earlier
failed sweeps. Installed environments and Chromium were reused.

The shared guide was then followed through the production browser, creating
three clearly named QA campaigns without modifying the thesis populations:

| Route | Measured usable answers | Diagnostics | Local verdicts | Haiku verdicts |
| --- | ---: | ---: | ---: | ---: |
| Installed Qwen, fresh text and image corpora | 4 | 2 | 4 | 4 |
| Hosted Haiku, fresh text corpus | 1 | 1 | 1 | 1 |
| Hosted Haiku, saved local inputs | 1 image | 3 | 1 | 1 |

All six measured answers are untruncated. The last route shows why the reviewed
total must distinguish measured and diagnostic requests: four saved source
answers do not imply four measured follow-on answers, or both measured modalities.
Local and Haiku judgments remain separate and output-specific. Twelve physical
Anthropic attempts have USD 0.011471 in monetary ledgers and an additional
USD 0.002553 token-based estimate for two direct target calls without monetary
ledgers. The combined USD 0.014024 estimate is not an invoice reconciliation or
current provider balance. It is within the existing USD 5 total acceptance cap.

This pass adds per-condition paired-judgment matrices and job-outcome bars to the
existing input-overlap donuts. Their denominators are explicit. Truncation is
not counted twice, invalid judgments remain excluded from the matrix but visible
in its coverage and table, and conditions are never pooled. Rig regressions and
four fix reversals cover these additions. Production desktop/mobile checks
compare chart counts with CSV exports and exercise existing SVM results without
training an unsupported classifier on the tiny QA sample.

Actual human-review preparation revealed gaps that synthetic form tests missed:
internal successful diagnostics appeared as completed review sources; the launch
used an older Runner reader; finalized checkpoints were incorrectly required
again while finding sibling media manifests; and configured image-source
locations were omitted from the review child's environment. The fixes retain
the measured Runner, dispatch review from the console's analysis release, read
exact retained output identities, and pass configured media locators without
provider credentials. Regression now launches a real analysis child against
an incompatible older Runner fixture and finalized response files. No target
generation, provider call or human rating is needed for that regression.

The live personal-review export also exposed a stuck navigation spinner after
the CSV arrived. Both personal and independent-rating links now use the shared
guarded export handler. Browser regression covers successful download, an HTTP
503, release of the busy state and retry on desktop and mobile. No failed
preparation is relabelled as successful; corrected preparations remain separate.

The final deployed console passed 72 read-only desktop/mobile page checks,
including both historical campaigns and all three new QA campaigns. The new
matched image pair and historical text/image matrices agree with their CSV
exports. Real personal review loads its assigned image, retains the main header,
and exports without a stuck spinner. No production human ratings were submitted.
The final affected export/browser pass passed 59 tests; removing the handler
fails both desktop and mobile cases. Re-preparing Haiku assessment selected zero
answers and skipped all four existing valid local-answer verdicts, without
generation or paid judging. No unresolved medium/high finding remains in these
exercised scenarios; this does not establish universal correctness.

Evidence and initial failures remain under
`runs/engineering/guide-live-regression-20260919`, outside Git. The focused
follow-ups supplement the complete suite; their overlapping totals are not
additional unique test counts. These QA outputs are not thesis experimental
results. Stop/interruption and independent-rater submission are exercised with
isolated fixtures, not by interrupting paid production calls or fabricating
research ratings.

## Completed-work boundary follow-up

The subsequent actual Build submission exposed a gap that replaying frozen
operation parameters did not cover. Automatic connection discovery and output
attempt numbering created another preparation for an unchanged completed
campaign. Reopening now retains the completed work; explicit choices and
configured generation settings remain significant. Historical duplicate
preparations cannot take precedence merely because filesystem restoration
loads them first. A new forecast date does not repeat completed saved-input
work, while unstarted work still requires a current forecast.

The existing boundary pass passed 203 tests; the clean-release affected pass
passed 217. Follow-ups cover actual submission, restore order, changed local
and hosted output allowances, saved-input settings and date rollover, with
detecting fix reversals. The final affected/document pass passed 68 tests.
These overlapping totals are not a count of unique tests.

Actual desktop/mobile submissions reopened all three completed QA campaigns
without new jobs or calls. All four saved review items and both assigned images
loaded; no human ratings were submitted. Another 72-page production sweep
passed, including matched-input charts, per-job outcome bars, scoped CSV
exports and SVM task filtering. The observed maximum page time was 0.88 seconds,
not a general latency guarantee. No medium/high issue remains open in these
exercised scenarios. No new paid call, model generation, runtime installation
or model-weight scan was required. The initial five technical preparation jobs
remain separate evidence; original campaign answers and judgments are unchanged.
Evidence: `runs/engineering/boundary-regression-20260919`, outside Git.
