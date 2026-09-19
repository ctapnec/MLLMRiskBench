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

| Workflow | Required checks | Current audit state |
| --- | --- | --- |
| Direct local campaign and single run | Automatic preparation, one start, stop/restart, retained scope | Re-audit pending |
| Direct hosted campaign | Real route, bounded calls, failure classification, usage | Live acceptance pending |
| Matched hosted campaign | Same inputs, automatic handoffs, no repeated paid work | Re-audit pending |
| Saved-output judging | Output-specific labels, duplicate preparations, interrupted execution | Re-audit pending |
| Jobs | Substantive work separated from technical stages, truthful state, recovery | Revision pending |
| Stats comparisons | Selected campaigns/jobs, denominators, conditions, exports | Revision pending |
| SVM in Stats | Existing and new studies, held-out scores, baselines, class/group support, intervals | Implementation in progress |
| Human review and Guide | Evaluation form, return navigation, no lost state, accurate links | Re-audit pending |
| Common UI | Busy state, errors, stop handling, desktop/mobile, spacing | Re-audit pending |
| Performance | No repeated reconstruction/hashing, bounded readers, no unused workers | Re-audit pending |

Track findings and evidence in the thesis project's development ledger. Thesis
chapters describe methods and findings academically, not audit chronology.
