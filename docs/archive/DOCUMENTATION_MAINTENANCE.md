# Historical record: campaign documentation consolidation

This map preserves the earlier guide consolidation. Current maintenance rules
are in the [documentation index](../README.md#maintaining-documentation) and
[UI flow checklist](../UI_FLOW_ACCEPTANCE.md).

<!-- BEGIN PRESERVED DOCUMENT -->

# Campaign documentation consolidation and regression

SMALL_CAMPAIGNS.md is the maintained operator guide for both local and hosted
campaigns. A common workflow is not permission to delete route-specific actions,
reference outcomes, analysis instructions or scientific qualifications.
The former small-guide filenames remain short links to that guide.

## Section preservation map

| Previous content | Current location in SMALL_CAMPAIGNS.md |
| --- | --- |
| Local/API creation and model picker | 1, with separate model-choice rows |
| Local text/image modalities and two-arm selection | 2A, with exact values |
| Local admission and automatic output path | 3, steps 5-7 |
| Local sampling, retry count and wall-time settings | 2A and 3 |
| Hosted fresh corpora and frameworks | 2A |
| Hosted reuse of local inputs and whole-cluster cap | 2B |
| Evaluation, separate collection/Haiku limits and output allowance | 3 |
| Preparation, review, start and return navigation | 4-5 |
| Stop/resume, incomplete judging and historical continuation | 6 |
| Result columns, figures, token usage and exports | 7 and 8 |
| Fill missing saved-output judgments | 7, dedicated subsection with exact actions |
| Local reference result and diagnostic/timing/cost caveats | 7, Reference result, not a required outcome |
| Hosted follow-on from the new local demonstration | 7, dedicated optional continuation |
| Hosted text/image reference counts, validity and costs | 7, dated reference, not a new spending forecast |
| Active/failed jobs and expired transport evidence | If a step fails or is interrupted |
| Compare model/generation/judge selection | 8.1-8.4 |
| All models, all conditions and exploratory selection rules | 8.5 |
| Individual measured-job comparison | 8.6 |
| Personal evaluation, draft, deferral and export | 9.1 |
| Independent study setup, enrollment, ratings and adjudication | 9.2-9.5 |
| SVM local-only or matched source choice | 10.1 |
| SVM execution, resume, limitations and saved reports | 10.2 |
| Existing SVM Stats, baselines, intervals and exports | 10.3 |
| Trusted advanced classifier reuse | 10.4 |

The current workspace contract and overview remove obsolete operator commands
from their main narrative. Their full previous text remains in
[Historical workspace record](HISTORICAL_CAMPAIGN_WORKSPACES.md) and
[Historical walkthrough](HISTORICAL_UI_CAMPAIGN_WALKTHROUGH.md), including dated
numbers, technical qualifications and command examples.

## Regression requirements

1. Compare sections and operator actions against the previous documents. A link
   to an unrelated overview is not a replacement for a missing click sequence.
2. Preserve actual reference values and their qualifications. Do not turn an
   observed result, price or timing into a requirement for a new campaign.
3. Check relative links and anchors, heading numbering and old entry pages.
   Numbered click sequences must not restart partway through a subsection or
   skip a step; preserve the full comparison, human-review and SVM subsections.
4. Exercise the visible controls on the rig. Text matching cannot establish that
   an action works, a form submits the right values or a saved choice survives.
5. Test meaningful omissions by reversal: deleting a required reference/action
   or breaking a section link must fail the corresponding document regression.
6. Keep the Guide, README, runbook and developer contracts consistent about
   current action names. Explicit CLI recipes and historical procedures can
   retain their technical steps when clearly labelled as such.

The document checks are in tests/ura/test_operator_documentation.py. Link and
anchor coverage includes every current document in docs and distro, plus the
project README and CLI runbook; historical copies are explicitly separate.
Run them
on the rig alongside the relevant browser and backend regressions. Review prose
and preservation semantically as well; automated string/link checks are not a
proof that all documentation is complete or correct.

Keep acceptance claims scoped and dated. The active checklist belongs in
[UI flow acceptance](../UI_FLOW_ACCEPTANCE.md), while older regression results
remain a historical record. Provider balances must name their observation date;
an old balance is not a current allowance. General manuals must not declare a
campaign pending or complete without consulting its retained records.
