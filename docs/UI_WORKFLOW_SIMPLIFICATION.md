# Operator workflows

Status: implementation in progress. This document specifies acceptance, not
claims about functionality already deployed.

Operators choose experimental inputs, models, sampling, evaluation and resource
limits. They must not coordinate internal planning, acquisition, conversion,
receipt creation or publication jobs. Those jobs remain inspectable as technical
details, never as required navigation.

The ordinary sequence is configure, automatic preparation, review the resulting
workload, and start. One progress page follows preparation across child jobs.
Errors stop progression and identify the affected choice; stop prevents further
handoffs. Reopening or refreshing must not duplicate work. Preparation must not
silently make target or judge calls. Any necessary diagnostic generations belong
in the reviewed execution workload, not an undisclosed preparation step.

## Coverage and acceptance

| Flow | Operator decisions | Internal work to automate |
| --- | --- | --- |
| Direct campaign or single run | Models, arms, attacks, sample, judges, limits | Plan, reuse/acquire installed models, no-call check, final execution preparation |
| Hosted comparison on retained inputs | Source runs, target models, request/token/cost limits | Input extraction, forecast, replay materialization, token counting and execution preparation |
| Local retained-output judging | Saved outputs and scoring condition | Discover unjudged outputs, prepare scorer, resume and publish verdicts |
| Hosted retained-output judging | Same-input selection, judge, spending limit | Inventory, exact-output matching, counting, execution preparation and publication |
| Personal review | Saved outputs, rubric, optional sample | Sample preparation and opening the evaluation form |
| Independent study | Actual participant and study arrangements | Artifact creation and assignment bookkeeping, not invented ethical or scientific decisions |
| SVM analysis | Cohort, target task, feature set and scientific analysis settings | Dataset export, file handoffs, evaluation/package/prediction stages appropriate to the chosen task |
| Recovery | Which interrupted operation to continue; any changed limit | Restore successful checkpoints and run only unfinished internal work |

Advanced CLI forms remain available for debugging and exceptional imports.
Normal flows use named saved objects and system-derived paths. They do not ask
for database filenames, receipt hashes, campaign IDs or intermediate output
directories.

Use the existing job launcher and stage implementations. Do not introduce a
second experiment engine or weaken selection, accounting, budget or admission
semantics. Validate on the rig, including restart, duplicate submissions, stop,
failed-child handling and the absence of target/judge calls during preparation.
Update both small-campaign walkthroughs and the Guide only against verified
behavior. A long document is not a substitute for removing operator handoffs.
