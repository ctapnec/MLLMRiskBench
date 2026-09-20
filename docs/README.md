# Documentation map

## Operator guides

- [First small campaign](SMALL_CAMPAIGNS.md): the detailed local/API workflow,
  including fresh or saved inputs, recovery, comparison charts, human review
  and SVM analysis.
- [Campaign walkthrough](UI_CAMPAIGN_WALKTHROUGH.md): navigation, campaign/run
  ownership, continuation and the optional Guide. This overview complements
  the detailed steps rather than maintaining another campaign recipe.
- [Human review](HUMAN_REVIEW_UI.md): personal and independent assessment
  protocols, qualifications, exports and advanced CLI use.
- [Response SVM](RESPONSE_SVM.md): classifier study design, execution,
  limitations and reuse of fitted models.
- [Conversational AI review](CONVERSATIONAL_AI_REVIEW.md): recording and
  publishing output-specific AI assessments separately from human ratings.

## Installation and administration

- [Installation](../distro/README.md): environments, managed runtimes and services.
- [Workstation archive](WORKSTATION_ARCHIVE.md): the local read-only console,
  retained-data locations, start/stop and recovery.
- [Run and return](../experiments/RUN_AND_RETURN.md): CLI procedures and campaign
  recipes. Dated recipes are not additional preparation tasks in the current UI.
- [Source conformance](SOURCE_CONFORMANCE.md): source admission, semantic review
  and receipt maintenance.
- [Native engine imports](NATIVE_ENGINE_IMPORTS.md): framework-specific import
  requirements and examples.

## Developer and analysis references

| Reference | Authoritative scope |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Components, dependencies and execution boundaries |
| [Schema](SCHEMA.md) | Records, configuration fields and compatibility contracts |
| [Metrics](METRICS.md) | Measures, denominators, eligibility and statistical analysis |
| [Campaign workspaces](CAMPAIGN_WORKSPACES.md) | Ownership, automated workflows, publication, recovery, budgets and comparison behavior |
| [UI flow acceptance](UI_FLOW_ACCEPTANCE.md) | Reusable scenario matrix, fault testing and documentation regression |
| [UI language](UI_LANGUAGE.md) | Catalogs, templates, escaping and localization checks |
| [Attack tags](ATTACK_TAGS.md) | Attack-mechanism vocabulary, distinct from risk taxonomy |
| [Synthetic compatibility](SYNTHETIC_COMPAT.md) | Experimental compatibility-rule tooling, distinct from response SVMs |

## Maintaining documentation

Keep each technical rule in its authoritative reference and link to it from
overviews. Operator steps belong in the small-campaign guide; internal record
fields and troubleshooting commands remain in developer/admin references.
Update the Guide, links and relevant tests when a visible action changes.

Before consolidating a document, preserve unique instructions, examples,
observed results and their qualifications. Dated acceptance records are not
current guarantees or renewed spending allowances. Move completed plans and
historical records to the archive instead of mixing them with current steps.
The [documentation regression requirements](UI_FLOW_ACCEPTANCE.md#documentation-maintenance-and-regression)
cover links, section numbering, content preservation and actual workflow checks.

## Historical records

The [archive index](archive/README.md) contains earlier manuals, completed
consolidation plans, acceptance records and study-specific observations. These
are retained for traceability, not alternative current instructions. The old
small-guide entry filenames remain short redirects for existing links.
