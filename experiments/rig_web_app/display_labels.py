"""Display names for application enums; persisted values remain unchanged.

Unknown values are returned verbatim, never guessed or rewritten as prose.
This is not a translator for prompts, answers, model names or operator data.
"""

import json

from .i18n import text as _ui_text

LABELS = {
    "absent": _ui_text("labels.absent"),
    "ambiguous": _ui_text("labels.ambiguous"),
    "busy": _ui_text("labels.busy"),
    "external": _ui_text("labels.external"),
    "owned": _ui_text("labels.owned"),
    "preparation": _ui_text("labels.preparation"),
    "collection": _ui_text("labels.collection"),
    "analysis": _ui_text("labels.analysis"),
    "budget": _ui_text("labels.budget"),
    "abstained": _ui_text("labels.abstained"),
    "associated_execution_unit_error": _ui_text("labels.associated_execution_unit_error"),
    "attempted": _ui_text("labels.attempted"),
    "attested": _ui_text("labels.attested"),
    "blocked_or_unresolved": _ui_text("labels.blocked_or_unresolved"),
    "completed": _ui_text("labels.completed"),
    "decided": _ui_text("labels.decided"),
    "error": _ui_text("labels.error"),
    "evaluable": _ui_text("labels.evaluable"),
    "execution_eligible": _ui_text("labels.execution_eligible"),
    "idle": _ui_text("labels.idle"),
    "included": _ui_text("labels.included"),
    "missing": _ui_text("labels.missing"),
    "missing_responses": _ui_text("labels.missing_responses"),
    "non_evaluable": _ui_text("labels.non_evaluable"),
    "orphaned": _ui_text("labels.orphaned"),
    "partial": _ui_text("labels.partial"),
    "passed": _ui_text("labels.passed"),
    "requested": _ui_text("labels.requested"),
    "scientifically_compatible": _ui_text("labels.scientifically_compatible"),
    "structural_not_applicable": _ui_text("labels.structural_not_applicable"),
    "unknown": _ui_text("labels.unknown"),
    "with_abstained_support": _ui_text("labels.with_abstained_support"),
    "with_decided_support": _ui_text("labels.with_decided_support"),
    "with_missing_response_support": _ui_text("labels.with_missing_response_support"),
    "input": _ui_text("labels.input"),
    "output": _ui_text("labels.output"),
    "cache_read": _ui_text("labels.cache_read"),
    "cache_write": _ui_text("labels.cache_write"),
    "reasoning": _ui_text("labels.reasoning"),
    "dry_run": _ui_text("labels.dry_run"),
    "attestation_probe": _ui_text("labels.attestation_probe"),
    "diagnostic_canary": _ui_text("labels.diagnostic_canary"),
    "measured": _ui_text("labels.measured"),
    "prompt": _ui_text("labels.prompt"),
    "response": _ui_text("labels.response"),
    "prompt_response": _ui_text("labels.prompt_response"),
    "group_holdout": _ui_text("labels.group_holdout"),
    "unseen_model": _ui_text("labels.unseen_model"),
    "unseen_corpus": _ui_text("labels.unseen_corpus"),
    "harmful_compliance": _ui_text("labels.harmful_compliance"),
    "judge_disagreement": _ui_text("labels.judge_disagreement"),
    "insufficient_class_group_support": _ui_text("labels.insufficient_class_group_support"),
    "evaluated": _ui_text("labels.evaluated"),
    "fitting": _ui_text("labels.fitting"),
    "collection_job": _ui_text("labels.collection_job"),
    "local_preparation": _ui_text("labels.local_preparation"),
    "local_execution": _ui_text("labels.local_execution"),
    "haiku_preparation": _ui_text("labels.haiku_preparation"),
    "haiku_execution": _ui_text("labels.haiku_execution"),
    "already_judged": _ui_text("labels.already_judged"),
    "source_specific_metric": _ui_text("labels.source_specific_metric"),
    "outside_requested_limit": _ui_text("labels.outside_requested_limit"),
    "original_local_cascade_unavailable": _ui_text("labels.original_local_cascade_unavailable"),
    "generation_context_unavailable": _ui_text("labels.generation_context_unavailable"),
    "eligible_usable_outputs": _ui_text("labels.eligible_usable_outputs"),
    "excluded_missing_outputs": _ui_text("labels.excluded_missing_outputs"),
    "excluded_source_authoritative_rows": _ui_text("labels.excluded_source_authoritative_rows"),
    "excluded_diagnostic_outputs": _ui_text("labels.excluded_diagnostic_outputs"),
    "unprepared_outputs": _ui_text("labels.unprepared_outputs"),
    "t3cap_limit": _ui_text("labels.t3cap_limit"),
    "t3cap_sample_seed": _ui_text("labels.t3cap_sample_seed"),
    "hcap_limit": _ui_text("labels.hcap_limit"),
    "hcap_sample_seed": _ui_text("labels.hcap_sample_seed"),
    "hcap_cases": _ui_text("labels.hcap_cases"),
    "candidate_outputs": _ui_text("labels.candidate_outputs"),
    "selected_outputs": _ui_text("labels.selected_outputs"),
    "excluded_outputs": _ui_text("labels.excluded_outputs"),
    "usable_outputs": _ui_text("labels.usable_outputs"),
    "missing_outputs": _ui_text("labels.missing_outputs"),
    "safe_rate": _ui_text("labels.safe_rate"),
    "violation_rate": _ui_text("labels.violation_rate"),
    "refusal_rate": _ui_text("labels.refusal_rate"),
    "over_refusal_rate": _ui_text("labels.over_refusal_rate"),
    "terminal_rows": _ui_text("labels.terminal_rows"),
    "target_calls": _ui_text("labels.target_calls"),
    "judge_calls": _ui_text("labels.judge_calls"),
    "http_attempts": _ui_text("labels.http_attempts"),
    "planning_strata": _ui_text("labels.planning_strata"),
    "execution_units": _ui_text("labels.execution_units"),
    "judgments_completed": _ui_text("labels.judgments_completed"),
    "judgments_decided": _ui_text("labels.judgments_decided"),
    "judgments_abstained": _ui_text("labels.judgments_abstained"),
    "request_errors": _ui_text("labels.request_errors"),
    "requests": _ui_text("labels.requests"),
    "intended_requests": _ui_text("labels.intended_requests"),
    "attempted_requests": _ui_text("labels.attempted_requests"),
    "target_generations": _ui_text("labels.target_generations"),
    "judge_generations": _ui_text("labels.judge_generations"),
    "queued": _ui_text("labels.queued"),
    "starting": _ui_text("labels.starting"),
    "running": _ui_text("labels.running"),
    "succeeded": _ui_text("labels.succeeded"),
    "failed": _ui_text("labels.failed"),
    "stopped": _ui_text("labels.stopped"),
    "cancelled": _ui_text("labels.cancelled"),
    "interrupted": _ui_text("labels.interrupted"),
    "retry_wait": _ui_text("labels.retry_wait"),
    "retry_waiting": _ui_text("labels.retry_waiting"),
    "downloading": _ui_text("labels.downloading"),
    "blocked": _ui_text("labels.blocked"),
    "complete": _ui_text("labels.complete"),
    "install": _ui_text("labels.install"),
    "verify": _ui_text("labels.verify"),
    "repair": _ui_text("labels.repair"),
    "resume": _ui_text("labels.resume"),
    "ready": _ui_text("labels.ready"),
    "preparing": _ui_text("labels.preparing"),
    "campaigns": _ui_text("labels.campaigns"),
    "cascade": _ui_text("labels.cascade"),
    "required_ratings": _ui_text("labels.required_ratings"),
    "paired": _ui_text("labels.paired"),
    "left": _ui_text("labels.left"),
    "right": _ui_text("labels.right"),
    "jobs": _ui_text("labels.jobs"),
    "stats": _ui_text("labels.stats"),
    "overview": _ui_text("labels.overview"),
    "definition": _ui_text("labels.definition"),
    "activity": _ui_text("labels.activity"),
    "results": _ui_text("labels.results"),
    "judging": _ui_text("labels.judging"),
    "costs": _ui_text("labels.costs"),
    "compare": _ui_text("labels.compare"),
    "corpus": _ui_text("labels.corpus"),
    "framework": _ui_text("labels.framework"),
    "modality": _ui_text("labels.modality"),
    "text": _ui_text("labels.text"),
    "image": _ui_text("labels.image"),
    "audio": _ui_text("labels.audio"),
    "video": _ui_text("labels.video"),
    "tool": _ui_text("labels.tool"),
    "local": _ui_text("labels.local"),
    "hosted": _ui_text("labels.hosted"),
    "haiku": _ui_text("labels.haiku"),
    "rules": _ui_text("labels.rules"),
    "llm": _ui_text("labels.llm"),
    "guardrail": _ui_text("labels.guardrail"),
    "label": _ui_text("labels.label"),
    "refusal_label": _ui_text("labels.refusal_label"),
    "harmfulness_label": _ui_text("labels.harmfulness_label"),
    "convincingness_label": _ui_text("labels.convincingness_label"),
    "specificity_label": _ui_text("labels.specificity_label"),
    "task_label": _ui_text("labels.task_label"),
    "parse_status_label": _ui_text("labels.parse_status_label"),
    "safe": _ui_text("labels.safe"),
    "unsafe": _ui_text("labels.unsafe"),
    "violation": _ui_text("labels.violation"),
    "refusal": _ui_text("labels.refusal"),
    "over_refusal": _ui_text("labels.over_refusal"),
    "not_refusal": _ui_text("labels.not_refusal"),
    "uncertain": _ui_text("labels.uncertain"),
    "harmful": _ui_text("labels.harmful"),
    "not_harmful": _ui_text("labels.not_harmful"),
    "convincing": _ui_text("labels.convincing"),
    "not_convincing": _ui_text("labels.not_convincing"),
    "not_applicable": _ui_text("labels.not_applicable"),
    "specific_actionable": _ui_text("labels.specific_actionable"),
    "general_non_actionable": _ui_text("labels.general_non_actionable"),
    "yes": _ui_text("labels.yes"),
    "no": _ui_text("labels.no"),
    "clean_single_label": _ui_text("labels.clean_single_label"),
    "ambiguous_or_multiple": _ui_text("labels.ambiguous_or_multiple"),
    "no_label_line": _ui_text("labels.no_label_line"),
    "common": _ui_text("labels.common"),
    "source_task": _ui_text("labels.source_task"),
    "draft": _ui_text("labels.draft"),
    "pending": _ui_text("labels.pending"),
    "submitted": _ui_text("labels.submitted"),
    "unstarted": _ui_text("labels.unstarted"),
    "deferred": _ui_text("labels.deferred"),
    "outputs": _ui_text("labels.outputs"),
    "assignments": _ui_text("labels.assignments"),
    "disagreements": _ui_text("labels.disagreements"),
    "adjudicated": _ui_text("labels.adjudicated"),
    "raters": _ui_text("labels.raters"),
}


def label(value):
    if isinstance(value, str):
        prefix, separator, subject = value.partition(":")
        if separator and prefix in {"unseen_model", "unseen_corpus"}:
            return _ui_text("labels.protocol_subject", protocol=LABELS[prefix], subject=subject)
    return LABELS.get(value, value)


def data_label(value):
    """Format imported cohort tags as data, without cataloguing campaign policy."""
    return " ".join(str(value).split("_"))


def script():
    encoded = (
        json.dumps(LABELS, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    missing = json.dumps(_ui_text("language.missing_message_value"), ensure_ascii=True).replace(
        "<", "\\u003c"
    )
    return (
        "<script>window.uraLabel=(value)=>Object.prototype.hasOwnProperty.call(window.uraLabels,value)?window.uraLabels[value]:value;window.uraLabels="
        + encoded
        + ";window.uraFormat=(message,values)=>message.replace(/\\{([a-zA-Z_][a-zA-Z_0-9]*)\\}/g,(match,key)=>{"
        "if(!Object.prototype.hasOwnProperty.call(values,key))throw new Error("
        + missing
        + "+key);return String(values[key]);});</script>"
    )
