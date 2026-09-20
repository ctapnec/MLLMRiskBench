"""Readable judging settings, indexed at publication rather than page load."""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import html
import json


def local_settings(*, run=None, source=None, revision=None):
    run, source = run or {}, source or {}
    cascade = source.get("judge_cascade") or {}
    stages = []
    for stage in cascade.get("stages", []):
        stages.append(
            {
                key: stage[key]
                for key in ("name", "model_id", "revision", "max_new_tokens", "escalate_below")
                if stage.get(key) is not None
            }
        )
    if not stages:
        for name in run.get("judge_names") or []:
            stage = dict(name=name)
            model = (
                run.get("guardrail_model" if name == "guardrail" else "judge_model")
                if name != "rules"
                else None
            )
            if model:
                stage["model_id"] = model
            if name == "guardrail" and run.get("guardrail_revision"):
                stage["revision"] = run["guardrail_revision"]
            stages.append(stage)
    result = dict(
        stages=stages,
        approximate_common_metrics=source.get(
            "approximate_common_metrics", run.get("approximate_common_metrics")
        ),
    )
    if revision:
        result["scoring_revision"] = revision
    return result


def indexed_settings(db, campaign):
    rows = db._query(
        "SELECT judge_id,settings FROM campaign_judge_settings WHERE campaign_id=?", (campaign,)
    )
    return {row["judge_id"]: json.loads(row["settings"]) for row in rows or []}


def judge_name(identity, settings=None):
    display = (settings or {}).get("display_name")
    if isinstance(display, str) and display.strip():
        return display
    if not identity.startswith("local-cascade-"):
        name, _, suffix = identity.rpartition(":")
        return (
            name if len(suffix) == 24 and all(c in "0123456789abcdef" for c in suffix) else identity
        )
    if not settings or not settings.get("stages"):
        return _ui_text("workspace_judge_settings.local_judge_settings_not_indexed")
    stages = settings["stages"]
    names = []
    for stage in stages:
        name = stage.get("name", _ui_text("workspace_judge_settings.unknown_stage"))
        model = stage.get("model_id")
        names.append(
            _ui_text("workspace_judge_settings.rules")
            if name == "rules"
            else model.split("/")[-1]
            if model
            else _ui_label(name)
        )
    label = (
        _ui_text("workspace_judge_settings.rules_only")
        if len(stages) == 1 and stages[0].get("name") == "rules"
        else " + ".join(names)
    )
    mode = settings.get("approximate_common_metrics")
    return (
        label
        + _ui_text("workspace_judge_settings.approximate_metrics")
        + (
            "on"
            if mode is True
            else "off"
            if mode is False
            else _ui_text("workspace_judge_settings.not_recorded")
        )
    )


def settings_html(identity, settings, *, side):
    """Always-visible description after selection; technical provenance stays folded."""
    label = judge_name(identity, settings)
    text = "<p>" + html.escape(label) + ".</p>"
    if (settings or {}).get("assessment_method") == "conversation_based_ai_review":
        text += _ui_template(
            "<p>[[text:workspace_judge_settings.conversation_based_ai_assessment_not_human_evaluation_or_a_fixed]]</p>"
        )
    if identity.startswith("local-cascade-"):
        stages = (settings or {}).get("stages", [])
        if stages and all(stage.get("name") == "rules" for stage in stages):
            text += _ui_template(
                "<p>[[text:workspace_judge_settings.no_model_backed_judge_is_used_in_this_condition]]</p>"
            )
        elif not stages:
            text += _ui_template(
                "<p>[[text:workspace_judge_settings.the_retained_configuration_has_not_been_indexed_no_settings_are_i]]</p>"
            )
        for stage in stages:
            details = []
            if stage.get("model_id"):
                details.append(_ui_text("workspace_judge_settings.model") + stage["model_id"])
            if stage.get("max_new_tokens") is not None:
                details.append(
                    _ui_text("workspace_judge_settings.output_allowance")
                    + str(stage["max_new_tokens"])
                    + _ui_text("workspace_judge_settings.tokens")
                )
            if stage.get("escalate_below") is not None:
                details.append(
                    _ui_text("workspace_judge_settings.escalate_below_confidence")
                    + str(stage["escalate_below"])
                )
            if details:
                text += "<p>" + html.escape("; ".join(details)) + ".</p>"
    text += _ui_template(
        "<p>[[text:workspace_judge_settings.distinct_judging_conditions_are_kept_separate_matching_names_do_n]]</p>"
    )
    text += (
        _ui_template(
            "<details><summary>[[text:workspace_judge_settings.exact_judging_identity]]</summary><p>"
        )
        + html.escape(identity)
        + "</p>"
    )
    for stage in (settings or {}).get("stages", []):
        if stage.get("revision"):
            text += (
                _ui_template("<p>[[text:workspace_judge_settings.model_revision]] ")
                + html.escape(stage["revision"])
                + "</p>"
            )
    if (settings or {}).get("scoring_revision"):
        text += (
            _ui_template("<p>[[text:workspace_judge_settings.scoring_revision]] ")
            + html.escape(settings["scoring_revision"])
            + "</p>"
        )
    return (
        "<section class='card' data-judge-settings='"
        + side
        + _ui_template(
            "' style='margin-top:1rem;overflow-wrap:anywhere'><h4>[[text:workspace_judge_settings.selected_judging_settings]]</h4>"
        )
        + text
        + "</details></section>"
    )
