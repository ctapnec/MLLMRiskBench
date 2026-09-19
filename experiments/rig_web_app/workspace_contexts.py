"""References to one output's existing judgment under equivalent criteria.

These links are grouping metadata, never additional generations or verdicts.
"""

from __future__ import annotations

from .i18n import text as _ui_text

import hashlib
import json


def response_identity(response: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            response, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def native_context_reference(
    context: dict, response: dict, judgments: list[dict], *, expected_judge_ids: set[str]
) -> dict:
    """Join already established criterion equivalence to actual output owners.

    The caller supplies the explicit source-context comparison, not a heuristic
    about similar question text. Unavailable primary judgments remain pending.
    Multiple retained assessments stay separate; no favorable label is chosen.
    """
    identity = response["run_id"] + ":" + response["attempt_id"]
    if (
        context["same_native_judge_input"] is not True
        or context["response_id"] != identity
        or context["target"] != response["target"]
        or context["response_identity"] != response_identity(response)
    ):
        raise ValueError(
            _ui_text(
                "workspace_contexts.native_context_reference_changed_its_criteria_or_model_output"
            )
        )
    references = []
    for row in judgments:
        if (
            row["response_id"] != identity
            or row["judge_id"] not in expected_judge_ids
            or row["status"] not in {"valid", "invalid", "missing"}
            or not isinstance(row["source_ref"], str)
            or not row["source_ref"]
        ):
            raise ValueError(
                _ui_text(
                    "workspace_contexts.native_context_reference_changed_its_judgment_owner_or_condition"
                )
            )
        if row["status"] != "valid" and row.get("label") is not None:
            raise ValueError(
                _ui_text("workspace_contexts.an_unscored_context_cannot_acquire_a_valid_label")
            )
        if row["status"] == "valid" and not row.get("label"):
            raise ValueError(
                _ui_text("workspace_contexts.a_valid_native_reference_needs_its_actual_label")
            )
        references.append(
            {
                key: row.get(key)
                for key in ("response_id", "judge_id", "status", "label", "source_ref")
            }
        )
    if len({row["judge_id"] for row in references}) != len(references):
        raise ValueError(_ui_text("workspace_contexts.repeated_native_judgment_reference"))
    return dict(
        context=context["context"],
        primary_input_id=context["input_id"],
        alias_input_ids=context["alias_input_ids"],
        target=context["target"],
        response_id=identity,
        criterion_source=context["criterion_source"],
        status="referenced" if references else "pending_primary_judgment",
        judgments=references,
        independent_generation=False,
        additional_judge_calls=0,
    )
