"""Canonical result-bundle schema and the deterministic compatibility oracle.

SYN-001: a *bundle* is one self-contained summary of one reported result
(identity, provenance, construct, unit, support, estimate).  A *comparison
case* proposes an operation over two bundles - a side-by-side table row, a
pooled rate, or a paired difference - and the deterministic oracle classifies
the proposal as ``compatible``, ``incompatible`` or ``abstain`` with explicit
reason codes.  The rules mechanize the maintained V.6/Section 7 no-pooling
contract and are authoritative: any learned model trained on these labels is
evaluated against them and never overrides them.

Scope: this is an engineering validator over *summaries of results*.  It
establishes nothing empirical about models, sources, judges or humans, and its
synthetic corpus (``ura.compat_synth``) proves rule fidelity only.  By
recorded operator decision (ledger Section 11.20) no real-world validity claim
is made for any learned component: SYN-003 was withdrawn, so such claims are
permanently out of scope.
"""

from __future__ import annotations

from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

COMPAT_BUNDLE_SCHEMA = "ura-compat-bundle/1"
COMPAT_CASE_SCHEMA = "ura-compat-case/1"

#: The one canonical claim boundary every output of this chain must carry
#: (recorded operator decision, ledger Section 11.20).
CLAIM_SCOPE = (
    "rule fidelity on synthetic distributions only; no real-world validity, "
    "benchmark generalization, model ranking or safety claim (SYN-003 "
    "withdrawn; ledger Section 11.20)"
)

#: The critical incompatibility reason codes (ledger Section 8.1).
REASON_POLICY = "policy_mismatch"
REASON_POPULATION = "harmful_benign_population_mismatch"
REASON_UNIT = "static_conversation_unit_mismatch"
REASON_HORIZON = "horizon_or_budget_mismatch"
REASON_NATIVE_PROXY = "native_common_proxy_mismatch"
REASON_IDENTITY = "source_or_run_identity_mismatch"
REASON_JUDGE = "judge_or_served_model_mismatch"
REASON_STRUCTURAL_NA = "structural_na_or_missing_pooled"
REASON_PROVENANCE = "missing_provenance"
REASON_POLARITY = "polarity_or_denominator_inconsistency"
REASON_IMPOSSIBLE = "impossible_support_interval_or_total"
REASON_MEDIA_EVALUATOR = "media_transport_evaluator_mismatch"

ALL_REASONS = (
    REASON_POLICY, REASON_POPULATION, REASON_UNIT, REASON_HORIZON,
    REASON_NATIVE_PROXY, REASON_IDENTITY, REASON_JUDGE, REASON_STRUCTURAL_NA,
    REASON_PROVENANCE, REASON_POLARITY, REASON_IMPOSSIBLE,
    REASON_MEDIA_EVALUATOR,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ResultBundle(_Strict):
    schema_name: Literal["ura-compat-bundle/1"] = Field(alias="schema")
    bundle_id: str
    requested_model: str
    resolved_model: str
    provider: str
    source: str
    source_policy_id: str
    source_policy_version: str
    source_policy_sha256: str | None = None
    modality: Literal["text", "image", "audio", "video", "tool"]
    delivery_mode: Literal["physical_bytes", "text_only"]
    evaluator_mode: Literal[
        "text_judges_over_text_response",
        "text_judges_with_source_reference_proxy",
        "response_only_text_judge_proxy",
        "source_specific_parser",
        "source_native_evaluator",
    ]
    attacker: str
    defense: str
    # strict=False so the JSON round-trip (list) and in-memory construction
    # (tuple) both validate; the value is normalized to a tuple either way.
    judge_order: tuple[str, ...] = Field(strict=False)
    execution_type: Literal[
        "static_replay", "live_conversation", "classification_replay",
        "native_campaign",
    ]
    run_id: str
    budget_horizon_turns: int | None = None
    metric_family: str
    metric_name: str
    endpoint_status: Literal["official", "native", "proxy"]
    population: Literal[
        "harmful_expected_refusal", "benign_expected_answer",
        "source_items", "native_episodes",
    ]
    unit: str
    denominator: str
    polarity: Literal["higher_adverse", "higher_favorable", "source_defined"]
    scale: str
    numerator: int | None = None
    support: int = Field(ge=0)
    decided: int | None = None
    abstained: int | None = None
    estimate: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    ci_method: str | None = None
    status: Literal["measured", "structural_na", "missing"]
    na_reason: str | None = None
    artifact_sha256: str | None = None
    config_sha256: str | None = None
    source_corpus_sha256: str | None = None

    @field_validator(
        "bundle_id", "requested_model", "resolved_model", "provider", "source",
        "source_policy_id", "source_policy_version", "attacker", "defense",
        "run_id", "metric_family", "metric_name", "unit", "denominator",
        "scale",
    )
    @classmethod
    def _nonblank(cls, value: str, info) -> str:
        if not value.strip():
            raise ValueError(f"bundle field {info.field_name} must be nonblank")
        return value

    def internal_defects(self) -> list[str]:
        """Per-bundle defects; a defective bundle is never admissible."""

        defects: set[str] = set()
        if self.status == "measured":
            if self.estimate is None:
                defects.add(REASON_IMPOSSIBLE)
            if self.numerator is not None and self.numerator > self.support:
                defects.add(REASON_IMPOSSIBLE)
            if self.decided is not None and self.abstained is not None:
                if self.decided + self.abstained > self.support:
                    defects.add(REASON_IMPOSSIBLE)
            if (self.ci_low is None) != (self.ci_high is None):
                defects.add(REASON_IMPOSSIBLE)
            if (
                self.ci_low is not None
                and self.ci_high is not None
                and self.estimate is not None
                and not (self.ci_low <= self.estimate <= self.ci_high)
            ):
                defects.add(REASON_IMPOSSIBLE)
            if self.support == 0:
                defects.add(REASON_IMPOSSIBLE)
            if self.artifact_sha256 is None or self.config_sha256 is None:
                defects.add(REASON_PROVENANCE)
        else:
            # A structural-N/A or missing cell carries no value: a number here
            # is exactly the silent-zero/imputation failure the rules forbid.
            if self.estimate is not None or self.numerator is not None:
                defects.add(REASON_STRUCTURAL_NA)
            if self.na_reason is None or not self.na_reason.strip():
                defects.add(REASON_PROVENANCE)
        return sorted(defects)


class ComparisonCase(_Strict):
    schema_name: Literal["ura-compat-case/1"] = Field(alias="schema")
    case_id: str
    proposed: Literal["side_by_side_row", "pooled_rate", "paired_difference"]
    left: ResultBundle
    right: ResultBundle


def _policy_axis(left: ResultBundle, right: ResultBundle) -> tuple[str | None, bool]:
    """Return (violation reason or None, unconfirmed-identity flag)."""

    if (
        left.source_policy_id != right.source_policy_id
        or left.source_policy_version != right.source_policy_version
    ):
        return REASON_POLICY, False
    if left.source_policy_sha256 is None or right.source_policy_sha256 is None:
        # Identity looks equal but cannot be confirmed byte-exactly; a
        # documented equivalence defense lives outside the bundles, so the
        # oracle abstains rather than guessing.
        return None, True
    if left.source_policy_sha256 != right.source_policy_sha256:
        return REASON_POLICY, False
    return None, False


def evaluate_comparison(case: ComparisonCase) -> dict[str, Any]:
    """Deterministically classify one proposed comparison."""

    left, right = case.left, case.right
    reasons: set[str] = set()
    abstain = False

    reasons.update(left.internal_defects())
    reasons.update(right.internal_defects())

    if case.proposed in {"pooled_rate", "paired_difference"}:
        if left.status != "measured" or right.status != "measured":
            reasons.add(REASON_STRUCTURAL_NA)
        policy_violation, policy_unconfirmed = _policy_axis(left, right)
        if policy_violation:
            reasons.add(policy_violation)
        abstain = abstain or policy_unconfirmed
        if left.population != right.population:
            reasons.add(REASON_POPULATION)
        if left.execution_type != right.execution_type:
            reasons.add(REASON_UNIT)
        if left.unit != right.unit:
            reasons.add(REASON_UNIT)
        if left.execution_type == right.execution_type:
            if left.execution_type == "live_conversation" and (
                left.budget_horizon_turns is None
                or right.budget_horizon_turns is None
            ):
                # A conversation endpoint without a declared horizon cannot be
                # admitted to a fixed-horizon comparison.
                reasons.add(REASON_PROVENANCE)
            elif left.budget_horizon_turns != right.budget_horizon_turns:
                # Any declared budget/horizon must match exactly, for every
                # execution type (native campaigns included).
                reasons.add(REASON_HORIZON)
        if left.endpoint_status != right.endpoint_status:
            reasons.add(REASON_NATIVE_PROXY)
        if (
            left.execution_type == "native_campaign"
            or right.execution_type == "native_campaign"
        ) and left.metric_name != right.metric_name:
            reasons.add(REASON_NATIVE_PROXY)
        if left.source != right.source:
            reasons.add(REASON_IDENTITY)
        if left.metric_family != right.metric_family:
            reasons.add(REASON_POLARITY)
        if (
            left.polarity != right.polarity
            or left.denominator != right.denominator
            or left.scale != right.scale
        ):
            reasons.add(REASON_POLARITY)
        if left.judge_order != right.judge_order:
            reasons.add(REASON_JUDGE)
        if (
            left.modality != right.modality
            or left.delivery_mode != right.delivery_mode
            or left.evaluator_mode != right.evaluator_mode
        ):
            reasons.add(REASON_MEDIA_EVALUATOR)
        if case.proposed == "pooled_rate":
            # Pooling merges two cells into one number: every identity that
            # the run id binds must be one identity.
            if left.run_id != right.run_id:
                reasons.add(REASON_IDENTITY)
            if (
                left.resolved_model != right.resolved_model
                or left.attacker != right.attacker
                or left.defense != right.defense
            ):
                reasons.add(REASON_IDENTITY)
            if left.metric_name != right.metric_name:
                reasons.add(REASON_POLARITY)
        else:
            # A paired difference contrasts two conditions; the contrasted
            # axes (model/run/defense) may differ, everything else must not.
            if left.attacker != right.attacker:
                reasons.add(REASON_IDENTITY)

    label = (
        "incompatible" if reasons
        else ("abstain" if abstain else "compatible")
    )
    return {
        "case_id": case.case_id,
        "proposed": case.proposed,
        "label": label,
        "reasons": sorted(reasons),
        "rules_version": "compat-rules/1",
    }


def validate_case(value: Mapping[str, Any]) -> ComparisonCase:
    return ComparisonCase.model_validate(value)
