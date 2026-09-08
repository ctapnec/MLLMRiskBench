"""Validated report collection, pricing, cost, and reconciliation helpers."""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from pathlib import Path
from typing import Any, Mapping

from ura.model_identity import canonical_provider_name

from ura.approximate_metrics import validate_approximate_metric_provenance
from ura.sampling import effective_sampling_policy
from ura.strict_json import strict_json_loads

from .catalog import _REPO_ROOT, _MAX_RENDER_BYTES, _INVENTORY_MAX_ENTRIES


from .artifacts import (
    _TOKEN_CATEGORIES,
    _BILLED_CATEGORIES,
    _UNBILLED_PROVIDERS,
    derived_scan_directory_excluded,
)

_REPORT_SCHEMAS = {
    "ura-retained-judge-comparison/1": "judge_comparison",
    "ura-local-campaign-execution-accounting/1": "execution_accounting",
    "ura-level1-evidence/3": "level1",
    "ura-level1-evidence/2": "level1",
    "ura-level2-report/1": "level2",
    "ura-level2-report/2": "level2",
    "ura-suite-evidence/1": "suite",
    "ura-lane-canary/1": "canary",
}

# Exact experiment/measurement conditions that keep Level-2 rows in one
# presentation stratum.  Target and run identity are deliberately included:
# the maintained Level-2 contract says rows from distinct strata are not
# comparable, so the console must not imply a cross-target ranking by placing
# them in one chart.
_LEVEL2_STRATUM_FIELDS = (
    "run_id",
    "corpus_arm",
    "model_spec",
    "resolved_model",
    "source",
    "source_policy_id",
    "source_policy_version",
    "source_policy_sha256",
    "risk_category",
    "effective_modality",
    "expected_behavior",
    "population",
    "horizon_turns",
    "attacker",
    "defense",
    "defense_guardrail_revision",
    "ordered_judges",
    "judge_model",
    "seeds",
    "sample_seed",
    "limit",
    "sampling_policy",
    "semantic_family",
    "metric",
    "endpoint_status",
    "metric_authority",
    "warning_tag",
    "evidence_class",
    "reliability_kind",
    "polarity",
    "group_refinements",
    "execution_modes",
    "ci_method",
    "cluster_unit",
)

_LEVEL2_ROW_FIELDS = frozenset(
    {
        *_LEVEL2_STRATUM_FIELDS,
        "value",
        "ci_low",
        "ci_high",
        "n_records",
        "n_clusters",
        "judgments_completed",
        "judgments_evaluable",
        "judgments_decided",
        "judgments_abstained",
        "judgments_non_evaluable",
        "cross_stratum_pooling_permitted",
        "metric_authority",
        "warning_tag",
        "evidence_class",
        "reliability_score",
        "reliability_kind",
        "approximate_provenance",
        "approximate_model_query_count",
        "approximate_source_reference_use_count",
    }
) - {"sampling_policy"}
# Historical Level-2 rows predate the explicit policy switch. They remain
# renderable; new rows carry the field and therefore form distinct strata.

_TERMINAL_INVENTORY_FIELDS = {
    "schema",
    "status",
    "cohort_order",
    "cohort_counts",
    "row_order",
    "rows",
    "failure_rows",
    "project_revision_strata",
    "source_conformance_strata",
    "all_rows_terminal",
    "cross_revision_pooling_permitted",
    "cross_source_pooling_permitted",
    "accounting",
}
_TERMINAL_INVENTORY_SCHEMA = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}terminal-inventory/[1-9][0-9]{0,8}\Z"
)
_TERMINAL_INVENTORY_MAX_GROUPS = 128


def _terminal_inventory_label(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and all(ord(character) >= 32 for character in value)
    )


_TERMINAL_INVENTORY_ROW_FIELDS = {
    "key",
    "cohort",
    "logical_id",
    "terminal_state",
    "failure",
    "project_revision_stratum",
    "source_conformance_stratum",
    "evidence",
}


def _validate_terminal_inventory(document: Mapping[str, Any]) -> None:
    """Validate a generic, self-reconciling terminal-inventory report."""

    rows = document.get("rows")
    row_order = document.get("row_order")
    cohort_order = document.get("cohort_order")
    cohort_counts = document.get("cohort_counts")
    if (
        set(document) != _TERMINAL_INVENTORY_FIELDS
        or not isinstance(document.get("schema"), str)
        or _TERMINAL_INVENTORY_SCHEMA.fullmatch(document["schema"]) is None
        or not isinstance(cohort_order, list)
        or not 1 <= len(cohort_order) <= _TERMINAL_INVENTORY_MAX_GROUPS
        or any(
            not _terminal_inventory_label(cohort)
            for cohort in cohort_order
        )
        or len(set(cohort_order)) != len(cohort_order)
        or not isinstance(cohort_counts, Mapping)
        or set(cohort_counts) != set(cohort_order)
        or any(
            type(cohort_counts.get(cohort)) is not int
            or cohort_counts[cohort] < 0
            for cohort in cohort_order
        )
        or not isinstance(rows, list)
        or not 1 <= len(rows) <= _INVENTORY_MAX_ENTRIES
        or sum(cohort_counts.values()) != len(rows)
        or not isinstance(row_order, list)
        or len(row_order) != len(rows)
        or document.get("all_rows_terminal") is not True
        or type(document.get("cross_revision_pooling_permitted")) is not bool
        or type(document.get("cross_source_pooling_permitted")) is not bool
    ):
        raise ValueError("terminal inventory schema, size, or cohort counts differ")

    accounting = document.get("accounting")
    if (
        not isinstance(accounting, Mapping)
        or len(accounting) > _TERMINAL_INVENTORY_MAX_GROUPS
        or any(
            not _terminal_inventory_label(field)
            or type(value) is not int
            or value < 0
            for field, value in accounting.items()
        )
    ):
        raise ValueError("terminal inventory accounting is malformed")

    keys: list[str] = []
    failures: list[str] = []
    cohort_rows = {str(cohort): [] for cohort in cohort_order}
    project_strata: dict[str, list[str]] = {}
    source_strata: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _TERMINAL_INVENTORY_ROW_FIELDS:
            raise ValueError("terminal inventory row fields differ")
        cohort = row.get("cohort")
        logical_id = row.get("logical_id")
        key = row.get("key")
        state = row.get("terminal_state")
        revision = row.get("project_revision_stratum")
        source = row.get("source_conformance_stratum")
        if (
            cohort not in cohort_rows
            or not _terminal_inventory_label(logical_id)
            or key != f"{cohort}:{logical_id}"
            or not _terminal_inventory_label(state)
            or type(row.get("failure")) is not bool
            or not _terminal_inventory_label(revision)
            or not _terminal_inventory_label(source)
            or not isinstance(row.get("evidence"), Mapping)
            or not row["evidence"]
            or len(row["evidence"]) > _TERMINAL_INVENTORY_MAX_GROUPS
        ):
            raise ValueError("terminal inventory row identity or fields differ")
        keys.append(key)
        cohort_rows[cohort].append(key)
        project_strata.setdefault(revision, []).append(key)
        source_strata.setdefault(source, []).append(key)
        if row["failure"]:
            failures.append(key)

    if (
        len(set(keys)) != len(rows)
        or row_order != keys
        or any(
            len(cohort_rows[cohort]) != cohort_counts[cohort]
            for cohort in cohort_order
        )
        or document.get("failure_rows") != failures
        or document.get("project_revision_strata") != project_strata
        or document.get("source_conformance_strata") != source_strata
        or document.get("status")
        != ("complete_with_failures" if failures else "complete")
    ):
        raise ValueError("terminal inventory partition or status differs")


def _validate_content_id(
    document: Mapping[str, Any],
    field: str,
    prefix: str,
) -> None:
    """Validate the producer's content-derived report/evidence identifier."""

    claimed = document.get(field)
    if (
        not isinstance(claimed, str)
        or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{24}", claimed) is None
    ):
        raise ValueError(f"missing or malformed {field}")
    body = dict(document)
    del body[field]
    try:
        material = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("report is not strict canonical JSON") from exc
    expected = prefix + hashlib.sha256(material).hexdigest()[:24]
    if not secrets.compare_digest(claimed, expected):
        raise ValueError(f"{field} does not match the report content")


def _validate_report_document(kind: str, document: Mapping[str, Any]) -> None:
    """Fail closed before a retained document receives a scientific badge."""

    if kind == "judge_comparison":
        from experiments.retained_response_judge_report import validate_report

        validate_report(dict(document))
        return

    if kind == "execution_accounting":
        from experiments.local_campaign.execution_accounting import (
            validate_execution_accounting,
        )

        validate_execution_accounting(dict(document))
        return

    if kind == "terminal_inventory":
        _validate_terminal_inventory(document)
        return

    if kind == "level1":
        if document.get("schema_version") not in {
            "ura-level1-evidence/3",
            "ura-level1-evidence/2",
        }:
            raise ValueError("wrong Level-1 schema")
        if document.get("status") != "validated_unit_qualified_lifecycle_inventory":
            raise ValueError("Level-1 status is not validated")
        _validate_content_id(document, "evidence_id", "level1-")
        scope = document.get("scope")
        if not isinstance(scope, Mapping):
            raise ValueError("Level-1 scope is missing")
        evidence_kind = scope.get("evidence_kind")
        if evidence_kind not in {"diagnostic_dry_run", "measured_run"}:
            raise ValueError("Level-1 evidence_kind is invalid")
        if scope.get("empirical_validity_established") is not False:
            raise ValueError("Level-1 empirical-validity boundary is missing")
        if scope.get("contains_diagnostic_dry_run") is not (evidence_kind == "diagnostic_dry_run"):
            raise ValueError("Level-1 diagnostic scope is inconsistent")
        counts = document.get("counts")
        if not isinstance(counts, Mapping):
            raise ValueError("Level-1 counts are missing")
        for name in (
            "prospective_request_units",
            "planning_strata",
            "execution_units",
            "judgment_records",
            "approximate_proxy_judgment_records",
            "request_level_errors",
        ):
            block = counts.get(name)
            if name in {
                "prospective_request_units",
                "approximate_proxy_judgment_records",
            } and block is None:
                continue
            if (
                not isinstance(block, Mapping)
                or not isinstance(block.get("unit"), str)
                or not block.get("unit")
            ):
                raise ValueError(f"Level-1 {name} count block is malformed")
            for key, value in block.items():
                if key == "unit" or value is None:
                    continue
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"Level-1 {name}.{key} is not a nonnegative count")
        judgment_counts = counts.get("judgment_records")
        if isinstance(judgment_counts, Mapping):
            completed = judgment_counts.get("completed")
            evaluable = judgment_counts.get("evaluable")
            decided = judgment_counts.get("decided")
            abstained = judgment_counts.get("abstained")
            missing_responses = judgment_counts.get("missing_responses")
            non_evaluable = judgment_counts.get("non_evaluable")
            if (
                all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in (completed, decided, abstained, non_evaluable)
                )
                and completed != decided + abstained + non_evaluable
            ):
                raise ValueError("Level-1 judgment decision counts do not reconcile")
            if (
                all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in (evaluable, decided, abstained)
                )
                and evaluable != decided + abstained
            ):
                raise ValueError("Level-1 evaluable judgment counts do not reconcile")
            if missing_responses is not None:
                if (
                    not isinstance(missing_responses, int)
                    or isinstance(missing_responses, bool)
                    or not isinstance(abstained, int)
                    or isinstance(abstained, bool)
                    or missing_responses < 0
                    or missing_responses > abstained
                ):
                    raise ValueError(
                        "Level-1 missing-response counts do not reconcile"
                    )
                planning_rows = document.get("planning_strata")
                if not isinstance(planning_rows, list):
                    raise ValueError(
                        "Level-1 missing-response counts require planning strata"
                    )
                row_counts = [
                    row.get("missing_response_judgment_records")
                    for row in planning_rows
                    if isinstance(row, Mapping)
                ]
                if (
                    len(row_counts) != len(planning_rows)
                    or any(
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                        for value in row_counts
                    )
                    or sum(row_counts) != missing_responses
                ):
                    raise ValueError(
                        "Level-1 missing-response counts do not match planning strata"
                    )
        approximate_counts = counts.get("approximate_proxy_judgment_records")
        if isinstance(approximate_counts, Mapping):
            evaluable = approximate_counts.get("evaluable")
            decided = approximate_counts.get("decided")
            abstained = approximate_counts.get("abstained")
            if (
                all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in (evaluable, decided, abstained)
                )
                and evaluable != decided + abstained
            ):
                raise ValueError(
                    "Level-1 approximate proxy decision counts do not reconcile"
                )
            planning_rows = document.get("planning_strata")
            if not isinstance(planning_rows, list):
                raise ValueError(
                    "Level-1 approximate proxy counts require planning strata"
                )
            row_fields = {
                "evaluable": "approximate_proxy_evaluable_judgment_records",
                "decided": "approximate_proxy_decided_judgment_records",
                "abstained": "approximate_proxy_abstained_judgment_records",
            }
            for count_name, row_name in row_fields.items():
                values = [
                    row.get(row_name)
                    for row in planning_rows
                    if isinstance(row, Mapping)
                ]
                if len(values) != len(planning_rows) or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                    for value in values
                ):
                    raise ValueError(
                        f"Level-1 planning-stratum {row_name} is malformed"
                    )
                if sum(values) != approximate_counts.get(count_name):
                    raise ValueError(
                        "Level-1 approximate proxy counts do not match planning strata"
                    )
        return

    if kind != "level2":
        return
    if document.get("schema_version") not in {"ura-level2-report/1", "ura-level2-report/2"}:
        raise ValueError("wrong Level-2 schema")
    if document.get("status") != "deterministic_compatible_stratum_export":
        raise ValueError("Level-2 status is not validated")
    if document.get("empirical_validity_established") is not False:
        raise ValueError("Level-2 empirical-validity boundary is missing")
    pooling = document.get("pooling_policy")
    if not isinstance(pooling, Mapping) or (
        pooling.get("universal_safety_score_defined") is not False
        or pooling.get("cross_stratum_pooling_permitted") is not False
        or pooling.get("native_scale_pooling_permitted") is not False
    ):
        raise ValueError("Level-2 no-pooling policy is missing")
    _validate_content_id(document, "report_id", "level2-")
    if document.get("schema_version") == "ura-level2-report/2":
        from experiments.generation_conditions import validate_generation_conditions

        inputs = document.get("inputs")
        cells = inputs.get("cells") if isinstance(inputs, Mapping) else None
        if not isinstance(cells, list) or any(not isinstance(cell, dict) for cell in cells):
            raise ValueError("Level-2 generation source cells are missing")
        if any(not isinstance(cell.get("run_id"), str) for cell in cells):
            raise ValueError("Level-2 generation source cells are ambiguous")
        run_ids = {cell["run_id"] for cell in cells}
        if len(run_ids) != len(cells):
            raise ValueError("Level-2 generation source cells are ambiguous")
        conditions = document.get("generation_conditions")
        validate_generation_conditions(conditions, run_ids)
        for cell in cells:
            expected = cell.get("n_responses")
            if type(expected) is not int or expected < 0 or expected != sum(
                row["rows"] for row in conditions["conditions"] if row["run_id"] == cell["run_id"]
            ):
                raise ValueError("Level-2 generation rows differ from source cell counts")
    common = document.get("common")
    if not isinstance(common, Mapping) or not isinstance(common.get("estimates"), list):
        raise ValueError("Level-2 common estimates are missing")
    estimates = common["estimates"]
    count = common.get("n_estimate_rows")
    if not isinstance(count, int) or isinstance(count, bool) or count != len(estimates):
        raise ValueError("Level-2 estimate count does not reconcile")
    for row in estimates:
        if not isinstance(row, Mapping) or not _LEVEL2_ROW_FIELDS.issubset(row):
            raise ValueError("Level-2 estimate row is incomplete")
        if "sampling_policy" in row:
            if not isinstance(row["sampling_policy"], str):
                raise ValueError(
                    "Level-2 estimate sampling policy is unsupported"
                )
            try:
                effective_sampling_policy(row["sampling_policy"])
            except ValueError as exc:
                raise ValueError(
                    "Level-2 estimate sampling policy is unsupported"
                ) from exc
        metric = row.get("metric")
        is_approximate = isinstance(metric, str) and metric.startswith("approximate_")
        approximate_value = row.get("approximate_provenance")
        if is_approximate:
            approximate = validate_approximate_metric_provenance(
                metric, approximate_value
            )
            expected_flat = {
                "metric_authority": "supplementary_non_authoritative",
                "warning_tag": approximate.warning_tag,
                "evidence_class": approximate.evidence_class,
                "reliability_score": approximate.reliability_score,
                "reliability_kind": approximate.reliability_kind,
            }
            if any(row.get(name) != value for name, value in expected_flat.items()):
                raise ValueError(
                    "Level-2 approximate warning/provenance fields are incoherent"
                )
            if row.get("endpoint_status") != "approximate_common_proxy":
                raise ValueError("Level-2 approximate endpoint status is incoherent")
            expected_counts = {
                "n_records": approximate.n_result_units,
                "judgments_decided": approximate.n_supporting_decisions,
                "judgments_non_evaluable": 0,
                "approximate_model_query_count": (
                    approximate.n_model_queried_decisions
                ),
                "approximate_source_reference_use_count": (
                    approximate.n_source_reference_context_used
                ),
            }
            # Supporting decisions do not include valid proxy abstentions.
            # The common conservation checks below retain those in completed
            # and evaluable coverage: decided + abstained, not decided alone.
            if any(
                isinstance(row.get(name), bool)
                or not isinstance(row.get(name), int)
                or row.get(name) != value
                for name, value in expected_counts.items()
            ):
                raise ValueError(
                    "Level-2 approximate support/query/reference counts are incoherent"
                )
        elif (
            approximate_value is not None
            or row.get("metric_authority") != "authoritative_or_source_native"
            or any(
                row.get(name) is not None
                for name in (
                    "warning_tag",
                    "evidence_class",
                    "reliability_score",
                    "reliability_kind",
                    "approximate_model_query_count",
                    "approximate_source_reference_use_count",
                )
            )
        ):
            raise ValueError(
                "Level-2 authoritative/source-native row carries approximate semantics"
            )
        value = row.get("value")
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise ValueError("Level-2 estimate value is not finite")
        ci_low, ci_high = row.get("ci_low"), row.get("ci_high")
        if (ci_low is None) != (ci_high is None):
            raise ValueError("Level-2 CI endpoints must be paired")
        if ci_low is not None and ci_high is not None:
            if any(
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not math.isfinite(item)
                for item in (ci_low, ci_high)
            ):
                raise ValueError("Level-2 CI endpoints are not finite numbers")
            if ci_low > ci_high:
                raise ValueError("Level-2 CI endpoints are reversed")
            tolerance = 1e-9
            if not ci_low - tolerance <= value <= ci_high + tolerance:
                raise ValueError("Level-2 estimate lies outside its CI")
        for name in ("n_records", "n_clusters"):
            item = row.get(name)
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                raise ValueError(f"Level-2 {name} is not a nonnegative count")
        if row.get("cross_stratum_pooling_permitted") is not False:
            raise ValueError("Level-2 row permits cross-stratum pooling")
        decisions: dict[str, int] = {}
        for name in (
            "judgments_completed",
            "judgments_evaluable",
            "judgments_decided",
            "judgments_abstained",
            "judgments_non_evaluable",
        ):
            item = row.get(name)
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                raise ValueError(f"Level-2 {name} is not a nonnegative count")
            decisions[name] = item
        if decisions["judgments_completed"] != (
            decisions["judgments_decided"]
            + decisions["judgments_abstained"]
            + decisions["judgments_non_evaluable"]
        ) or decisions["judgments_evaluable"] != (
            decisions["judgments_decided"] + decisions["judgments_abstained"]
        ):
            raise ValueError("Level-2 judgment counts do not reconcile")
        missing_responses = row.get("judgments_missing_responses")
        if missing_responses is not None and (
            not isinstance(missing_responses, int)
            or isinstance(missing_responses, bool)
            or missing_responses < 0
            or missing_responses > decisions["judgments_abstained"]
        ):
            raise ValueError("Level-2 missing-response count is incoherent")


def collect_reports(
    root: Path,
    *,
    max_entries: int = _INVENTORY_MAX_ENTRIES,
) -> list[dict[str, Any]]:
    """Index retained report artifacts by their declared schema_version."""

    rows: list[dict[str, Any]] = []
    seen = 0
    stack: list[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return rows
            if entry.is_dir():
                if not derived_scan_directory_excluded(entry):
                    stack.append(entry)
                continue
            if entry.is_symlink():
                continue
            if not entry.name.endswith(".json"):
                continue
            try:
                size = entry.stat().st_size
                if size > _MAX_RENDER_BYTES:
                    continue
                doc = strict_json_loads(entry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            schema = doc.get("schema_version") if isinstance(doc, dict) else None
            kind = _REPORT_SCHEMAS.get(schema or "")
            if kind is None:
                continue
            try:
                relative = entry.relative_to(root).as_posix()
            except ValueError:
                relative = entry.name
            rows.append(
                {
                    "path": relative,
                    "schema": str(schema),
                    "kind": kind,
                    "sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
                    "bytes": size,
                    "mtime": entry.stat().st_mtime,
                    "recorded_at": time.time(),
                }
            )
    return rows


def collect_report_file(root: Path, path: Path) -> dict[str, Any] | None:
    """Index one exact, regular, in-root report output or return ``None``."""

    try:
        root_resolved = root.resolve(strict=True)
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root_resolved).as_posix()
        if not resolved.is_file() or not resolved.name.endswith(".json"):
            return None
        size = resolved.stat().st_size
        if size > _MAX_RENDER_BYTES:
            return None
        payload = resolved.read_bytes()
        doc = strict_json_loads(payload.decode("utf-8"))
        schema = doc.get("schema_version") if isinstance(doc, dict) else None
        kind = _REPORT_SCHEMAS.get(schema or "")
        if kind is None:
            return None
        metadata = resolved.stat()
    except (OSError, UnicodeError, ValueError):
        return None
    return {
        "path": relative,
        "schema": str(schema),
        "kind": kind,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": size,
        "mtime": metadata.st_mtime,
        "recorded_at": time.time(),
    }


def load_pricing(repo_root: Path = _REPO_ROOT) -> dict[str, Any]:
    """The operator-edited pricing table (local file, then the example)."""

    for candidate in ("pricing.json", "rig/pricing.example.json"):
        path = repo_root / "experiments" / candidate
        try:
            data = strict_json_loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def rate_for(
    pricing: Mapping[str, Any],
    provider: str,
    model: str,
    *,
    on_date: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """The effective-dated rate row for (provider, model), or (None, why).

    Picks the newest rate whose effective_date is on or before ``on_date``
    (default today).  Missing provider, model, or applicable rate returns the
    exact missing field so the page can display N/A with its reason.
    """

    provider = canonical_provider_name(provider)
    providers = pricing.get("providers")
    if not isinstance(providers, Mapping):
        return None, "pricing table has no providers section"
    entry = None
    for key, value in providers.items():
        if str(key).lower() == provider.lower():
            entry = value
            break
    if not isinstance(entry, Mapping):
        return None, f"no pricing entry for provider {provider!r}"
    models = entry.get("models")
    if not isinstance(models, Mapping) or model not in models:
        return None, f"no pricing entry for model {model!r}"
    rates = models[model].get("rates") if isinstance(models[model], Mapping) else None
    if not isinstance(rates, list) or not rates:
        return None, f"no rates recorded for model {model!r}"
    today = on_date or time.strftime("%Y-%m-%d")
    if not _valid_iso_date(today):
        return None, f"invalid usage date {today!r}; expected YYYY-MM-DD"

    if any(
        not isinstance(rate, Mapping) or not _valid_iso_date(rate.get("effective_date"))
        for rate in rates
    ):
        return None, (
            f"model {model!r} has a malformed rate or a non ISO 8601 (YYYY-MM-DD) effective_date"
        )

    def _is_priced(rate: Mapping[str, Any]) -> bool:
        # An all-null row is a placeholder, not a real price: skip it so an
        # operator's earlier real rate stays the billed figure even when a
        # later-dated null placeholder sits above it in the list.
        per_million = rate.get("per_million_tokens")
        per_million = per_million if isinstance(per_million, Mapping) else {}
        return any(value is not None for value in per_million.values())

    applicable = [
        rate
        for rate in rates
        if isinstance(rate, Mapping) and rate["effective_date"] <= today and _is_priced(rate)
    ]
    if not applicable:
        return None, f"no priced rate effective on or before {today} for {model!r}"
    # On an equal effective_date, an operator-entered rate outranks an
    # auto-fetched one, and a later list position outranks an earlier one, so a
    # same-date operator correction always wins over an auto rate regardless of
    # the order the two entries happen to sit in the rates list.
    chosen = max(
        enumerate(applicable),
        key=lambda item: (
            item[1]["effective_date"],
            0 if item[1].get("auto_fetched") else 1,
            item[0],
        ),
    )[1]
    return dict(chosen), ""


def _valid_iso_date(value: Any) -> bool:
    """A real, zero-padded Gregorian calendar date."""

    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        return False
    try:
        time.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _finite_nonneg(value: Any) -> float | None:
    """A price is valid only as a finite, nonnegative real number.

    Rejects booleans (a bool is an int in Python), NaN, infinity, and negatives
    so a malformed rate never silently produces a wrong or fabricated cost.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        return float(value)
    return None


def _currency_code(value: Any) -> str | None:
    """Normalized three-letter currency code, or None when not declared."""

    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z]{3}", value) is None:
        return None
    return value.upper()


def compute_costs(
    usage_totals: Mapping[tuple[str, str, str, str], Mapping[str, int]],
    pricing: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Calculated monetary cost per (role, provider, model) from recorded use.

    The usage key carries the run's completion date, so each date's tokens are
    priced at the rate effective ON THAT DATE (reindexing today never reprices
    an old run).  Cost is recorded tokens times the applicable per-million rate;
    a rate value is honoured only when finite and nonnegative.  If any billed
    category with recorded tokens lacks a valid rate, the whole row is N/A with
    the missing fields named.  Different currencies are never summed as one:
    a single currency yields a total, a mix yields per-currency subtotals and no
    combined figure.  Local providers are not billable rather than zero.
    """

    grouped: dict[tuple[str, str, str], dict[str, dict[str, Any]]] = {}
    for key, categories in usage_totals.items():
        role, provider, model, usage_date = key
        canonical_provider = canonical_provider_name(provider)
        by_date = grouped.setdefault((role, canonical_provider, model), {})
        bucket = by_date.setdefault(usage_date, {})
        for category, value in categories.items():
            prior = bucket.get(category)
            if prior is None:
                bucket[category] = value
            elif (
                isinstance(prior, int)
                and not isinstance(prior, bool)
                and isinstance(value, int)
                and not isinstance(value, bool)
            ):
                bucket[category] = prior + value
            else:
                # Preserve malformed evidence so recorded_count reports it as
                # N/A instead of silently coercing or dropping the row.
                bucket[category] = value

    rows: list[dict[str, Any]] = []
    for (role, provider, model), by_date in sorted(grouped.items()):
        tokens = {category: 0 for category in _TOKEN_CATEGORIES}
        calls = 0
        missing_tokens = 0
        malformed_usage: list[str] = []

        def recorded_count(cats: Mapping[str, int], category: str) -> int:
            value = cats.get(category, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                malformed_usage.append(f"{provider}/{model}: invalid recorded {category} count")
                return 0
            return value

        for usage_date, cats in by_date.items():
            date_calls = recorded_count(cats, "calls")
            calls += date_calls
            missing_tokens += recorded_count(cats, "missing_tokens")
            if date_calls and not {"input", "output"}.issubset(cats):
                malformed_usage.append(
                    f"{provider}/{model}: incomplete input/output token usage "
                    f"on {usage_date or 'unknown date'}"
                )
            for category in _TOKEN_CATEGORIES:
                tokens[category] += recorded_count(cats, category)
        row: dict[str, Any] = {
            "role": role,
            "provider": provider,
            "model": model,
            "calls": calls,
            "missing_tokens": missing_tokens,
            "tokens": tokens,
            "rate": None,
            "effective_date": "",
            "currency": "",
            "cost": None,
            "by_currency": {},
            "missing": [],
            "billable": True,
            "auto_fetched": False,
            "source_url": "",
        }
        if provider.lower() in _UNBILLED_PROVIDERS:
            row["billable"] = False
            rows.append(row)
            continue

        cost_by_currency: dict[str, float] = {}
        missing: list[str] = list(dict.fromkeys(malformed_usage))
        effective_dates: set[str] = set()
        display_rate: Mapping[str, Any] | None = None
        for usage_date, cats in sorted(by_date.items()):
            if not _valid_iso_date(usage_date):
                missing.append(
                    f"{provider}/{model}: missing or invalid completion date; "
                    "historical usage cannot be priced at today's rate"
                )
                continue
            rate, why = rate_for(pricing, provider, model, on_date=usage_date)
            if rate is None:
                missing.append(f"{why} (for {usage_date})")
                continue
            per_million = rate.get("per_million_tokens")
            per_million = per_million if isinstance(per_million, Mapping) else {}
            currency = _currency_code(rate.get("currency"))
            if currency is None:
                missing.append(
                    f"{provider}/{model}: rate on {usage_date} has no valid three-letter currency"
                )
                continue
            display_rate = rate
            effective_dates.add(str(rate.get("effective_date", "")))
            subtotal = 0.0
            for category in _BILLED_CATEGORIES:
                amount = recorded_count(cats, category)
                if amount <= 0:
                    continue
                unit = _finite_nonneg(per_million.get(category))
                if unit is None:
                    missing.append(
                        f"{provider}/{model}: no valid {category} rate on {usage_date or 'today'}"
                    )
                else:
                    subtotal += amount / 1_000_000 * unit
            cost_by_currency[currency] = cost_by_currency.get(currency, 0.0) + subtotal
        if missing_tokens:
            missing.append(
                f"{provider}/{model}: {missing_tokens} call(s) have incomplete token usage"
            )
        if display_rate is not None:
            per_million = display_rate.get("per_million_tokens")
            per_million = per_million if isinstance(per_million, Mapping) else {}
            row["rate"] = {k: per_million.get(k) for k in _TOKEN_CATEGORIES}
            row["effective_date"] = ", ".join(sorted(d for d in effective_dates if d))
            row["auto_fetched"] = bool(display_rate.get("auto_fetched"))
            row["source_url"] = str(display_rate.get("source_url", ""))
        row["by_currency"] = {c: round(v, 6) for c, v in sorted(cost_by_currency.items())}
        if missing:
            row["missing"] = missing  # any missing rate -> whole row N/A
        elif len(cost_by_currency) == 1:
            currency, total = next(iter(cost_by_currency.items()))
            row["currency"] = currency
            row["cost"] = total
        elif len(cost_by_currency) > 1:
            # Never sum different currencies into one figure.
            row["currency"] = "mixed"
            row["missing"].append(
                f"{provider}/{model}: mixed currencies "
                f"{sorted(cost_by_currency)}; per-currency subtotals shown"
            )
        rows.append(row)
    return rows


def reconcile_pricing_ownership(
    submitted: Mapping[str, Any],
    current: Mapping[str, Any],
) -> None:
    """Strip auto-fetch provenance from any pricing rate the operator edited.

    When the operator corrects a fetched rate IN PLACE through the config
    editor, the row still carries ``auto_fetched`` and the fetcher would treat
    it as its own and overwrite the correction on the next run.  Comparing the
    submitted table against the on-disk one, any rate that still claims
    ``auto_fetched`` but whose (provider, model, effective_date, per-million
    figures) no longer matches an on-disk auto rate must have been changed by
    the operator, so its provenance flags are dropped and it becomes an
    operator-owned rate the fetcher will never supersede.  Mutates ``submitted``
    in place.
    """

    def index_auto(data: Mapping[str, Any]) -> dict[tuple[str, str, Any], list[Any]]:
        idx: dict[tuple[str, str, Any], list[Any]] = {}
        providers = data.get("providers")
        if not isinstance(providers, Mapping):
            return idx
        for provider, pentry in providers.items():
            models = pentry.get("models") if isinstance(pentry, Mapping) else None
            if not isinstance(models, Mapping):
                continue
            for model, mentry in models.items():
                rates = mentry.get("rates") if isinstance(mentry, Mapping) else None
                if not isinstance(rates, list):
                    continue
                for rate in rates:
                    if isinstance(rate, Mapping) and rate.get("auto_fetched"):
                        key = (provider, model, rate.get("effective_date"))
                        per_million = rate.get("per_million_tokens")
                        idx.setdefault(key, []).append(
                            dict(per_million) if isinstance(per_million, Mapping) else {}
                        )
        return idx

    on_disk = index_auto(current)
    providers = submitted.get("providers")
    if not isinstance(providers, Mapping):
        return
    for provider, pentry in providers.items():
        models = pentry.get("models") if isinstance(pentry, Mapping) else None
        if not isinstance(models, Mapping):
            continue
        for model, mentry in models.items():
            rates = mentry.get("rates") if isinstance(mentry, Mapping) else None
            if not isinstance(rates, list):
                continue
            for rate in rates:
                if not (isinstance(rate, dict) and rate.get("auto_fetched")):
                    continue
                key = (provider, model, rate.get("effective_date"))
                per_million = rate.get("per_million_tokens")
                per_million = dict(per_million) if isinstance(per_million, Mapping) else {}
                if any(per_million == known for known in on_disk.get(key, [])):
                    continue  # untouched auto rate: keep its provenance
                # The operator changed this fetched rate: it is now theirs.
                rate.pop("auto_fetched", None)
                rate.pop("source_url", None)
                rate.pop("fetched_at", None)
