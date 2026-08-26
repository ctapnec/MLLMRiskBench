"""Small target-only execution-accounting helpers for campaign controllers."""
from __future__ import annotations

from collections.abc import Iterable, Mapping


MAX_TARGET_EXECUTION_COUNT = 1_000_000


def target_execution_counts(attempted: object, successful: object) -> tuple[int, int]:
    """Validate one target-only attempted/successful count pair."""

    if (
        isinstance(attempted, bool)
        or not isinstance(attempted, int)
        or isinstance(successful, bool)
        or not isinstance(successful, int)
        or attempted < 0
        or attempted > MAX_TARGET_EXECUTION_COUNT
        or successful < 0
        or successful > attempted
    ):
        raise ValueError("target execution counts are invalid")
    return attempted, successful


def completed_target_execution(summary: Mapping[str, object]) -> tuple[int, int]:
    """Use completion-bound target observations, never call reservations."""

    roles = summary.get("role_reachability")
    execution = roles.get("execution_roles") if isinstance(roles, Mapping) else None
    target = execution.get("target") if isinstance(execution, Mapping) else None
    observed = target.get("observed_records") if isinstance(target, Mapping) else None
    return target_execution_counts(observed, observed)


def aggregate_target_execution(
    rows: Iterable[Mapping[str, object]],
    *,
    accounting_unavailable: bool = False,
) -> tuple[int, int] | None:
    """Sum already accepted status rows, or retain an explicit unknown result."""

    if accounting_unavailable:
        return None
    attempted_total = 0
    successful_total = 0
    for row in rows:
        attempted_raw = row.get("target_attempts")
        successful_raw = row.get("successful_target_generations")
        try:
            attempted = int(attempted_raw)  # type: ignore[arg-type]
            successful = int(successful_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError("target execution status count is not an integer") from exc
        if str(attempted) != attempted_raw or str(successful) != successful_raw:
            raise ValueError("target execution status count is not canonical decimal")
        attempted, successful = target_execution_counts(attempted, successful)
        attempted_total += attempted
        successful_total += successful
        target_execution_counts(attempted_total, successful_total)
    return attempted_total, successful_total
