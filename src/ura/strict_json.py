"""Side-effect-free strict JSON decoding for persisted trust boundaries.

The standard-library decoder deliberately accepts duplicate object names and
JavaScript numeric constants.  Neither behaviour is safe for scientific,
budget, or lifecycle state: two readers can disagree about which value is
authoritative.  Keep the policy in this neutral leaf module so runtime,
analysis, and the local console all apply the same contract.
"""

from __future__ import annotations

import json
import math
from typing import Any


DEFAULT_MAX_JSON_NODES = 2_000_000
DEFAULT_MAX_JSON_DEPTH = 64


class DuplicateJSONKeyError(ValueError):
    """A JSON object declared the same decoded member name more than once."""


class NonFiniteJSONNumberError(ValueError):
    """A JSON input used NaN or an infinite numeric constant."""


def strict_json_loads(
    text: str | bytes | bytearray,
    *,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> Any:
    """Decode JSON with one unambiguous bounded representation.

    Syntax and UTF-8 errors remain the standard ``json``/``Unicode`` exception
    types so append-only recovery code can distinguish a torn final write from
    a complete but semantically invalid record.
    """

    if (
        isinstance(max_nodes, bool)
        or not isinstance(max_nodes, int)
        or max_nodes < 1
        or isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or max_depth < 0
    ):
        raise ValueError("strict JSON complexity bounds must be positive integers")

    def reject_constant(value: str) -> None:
        raise NonFiniteJSONNumberError(
            f"non-standard JSON numeric constant {value!r}"
        )

    def object_without_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise DuplicateJSONKeyError(f"duplicate JSON object key {key!r}")
            value[key] = item
        return value

    decoded = (
        bytes(text).decode("utf-8")
        if isinstance(text, (bytes, bytearray))
        else text
    )
    try:
        value = json.loads(
            decoded,
            parse_constant=reject_constant,
            object_pairs_hook=object_without_duplicates,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the decoder limit") from exc
    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"JSON artifact exceeds {max_nodes} value nodes")
        if depth > max_depth:
            raise ValueError(f"JSON artifact nesting exceeds {max_depth}")
        if isinstance(item, float) and not math.isfinite(item):
            raise NonFiniteJSONNumberError(
                "JSON artifact contains a non-finite number"
            )
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


__all__ = [
    "DEFAULT_MAX_JSON_DEPTH",
    "DEFAULT_MAX_JSON_NODES",
    "DuplicateJSONKeyError",
    "NonFiniteJSONNumberError",
    "strict_json_loads",
]
