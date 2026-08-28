"""Versioned whole-cluster sampling policies shared by CLI artifacts and UI."""
from __future__ import annotations


SEEDED_PSEUDORANDOM_CLUSTER_PREFIX = (
    "seeded_pseudorandom_whole_cluster_prefix_v1"
)
SOURCE_ORDER_CLUSTER_PREFIX = "source_order_whole_cluster_prefix_v1"
DEFAULT_SAMPLING_POLICY = SEEDED_PSEUDORANDOM_CLUSTER_PREFIX
SAMPLING_POLICIES = frozenset({
    SEEDED_PSEUDORANDOM_CLUSTER_PREFIX,
    SOURCE_ORDER_CLUSTER_PREFIX,
})


def effective_sampling_policy(value: object) -> str:
    """Return the legacy default for omission and reject every unknown policy."""

    if value is None:
        return DEFAULT_SAMPLING_POLICY
    if not isinstance(value, str) or value not in SAMPLING_POLICIES:
        raise ValueError("sampling policy is unsupported")
    return value


__all__ = [
    "DEFAULT_SAMPLING_POLICY",
    "SAMPLING_POLICIES",
    "SEEDED_PSEUDORANDOM_CLUSTER_PREFIX",
    "SOURCE_ORDER_CLUSTER_PREFIX",
    "effective_sampling_policy",
]
