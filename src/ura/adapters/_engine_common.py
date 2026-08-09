"""Shared helpers for the external red-team engine adapters (thesis III.2.2).

Every engine adapter (pyrit, garak, deepteam, promptfoo) imports these to lazily
load its third-party dependency and to build schema-valid Attempts uniformly.
"""
from __future__ import annotations

from ..data_models import Attempt, DataPoint, DialogTurn


def _require(module: str, feature: str, pip_name: str | None = None):
    """Lazily import ``module`` or raise a uniform install hint.

    Kept in one place so every engine reports missing deps identically. The
    install hint names the distributable ``pip_name`` (defaults to the module's
    top-level package).
    """
    import importlib

    pkg = pip_name or module.split(".", 1)[0]
    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            f"{pkg} is required for {feature}; pip install {pkg}"
        ) from exc


def _seed_dialog(datapoint: DataPoint, prompt: str) -> list[DialogTurn]:
    """Render an engine-produced prompt as a dialog, preserving prior history."""
    history = list(datapoint.dialog_history)
    history.append(DialogTurn(role="user", content=prompt))
    return history


def _attempt(
    datapoint: DataPoint,
    attacker: str,
    strategy: str,
    turn_index: int,
    prompt: str,
    seed: int,
    params: dict | None = None,
) -> Attempt:
    """Build a schema-valid :class:`Attempt` for a single engine turn."""
    return Attempt(
        id=f"{datapoint.id}:{attacker}:{turn_index}",
        datapoint_id=datapoint.id,
        attacker=attacker,
        strategy=strategy,
        turn_index=turn_index,
        rendered_input=_seed_dialog(datapoint, prompt),
        seed=seed,
        params=params or {},
    )
