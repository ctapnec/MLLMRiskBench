"""Render the three Chapter V figures and their machine-readable provenance.

``--synth`` creates exactly three neutral, conspicuously watermarked layout
placeholders.  Measured mode is intentionally explicit: Figures V.1/V.2 take a
paired cross-target experiment root while Figure V.3 takes a same-base defense
experiment root.  Both paths are validated by :mod:`experiments.figure_results`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless and deterministic
import matplotlib.pyplot as plt  # noqa: E402

from experiments.figure_results import load_results  # noqa: E402

_ACCENT = "#2a78d6"
_INK_2 = "#52514e"
_CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#7a5cc8"]
_WATERMARK = "ILLUSTRATIVE \u2014 NOT MEASURED"
_PROVENANCE_NAME = "fig-v-provenance.json"
_FIGURE_NAMES = (
    "fig-v-asr-by-model.png",
    "fig-v-asr-by-category.png",
    "fig-v-safety-utility.png",
)


def _color_for(index: int) -> str:
    return _CATEGORICAL[index % len(_CATEGORICAL)]


def _apply_style() -> None:
    plt.rcParams.update({
        "figure.dpi": 110,
        "font.size": 9,
        "axes.edgecolor": "#c3c2b7",
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": "#e1e0d9",
        "grid.linewidth": 0.8,
        "axes.titlesize": 11,
    })


def _det(*parts: str) -> float:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def _placeholder_point(point_id: str, label: str, index: int, **extra: Any) -> dict[str, Any]:
    value = -0.28 + 0.56 * _det(point_id, label)
    half_width = 0.08 + 0.05 * _det(point_id, "ci")
    return {
        "point_id": point_id,
        "label": label,
        "status": "illustrative_not_measured",
        "value": value,
        "ci_low": max(-1.0, value - half_width),
        "ci_high": min(1.0, value + half_width),
        "effect_direction": "Condition A minus Condition B",
        "n_pairs": 40 + index * 7,
        "n_clusters": 20 + index * 3,
        "illustrative": True,
        **extra,
    }


def synth_matrix() -> dict[str, Any]:
    """Return a neutral preview of the final paired-effect layouts."""
    model_points = [
        _placeholder_point(f"model:condition-{index}", f"Condition {letter}", index)
        for index, letter in enumerate("ABCDEF")
    ]
    category_points = [
        _placeholder_point(
            f"category:condition-{index}",
            f"Condition {letter} | Category {index + 1} | Modality {index % 2 + 1}",
            index,
            corpus=f"Condition {letter}",
            risk_category=f"Category {index + 1}",
            modality=f"Modality {index % 2 + 1}",
        )
        for index, letter in enumerate("ABCDE")
    ]
    defense_points: list[dict[str, Any]] = []
    for index, letter in enumerate("ABC"):
        for metric_index, metric in enumerate(("ASR", "FRR")):
            defense_points.append(_placeholder_point(
                f"defense:condition-{index}:{metric}",
                f"Condition {letter} | {metric}",
                index * 2 + metric_index,
                corpus=f"Condition {letter}",
                metric=metric,
            ))
    figures = {
        _FIGURE_NAMES[0]: {
            "estimand": "illustrative paired harmful-risk difference",
            "points": model_points,
        },
        _FIGURE_NAMES[1]: {
            "estimand": "illustrative paired category-cell difference",
            "points": category_points,
        },
        _FIGURE_NAMES[2]: {
            "estimand": "illustrative paired defense effects",
            "points": defense_points,
        },
    }
    return {
        "schema_version": "ura-chapter-v-figures/1.0",
        "illustrative": True,
        "analysis": {
            "status": "illustrative_not_measured",
            "labels": "neutral Condition A--F labels",
            "corpus_pooling": "not applicable",
        },
        "figures": figures,
    }


def _tag(fig: Any, illustrative: bool) -> None:
    if illustrative:
        fig.text(
            0.5,
            0.5,
            _WATERMARK,
            fontsize=28,
            color="#00000018",
            ha="center",
            va="center",
            rotation=30,
            zorder=0,
        )


def _point_label(point: dict[str, Any], *, category: bool = False) -> str:
    if point.get("label"):
        return str(point["label"])
    corpus = str(point.get("corpus") or "unknown corpus")
    if category:
        risk = str(point.get("risk_category") or "no harmful cells")
        modality = str(point.get("modality") or "unavailable modality")
        return f"{corpus} | {risk} | {modality}"
    if point.get("metric"):
        return f"{corpus} | {point['metric']}"
    return corpus


def _contrast_figure(
    points: list[dict[str, Any]], out: Path, *, filename: str, title: str,
    category: bool = False, illustrative: bool,
) -> None:
    if not points:
        raise ValueError(f"{filename} has no explicit facet rows")
    height = max(3.4, 0.48 * len(points) + 1.8)
    fig, ax = plt.subplots(figsize=(9.6 if category else 8.2, height))
    ax.axvline(0.0, color=_INK_2, linewidth=1.0)
    labels: list[str] = []
    for index, point in enumerate(points):
        labels.append(_point_label(point, category=category))
        value = point.get("value")
        low = point.get("ci_low")
        high = point.get("ci_high")
        if value is None or low is None or high is None:
            ax.scatter([0.0], [index], marker="x", color=_INK_2, zorder=3)
            ax.text(
                0.025,
                index,
                f"unestimated ({point['status']}; clusters={point['n_clusters']})",
                va="center",
                fontsize=8,
                color=_INK_2,
            )
            continue
        color_index = index
        if point.get("metric") == "FRR":
            color_index = 2
        elif point.get("metric") == "ASR":
            color_index = 1
        ax.errorbar(
            [value],
            [index],
            xerr=[[value - low], [high - value]],
            fmt="o",
            color=_color_for(color_index),
            ecolor=_INK_2,
            capsize=3,
            markersize=6,
            zorder=3,
        )
        ax.text(
            min(0.96, max(-0.96, high + 0.025)),
            index,
            f"{value:+.1%}; n={point['n_pairs']}/{point['n_clusters']} clusters",
            va="center",
            fontsize=8,
            color=_INK_2,
        )
    ax.set_yticks(range(len(points)))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(-1.0, 1.0)
    ax.xaxis.set_major_formatter(lambda x, _: f"{x:+.0%}")
    ax.set_xlabel("paired risk difference (left minus right; lower favours left)")
    ax.set_title(title)
    _tag(fig, illustrative)
    fig.savefig(out / filename, dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig_asr_by_model(data: dict[str, Any], out: Path) -> None:
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[0]]["points"],
        out,
        filename=_FIGURE_NAMES[0],
        title=(
            "Paired harmful-risk endpoint contrasts by benchmark (illustrative)"
            if data["illustrative"]
            else "Paired harmful-risk endpoint contrasts by benchmark"
        ),
        illustrative=data["illustrative"],
    )


def fig_asr_by_category(data: dict[str, Any], out: Path) -> None:
    analysis = data.get("analysis") or {}
    detail = ""
    if not data["illustrative"]:
        detail = (
            f"\npolicy={analysis['policy_label']}; "
            f"multiplicity family={analysis['multiplicity_family']}; "
            "judge/run versions are bound per cell in the provenance sidecar"
        )
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[1]]["points"],
        out,
        filename=_FIGURE_NAMES[1],
        title="Paired harmful-risk differences by benchmark, category, and modality" + detail,
        category=True,
        illustrative=data["illustrative"],
    )


def fig_safety_utility(data: dict[str, Any], out: Path) -> None:
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[2]]["points"],
        out,
        filename=_FIGURE_NAMES[2],
        title=(
            "Paired same-base defense effects on harmful risk and benign false refusal"
            + (" (illustrative)" if data["illustrative"] else "")
        ),
        illustrative=data["illustrative"],
    )


def _write_provenance(data: dict[str, Any], out: Path) -> Path:
    destination = out / _PROVENANCE_NAME
    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return destination


def render_all(data: dict[str, Any], out: Path) -> list[Path]:
    """Render three PNGs and ``fig-v-provenance.json`` into ``out``.

    The return value remains the three image paths so callers cannot mistake the
    JSON sidecar for a fourth figure.
    """
    figures = data.get("figures")
    if not isinstance(figures, dict) or set(figures) != set(_FIGURE_NAMES):
        raise ValueError("figure payload must define exactly the three Chapter V figures")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    _apply_style()
    fig_asr_by_model(data, out)
    fig_asr_by_category(data, out)
    fig_safety_utility(data, out)
    _write_provenance(data, out)
    return [out / filename for filename in _FIGURE_NAMES]


def _measured_args_missing(args: argparse.Namespace) -> list[str]:
    required = {
        "--defense-results": args.defense_results,
        "--model-left": args.model_left,
        "--model-right": args.model_right,
        "--model-corpus": args.model_corpus,
        "--defense-model": args.defense_model,
        "--defense-right": args.defense_right,
        "--defense-corpus": args.defense_corpus,
        "--policy-label": args.policy_label,
        "--multiplicity-family": args.multiplicity_family,
        "--minimum-cell-n": args.minimum_cell_n,
    }
    return [flag for flag, value in required.items() if value is None or value == []]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render paired, corpus-faceted Chapter V figures and provenance."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synth", action="store_true", help="render three layout placeholders")
    mode.add_argument(
        "--model-results",
        type=Path,
        help="completed grid root for the paired model contrast (measured mode)",
    )
    parser.add_argument(
        "--defense-results", type=Path,
        help="completed grid root for the same-base defense contrast",
    )
    parser.add_argument("--model-left", help="left requested model_spec for Figures V.1/V.2")
    parser.add_argument("--model-right", help="right requested model_spec for Figures V.1/V.2")
    parser.add_argument("--model-defense", default="none")
    parser.add_argument(
        "--model-corpus", action="append",
        help="explicit model-contrast corpus facet; repeat for multiple benchmarks",
    )
    parser.add_argument("--defense-model", help="same model_spec in both Figure V.3 arms")
    parser.add_argument("--defense-left", default="none")
    parser.add_argument("--defense-right", help="right defense configuration for Figure V.3")
    parser.add_argument(
        "--defense-corpus", action="append",
        help="explicit defense-contrast corpus facet; repeat for multiple benchmarks",
    )
    parser.add_argument("--attacker", default="replay")
    parser.add_argument("--policy-label", help="frozen policy/decision-boundary label")
    parser.add_argument("--multiplicity-family", help="frozen confirmatory/exploratory family")
    parser.add_argument(
        "--minimum-cell-n",
        type=int,
        help="pilot-frozen minimum unique corpus/source/datapoint clusters per plotted cell",
    )
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "figures",
        help="output directory for three PNGs and fig-v-provenance.json",
    )
    args = parser.parse_args(argv)

    if args.synth:
        supplied = [
            args.defense_results,
            args.model_left,
            args.model_right,
            args.model_corpus,
            args.defense_model,
            args.defense_right,
            args.defense_corpus,
            args.policy_label,
            args.multiplicity_family,
            args.minimum_cell_n,
        ]
        if any(value is not None and value != [] for value in supplied):
            parser.error("--synth cannot be combined with measured-analysis arguments")
        data = synth_matrix()
    else:
        missing = _measured_args_missing(args)
        if missing:
            parser.error("measured mode requires " + ", ".join(missing))
        if args.bootstrap < 1:
            parser.error("--bootstrap must be positive")
        if args.minimum_cell_n < 1:
            parser.error("--minimum-cell-n must be positive")
        try:
            data = load_results(
                args.model_results,
                args.defense_results,
                model_left=args.model_left,
                model_right=args.model_right,
                model_defense=args.model_defense,
                model_corpora=args.model_corpus,
                defense_model=args.defense_model,
                defense_left=args.defense_left,
                defense_right=args.defense_right,
                defense_corpora=args.defense_corpus,
                attacker=args.attacker,
                policy_label=args.policy_label,
                multiplicity_family=args.multiplicity_family,
                minimum_cell_n=args.minimum_cell_n,
                n_resamples=args.bootstrap,
                seed=args.seed,
            )
        except ValueError as exc:
            print(f"figure input validation failed: {exc}", file=sys.stderr)
            return 1
    paths = render_all(data, args.out)
    kind = "illustrative" if data["illustrative"] else "measured paired effects"
    print(
        f"wrote {len(paths)} figures ({kind}) and {_PROVENANCE_NAME} to {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
