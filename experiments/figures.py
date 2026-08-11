"""Render the three Chapter V figures and their machine-readable provenance.

``--synth`` creates exactly three neutral, conspicuously watermarked layout
placeholders. Measured mode reads the completed run tree directly and requires
the achieved, content-addressed human audit before rendering sample-conditional
model, policy-proxy, and adaptivity estimates.
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

from experiments.figure_results import load_postrun_results  # noqa: E402

_ACCENT = "#2a78d6"
_INK_2 = "#52514e"
_CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#7a5cc8"]
_WATERMARK = "ILLUSTRATIVE \u2014 NOT MEASURED"
_PROVENANCE_NAME = "fig-v-provenance.json"
_MEASURED_QUALIFICATION = (
    "Post-experiment, sample-conditional; paired source prompt/intent-cluster "
    "percentile interval; exact identities and details in fig-v-provenance.json."
)
_FIGURE_NAMES = (
    "fig-v-asr-by-model.png",
    "fig-v-policy-proxies.png",
    "fig-v-adaptivity.png",
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
        _placeholder_point(
            "model:condition-a",
            "Condition A | primary model contrast | ASR",
            0,
            corpus="Condition A",
            metric="ASR",
            comparison_type="cross_target_endpoint_noncausal",
        )
    ]
    proxy_points = [
        _placeholder_point(
            f"proxy:condition-{index}",
            f"Condition {letter} | policy-qualified proxy | {metric}",
            index,
            corpus=f"Condition {letter}",
            source_policy_id=f"Policy {index + 1}",
            metric=metric,
            population=(
                "harmful_expected_refusal" if metric == "ASR"
                else "benign_expected_answer"
            ),
            comparison_type="cross_target_endpoint_noncausal",
        )
        for index, (letter, metric) in enumerate(zip("ABCDEFG", ["ASR"] * 6 + ["FRR"]))
    ]
    adaptivity_points = [
        _placeholder_point(
            f"adaptivity:condition-{index}",
            f"Condition {letter} | replay-vs-adaptive | ASR",
            index,
            corpus="Condition A",
            metric="ASR",
            comparison_type="within_target_adaptivity_endpoint",
        )
        for index, letter in enumerate("HI")
    ]
    figures = {
        _FIGURE_NAMES[0]: {
            "figure_role": "primary_model",
            "estimand": "illustrative primary paired harmful-ASR difference",
            "points": model_points,
        },
        _FIGURE_NAMES[1]: {
            "figure_role": "secondary_policy_proxies",
            "estimand": "illustrative policy-qualified ASR/FRR proxy differences",
            "points": proxy_points,
        },
        _FIGURE_NAMES[2]: {
            "figure_role": "h4_adaptivity",
            "estimand": "illustrative replay-versus-adaptive harmful-ASR differences",
            "points": adaptivity_points,
        },
    }
    return {
        "schema_version": "ura-chapter-v-figures/1.2",
        "illustrative": True,
        "analysis": {
            "status": "illustrative_not_measured",
            "labels": "neutral Condition A--I labels",
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


def _arm_label(arm: Any) -> str:
    if not isinstance(arm, dict):
        return "unknown arm"
    model = arm.get("model_spec") or arm.get("resolved_target") or "unknown model"
    attacker = arm.get("attacker") or "unknown attacker"
    return f"{model} [{attacker}]"


def _point_label(point: dict[str, Any], *, policy_proxy: bool = False) -> str:
    if point.get("label"):
        return str(point["label"])
    corpus = str(point.get("corpus") or "unknown corpus")
    metric = str(point.get("metric") or "unknown endpoint")
    arms = f"{_arm_label(point.get('left_arm'))} minus {_arm_label(point.get('right_arm'))}"
    if policy_proxy:
        policy = str(point.get("source_policy_id") or "unversioned policy")
        cells = [corpus, policy, metric]
        if point.get("risk_category"):
            cells.append(str(point["risk_category"]))
        if point.get("modality"):
            cells.append(str(point["modality"]))
        return " | ".join(cells) + f"\n{arms}"
    return f"{corpus} | {metric}\n{arms}"


def _contrast_figure(
    points: list[dict[str, Any]], out: Path, *, filename: str, title: str,
    policy_proxy: bool = False, illustrative: bool,
) -> None:
    if not points:
        raise ValueError(f"{filename} has no explicit facet rows")
    height = max(3.4, 0.48 * len(points) + 1.8)
    fig, ax = plt.subplots(figsize=(9.6 if policy_proxy else 8.2, height))
    ax.axvline(0.0, color=_INK_2, linewidth=1.0)
    labels: list[str] = []
    for index, point in enumerate(points):
        labels.append(_point_label(point, policy_proxy=policy_proxy))
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
    ax.set_xlabel("paired adverse-endpoint difference (left minus right; lower favours left)")
    ax.set_title(title)
    if not illustrative:
        fig.subplots_adjust(bottom=0.14)
        fig.text(
            0.5, 0.015, _MEASURED_QUALIFICATION,
            ha="center", va="bottom", fontsize=7, color=_INK_2,
        )
    _tag(fig, illustrative)
    fig.savefig(out / filename, dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig_asr_by_model(data: dict[str, Any], out: Path) -> None:
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[0]]["points"],
        out,
        filename=_FIGURE_NAMES[0],
        title=(
            "Primary paired harmful-ASR model contrast (illustrative)"
            if data["illustrative"]
            else "Primary paired harmful-ASR model contrast"
        ),
        illustrative=data["illustrative"],
    )


def fig_policy_proxies(data: dict[str, Any], out: Path) -> None:
    analysis = data.get("analysis") or {}
    detail = ""
    if not data["illustrative"]:
        detail = f"\njudge policy [{analysis['policy_fingerprint'][:12]}]"
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[1]]["points"],
        out,
        filename=_FIGURE_NAMES[1],
        title=(
            "Secondary policy-qualified proxy endpoints: MM-SafetyBench ASR and "
            "MOSSBench benign FRR"
        ) + detail,
        policy_proxy=True,
        illustrative=data["illustrative"],
    )


def fig_adaptivity(data: dict[str, Any], out: Path) -> None:
    _contrast_figure(
        data["figures"][_FIGURE_NAMES[2]]["points"],
        out,
        filename=_FIGURE_NAMES[2],
        title=(
            "H4 within-target replay-versus-Crescendo harmful-ASR contrasts"
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
    fig_policy_proxies(data, out)
    fig_adaptivity(data, out)
    _write_provenance(data, out)
    return [out / filename for filename in _FIGURE_NAMES]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render paired, corpus-faceted Chapter V figures and provenance."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synth", action="store_true", help="render three layout placeholders")
    mode.add_argument("--results", type=Path, help="common parent of completed run grids")
    parser.add_argument(
        "--left-model", help="exact manifest run.model_spec for the left model"
    )
    parser.add_argument(
        "--right-model", help="exact manifest run.model_spec for the right model"
    )
    parser.add_argument(
        "--human-audit", type=Path,
        help="achieved human_audit.json directly under --results",
    )
    parser.add_argument(
        "--human-audit-sha256",
        help="required SHA-256 of --human-audit",
    )
    parser.add_argument(
        "--strongreject-corpus", default="strongreject",
        help="exact run.corpus arm carrying StrongREJECT (default: strongreject)",
    )
    parser.add_argument(
        "--mmsafety-corpus", default="mmsafety",
        help="exact run.corpus arm carrying MM-SafetyBench (default: mmsafety)",
    )
    parser.add_argument(
        "--mossbench-corpus", default="mossbench",
        help="exact run.corpus arm carrying MOSSBench (default: mossbench)",
    )
    parser.add_argument(
        "--bootstrap", type=int, default=2000,
        help="paired prompt/intent-cluster bootstrap resamples (default: 2000)",
    )
    parser.add_argument(
        "--seed", type=int, default=0, help="analysis resampling seed"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "figures",
        help="output directory for three PNGs and fig-v-provenance.json",
    )
    args = parser.parse_args(argv)

    if args.synth:
        if any(value is not None for value in (
            args.left_model, args.right_model, args.human_audit,
            args.human_audit_sha256,
        )):
            parser.error("--synth cannot be combined with measured-analysis arguments")
        data = synth_matrix()
    else:
        missing = [
            option for option, value in (
                ("--left-model", args.left_model),
                ("--right-model", args.right_model),
                ("--human-audit", args.human_audit),
                ("--human-audit-sha256", args.human_audit_sha256),
            ) if value is None
        ]
        if missing:
            parser.error("measured figures require " + ", ".join(missing))
        if args.bootstrap < 1:
            parser.error("--bootstrap must be positive")
        try:
            data = load_postrun_results(
                args.results,
                left_model=args.left_model,
                right_model=args.right_model,
                human_audit=args.human_audit,
                human_audit_sha256=args.human_audit_sha256,
                n_resamples=args.bootstrap,
                seed=args.seed,
                strongreject_corpus=args.strongreject_corpus,
                mmsafety_corpus=args.mmsafety_corpus,
                mossbench_corpus=args.mossbench_corpus,
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
