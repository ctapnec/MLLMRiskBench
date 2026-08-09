"""Deterministic run orchestrator (thesis III.2.2, N1/N6).

The Runner ties the four layers together for one (attacker, target, judge)
triple: for every DataPoint it materializes Attempts (per seed), sends each
Attempt's rendered dialog to the target, judges the Response through the
cascade, and records the full provenance lineage (attempt -> response ->
judgment + per-stage trail). It emits a re-derivable :class:`RunManifest`,
aggregates judgments into :class:`EvalResult` metrics with bootstrap CIs, and
persists results as JSONL (and Parquet when pandas is importable).

Determinism is a hard requirement: no wall-clock or unseeded randomness leaks
into the manifest or the metrics - ``started_at`` is injected by the caller and
every stochastic metric threads a fixed seed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

from . import metrics
from .adapters.base import AttackBudget, BaseAttacker
from .data_models import (
    Attempt,
    DataPoint,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
    SCHEMA_VERSION,
)
from .judges.base import JudgeCascade
from .targets.base import BaseTarget

#: Bumped when the orchestration semantics change (recorded in every manifest).
CODE_VERSION = "ura-runner/1.0"


class Runner:
    """Execute an (attacker, target, judge-cascade) triple over a corpus."""

    def __init__(
        self,
        attacker: BaseAttacker,
        target: BaseTarget,
        judge_cascade: JudgeCascade,
        budget: AttackBudget,
        seeds: list[int],
    ) -> None:
        self.attacker = attacker
        self.target = target
        self.judge_cascade = judge_cascade
        self.budget = budget
        self.seeds = list(seeds) if seeds else [budget.seed]

        # Provenance captured during the most recent run (deterministic order).
        self.attempts: list[Attempt] = []
        self.responses: list[Response] = []
        self.trails: dict[str, list[Judgment]] = {}
        # Per-attempt grouping keys for the trails (risk_category/modality/model/seed),
        # so save_trails can emit per-category rows that kappa.py groups on (V.2.5).
        self.trail_meta: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #

    def run(
        self,
        corpus: list[DataPoint],
        *,
        started_at: str = "",
        skip_ids: Optional[set[str]] = None,
    ) -> tuple[list[Judgment], RunManifest]:
        """Run the full pipeline over ``corpus``.

        Returns the list of final judgments (one per Attempt) and a manifest.
        ``started_at`` is injected verbatim (blank by default) to keep runs
        reproducible; ``skip_ids`` lets a resumed run bypass finished attempts.
        """
        skip = skip_ids or set()
        self.attempts = []
        self.responses = []
        self.trails = {}
        self.trail_meta = {}
        judgments: list[Judgment] = []

        for dp in corpus:
            for seed in self.seeds:
                seeded_budget = replace(self.budget, seed=seed)
                for attempt in self.attacker.generate(dp, seeded_budget):
                    if attempt.id in skip:
                        continue
                    response = self._respond(attempt)
                    final, trail = self.judge_cascade.judge(dp, response)
                    final = self._annotate(final, dp, attempt, response)

                    self.attempts.append(attempt)
                    self.responses.append(response)
                    self.trails[attempt.id] = trail
                    self.trail_meta[attempt.id] = {
                        "risk_category": dp.risk_category.value,
                        "modality": _modality_label(dp.modalities),
                        "model": response.target,
                        "seed": str(attempt.seed),
                    }
                    judgments.append(final)

        manifest = self._build_manifest(corpus, started_at=started_at)
        return judgments, manifest

    def _respond(self, attempt: Attempt) -> Response:
        """Query the target and guarantee the response is linked to the attempt."""
        response = self.target.generate(attempt.rendered_input)
        if response.attempt_id != attempt.id:
            response = response.model_copy(update={"attempt_id": attempt.id})
        return response

    @staticmethod
    def _annotate(
        judgment: Judgment,
        datapoint: DataPoint,
        attempt: Attempt,
        response: Response,
    ) -> Judgment:
        """Fold grouping/provenance keys into the judgment's ``raw`` block.

        Aggregation only sees judgments, so the dimensions we may later group by
        (model, adapter, risk) must travel inside the record itself.
        """
        provenance = {
            "datapoint_id": datapoint.id,
            "source": datapoint.source,
            "risk_category": datapoint.risk_category.value,
            "risk": datapoint.risk_category.value,  # short alias for grouping/figures
            "modality": _modality_label(datapoint.modalities),   # for m-ASR grouping
            "is_multimodal": len(set(datapoint.modalities) - {"text"}) > 0,
            "risk_subtype": datapoint.risk_subtype,
            "expected_behavior": datapoint.expected_behavior,
            "attack_family": datapoint.attack_family,
            "attacker": attempt.attacker,
            "strategy": attempt.strategy,
            "seed": attempt.seed,
            "turn_index": attempt.turn_index,   # orders multi-turn escalations (V.2.4)
            "target": response.target,
            "model": response.target,
        }
        merged = {**judgment.raw, **provenance}
        return judgment.model_copy(update={"raw": merged})

    # ------------------------------------------------------------------ #
    # Manifest
    # ------------------------------------------------------------------ #

    def _build_manifest(self, corpus: list[DataPoint], *, started_at: str) -> RunManifest:
        dataset_hashes = self._dataset_hashes(corpus)
        adapters = [self.attacker.name]
        models = [self.target.name]
        judges = [stage.name for stage in self.judge_cascade.stages]
        if self.judge_cascade.human_sink is not None:
            judges.append(self.judge_cascade.human_sink.name)

        run_id = self._run_id(dataset_hashes, models, adapters, judges)
        return RunManifest(
            run_id=run_id,
            code_version=CODE_VERSION,
            config={
                "budget": {
                    "max_queries": self.budget.max_queries,
                    "max_turns": self.budget.max_turns,
                    "seed": self.budget.seed,
                },
                "n_datapoints": len(corpus),
                "n_attempts": len(self.attempts),
            },
            seeds=list(self.seeds),
            models=models,
            adapters=adapters,
            judges=judges,
            dataset_hashes=dataset_hashes,
            started_at=started_at,
            schema_version=SCHEMA_VERSION,
        )

    @staticmethod
    def _dataset_hashes(corpus: list[DataPoint]) -> dict[str, str]:
        """Content hash of the whole corpus plus a per-source breakdown."""
        hashes: dict[str, str] = {}
        hashes["corpus"] = _sha256_json([dp.model_dump(mode="json") for dp in corpus])
        by_source: dict[str, list[dict[str, Any]]] = {}
        for dp in corpus:
            by_source.setdefault(dp.source, []).append(dp.model_dump(mode="json"))
        for source, rows in sorted(by_source.items()):
            hashes[f"source:{source}"] = _sha256_json(rows)
        return hashes

    @staticmethod
    def _run_id(
        dataset_hashes: dict[str, str],
        models: list[str],
        adapters: list[str],
        judges: list[str],
    ) -> str:
        material = _sha256_json(
            {
                "code_version": CODE_VERSION,
                "dataset": dataset_hashes.get("corpus", ""),
                "models": models,
                "adapters": adapters,
                "judges": judges,
            }
        )
        return f"run-{material[:16]}"

    # ------------------------------------------------------------------ #
    # Aggregation
    # ------------------------------------------------------------------ #

    def aggregate(
        self, judgments: list[Judgment], group_keys: list[str]
    ) -> list[EvalResult]:
        """Bucket judgments by ``group_keys`` and compute the standard metrics.

        For each bucket emits ASR (with bootstrap CI), refusal rate, over-refusal
        rate, and the graded StrongREJECT-style score as :class:`EvalResult`s.
        """
        keys = list(group_keys)

        def _key(j: Judgment) -> str:
            return "|".join(f"{k}={_group_value(j, k)}" for k in keys) or "all"

        buckets = metrics.group_by_key(judgments, _key)
        seed = self.budget.seed
        results: list[EvalResult] = []

        for bucket_label in sorted(buckets):
            bucket = buckets[bucket_label]
            group_by = _decode_group(bucket_label, keys)
            n = len(bucket)

            # Every rate carries a bootstrap 95% CI (no bare point estimates, V.1.6).
            asr, lo, hi = metrics.asr_with_ci(bucket, seed=seed)
            results.append(
                _result("ASR", asr, group_by, n, ci=(lo, hi), bucket=bucket_label)
            )
            # ISR: ASR restricted to indirect prompt-injection attempts, emitted
            # separately so the injection axis is not averaged away (II.5.1).
            injection = [
                j for j in bucket
                if (j.raw.get("risk_category") or j.raw.get("risk")) == "prompt_injection_indirect"
            ]
            if injection:
                isr, ilo, ihi = metrics.asr_with_ci(injection, seed=seed)
                results.append(
                    _result("ISR", isr, group_by, len(injection), ci=(ilo, ihi), bucket=bucket_label)
                )
            refusal_ind = [1.0 if j.label in ("refusal", "over_refusal") else 0.0 for j in bucket]
            results.append(
                _result(
                    "refusal_rate",
                    metrics.refusal_rate(bucket),
                    group_by,
                    n,
                    ci=metrics.bootstrap_ci(refusal_ind, seed=seed),
                    bucket=bucket_label,
                )
            )
            over_ind = [1.0 if j.label == "over_refusal" else 0.0 for j in bucket]
            results.append(
                _result(
                    "over_refusal_rate",
                    metrics.over_refusal_rate(bucket),
                    group_by,
                    n,
                    ci=metrics.bootstrap_ci(over_ind, seed=seed),
                    bucket=bucket_label,
                )
            )
            graded = [j.score for j in bucket if j.label in ("violation", "safe")]
            results.append(
                _result(
                    "strongreject",
                    metrics.strongreject_score(bucket),
                    group_by,
                    n,
                    ci=metrics.bootstrap_ci(graded, seed=seed),
                    bucket=bucket_label,
                )
            )

            # Multi-turn robustness (V.2.4 / RQ4): group the bucket's judgments into
            # escalations (one conversation per datapoint+seed, ordered by turn) and
            # report whole-escalation robust refusal and median turns-to-break. Well
            # defined for single-turn cells too (each escalation is one turn).
            escalations = _escalations(bucket)
            resisted_ind = [
                1.0 if all(j.label != "violation" for j in e) else 0.0
                for e in escalations.values()
            ]
            results.append(
                _result(
                    "robust_refusal_rate",
                    metrics.robust_refusal_rate(escalations),
                    group_by,
                    len(escalations),
                    ci=metrics.bootstrap_ci(resisted_ind, seed=seed),
                    bucket=bucket_label,
                )
            )
            mttb = metrics.median_turns_to_break(escalations)
            if mttb is not None:  # None = no escalation ever broke; omit rather than emit 0
                results.append(
                    _result(
                        "median_turns_to_break",
                        mttb,
                        group_by,
                        len(escalations),
                        bucket=bucket_label,
                    )
                )
        return results

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def save_results(self, judgments: list[Judgment], path: str | Path) -> None:
        """Persist judgments as JSONL (always) and Parquet (if pandas is present)."""
        p = Path(path)
        jsonl_path = p if p.suffix == ".jsonl" else p.with_suffix(".jsonl")
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        rows = [j.model_dump(mode="json") for j in judgments]
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

        try:
            import pandas as pd  # noqa: PLC0415  (lazy: optional dependency)
        except ImportError:
            return
        parquet_path = jsonl_path.with_suffix(".parquet")
        # ``raw`` is a nested dict; JSON-encode it so Parquet stays flat/portable.
        flat = [{**r, "raw": json.dumps(r.get("raw", {}), sort_keys=True)} for r in rows]
        pd.DataFrame(flat).to_parquet(parquet_path, index=False)

    def save_trails(self, path: str | Path) -> None:
        """Persist the per-stage judge trail as JSONL for inter-judge agreement (kappa).

        One row per (attempt, judge stage): ``{attempt_id, stage, judge, label,
        score, risk_category, modality}``. Consumed by ``experiments/kappa.py`` to
        compute Cohen's kappa between judge stages, pooled and PER RISK CATEGORY -
        the per-category agreement V.2.2/V.2.3/V.2.5 depend on.
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            for attempt_id, trail in self.trails.items():
                meta = self.trail_meta.get(attempt_id, {})
                for stage, j in enumerate(trail):
                    fh.write(json.dumps({
                        "attempt_id": attempt_id,
                        "stage": stage,
                        "judge": j.judge,
                        "label": j.label,
                        "score": j.score,
                        "risk_category": meta.get("risk_category", "unknown"),
                        "modality": meta.get("modality", "unknown"),
                    }, sort_keys=True) + "\n")

    # ------------------------------------------------------------------ #
    # Resume
    # ------------------------------------------------------------------ #

    @staticmethod
    def resume(manifest_path: str | Path) -> RunManifest:
        """Load a previously written manifest so a run can skip finished work.

        Returns the parsed :class:`RunManifest`; callers derive the set of
        already-completed attempt ids (e.g. from a sibling results file) and pass
        it to :meth:`run` as ``skip_ids``.
        """
        raw = Path(manifest_path).read_text(encoding="utf-8")
        return RunManifest.model_validate_json(raw)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _sha256_json(obj: Any) -> str:
    """Stable SHA-256 over a JSON-serializable object (sorted keys)."""
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _modality_label(modalities: list[str]) -> str:
    """Canonical single-label modality for grouping (e.g. m-ASR): the richest
    non-text modality present, else 'tool', else 'text'."""
    for m in ("video", "audio", "image"):
        if m in modalities:
            return m
    if "tool" in modalities:
        return "tool"
    return "text"


def _escalations(bucket: list[Judgment]) -> dict[str, list[Judgment]]:
    """Group a bucket of judgments into per-conversation escalations for the
    multi-turn metrics: keyed by (datapoint_id, seed), each ordered by turn_index.

    A single-turn attacker (replay) yields one-turn escalations; a multi-turn one
    (crescendo) yields the full turn ladder, so turns-to-break is well defined.
    """
    esc: dict[str, list[Judgment]] = {}
    for j in bucket:
        dp_id = j.raw.get("datapoint_id", "?")
        seed = j.raw.get("seed", "?")
        esc.setdefault(f"{dp_id}::s{seed}", []).append(j)
    for key in esc:
        esc[key].sort(key=lambda j: j.raw.get("turn_index", 0))
    return esc


def _group_value(judgment: Judgment, key: str) -> str:
    """Resolve a grouping dimension from a judgment's raw provenance/attributes."""
    if key in judgment.raw and judgment.raw[key] is not None:
        return str(judgment.raw[key])
    value = getattr(judgment, key, None)
    return str(value) if value is not None else "unknown"


def _decode_group(bucket_label: str, keys: list[str]) -> dict[str, str]:
    """Invert the composite bucket label back into a {key: value} mapping."""
    if not keys or bucket_label == "all":
        return {}
    out: dict[str, str] = {}
    for part in bucket_label.split("|"):
        name, _, value = part.partition("=")
        out[name] = value
    return out


def _result(
    metric: str,
    value: float,
    group_by: dict[str, str],
    n: int,
    *,
    ci: Optional[tuple[float, float]] = None,
    bucket: str = "all",
) -> EvalResult:
    ident = f"{metric}:{bucket}"
    return EvalResult(
        id=f"res-{_sha256_json(ident)[:16]}",
        metric=metric,
        value=value,
        ci_low=ci[0] if ci else None,
        ci_high=ci[1] if ci else None,
        n=n,
        group_by=group_by,
        provenance={"bucket": bucket},
    )


__all__ = ["Runner", "CODE_VERSION"]
