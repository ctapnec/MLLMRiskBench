"""Transparent linear baselines for compatibility detection (SYN-002).

Logistic regression and a linear SVM are trained to reproduce the
deterministic oracle's labels from pair-comparison indicator features and are
evaluated on held-out generator templates plus one fully held-out benchmark
family and model family, with hand-authored adversarial cases as the OOD set.

Boundaries, fixed by recorded operator decision (ledger Section 11.20): the
oracle's rules remain authoritative and are the label source, so every score
here measures fidelity to the rules on synthetic distributions - never
real-world validity, benchmark generalization, model ranking, or any safety
construct.  SYN-003 (independent real-label validation) was withdrawn, so no
real-world claim may ever be attached to these numbers.  Template identity,
family tags and seeds live in split metadata only and are excluded from the
feature space.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .compat_bundles import CLAIM_SCOPE, ComparisonCase, evaluate_comparison

_CLASSES = ("abstain", "compatible", "incompatible")


def featurize(case: ComparisonCase) -> dict[str, float]:
    """Pair-comparison indicators only; no ids, templates, or free text."""

    left, right = case.left, case.right
    features: dict[str, float] = {
        f"proposed={case.proposed}": 1.0,
        "same_source": float(left.source == right.source),
        "same_policy_id": float(left.source_policy_id == right.source_policy_id),
        "same_policy_version": float(
            left.source_policy_version == right.source_policy_version
        ),
        "policy_hash_both_present": float(
            left.source_policy_sha256 is not None
            and right.source_policy_sha256 is not None
        ),
        "policy_hash_match": float(
            left.source_policy_sha256 is not None
            and left.source_policy_sha256 == right.source_policy_sha256
        ),
        "same_population": float(left.population == right.population),
        "same_execution_type": float(
            left.execution_type == right.execution_type
        ),
        "same_unit": float(left.unit == right.unit),
        "same_denominator": float(left.denominator == right.denominator),
        "same_polarity": float(left.polarity == right.polarity),
        "same_scale": float(left.scale == right.scale),
        "same_metric_family": float(left.metric_family == right.metric_family),
        "same_metric_name": float(left.metric_name == right.metric_name),
        "same_endpoint_status": float(
            left.endpoint_status == right.endpoint_status
        ),
        "same_judge_order": float(left.judge_order == right.judge_order),
        "same_judge_set": float(
            sorted(left.judge_order) == sorted(right.judge_order)
        ),
        "same_run": float(left.run_id == right.run_id),
        "same_resolved_model": float(
            left.resolved_model == right.resolved_model
        ),
        "same_attacker": float(left.attacker == right.attacker),
        "same_defense": float(left.defense == right.defense),
        "same_delivery_mode": float(left.delivery_mode == right.delivery_mode),
        "same_evaluator_mode": float(
            left.evaluator_mode == right.evaluator_mode
        ),
        "same_modality": float(left.modality == right.modality),
        "both_measured": float(
            left.status == "measured" and right.status == "measured"
        ),
        "any_structural_na": float(
            "structural_na" in {left.status, right.status}
        ),
        "any_missing_status": float("missing" in {left.status, right.status}),
        "both_conversation": float(
            left.execution_type == "live_conversation"
            and right.execution_type == "live_conversation"
        ),
        "horizon_both_present": float(
            left.budget_horizon_turns is not None
            and right.budget_horizon_turns is not None
        ),
        "horizon_match": float(
            left.budget_horizon_turns is not None
            and left.budget_horizon_turns == right.budget_horizon_turns
        ),
    }
    for name, bundle in (("left", left), ("right", right)):
        numerator_ok = (
            bundle.numerator is None or bundle.numerator <= bundle.support
        )
        decided_ok = (
            bundle.decided is None or bundle.abstained is None
            or bundle.decided + bundle.abstained <= bundle.support
        )
        interval_ok = (
            bundle.ci_low is None or bundle.ci_high is None
            or bundle.estimate is None
            or bundle.ci_low <= bundle.estimate <= bundle.ci_high
        )
        interval_paired = (bundle.ci_low is None) == (bundle.ci_high is None)
        features[f"{name}_counts_consistent"] = float(
            numerator_ok and decided_ok
        )
        features[f"{name}_interval_consistent"] = float(
            interval_ok and interval_paired
        )
        features[f"{name}_provenance_complete"] = float(
            bundle.artifact_sha256 is not None
            and bundle.config_sha256 is not None
        )
        features[f"{name}_na_value_conflict"] = float(
            bundle.status != "measured"
            and (bundle.estimate is not None or bundle.numerator is not None)
        )
        features[f"{name}_na_reason_present"] = float(
            bundle.status == "measured" or bool(bundle.na_reason)
        )
    return features


_FORBIDDEN_FEATURE_TOKENS = ("template", "seed", "bundle_id", "case_id", "run-")


def assert_feature_hygiene(features: Mapping[str, float]) -> None:
    for name in features:
        lowered = name.lower()
        if any(token in lowered for token in _FORBIDDEN_FEATURE_TOKENS):
            raise ValueError(f"feature {name!r} leaks split/identity metadata")


def _template_order_token(template: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{template}".encode("utf-8")).hexdigest()


def split_cases(
    cases: Sequence[ComparisonCase],
    metadata: Mapping[str, Mapping[str, Any]],
    *, seed: int, held_out_fraction: float = 0.3,
) -> dict[str, Any]:
    """Simultaneous template/benchmark-family/model-family holdout.

    Whole templates are held out (never perturbation rows of a train
    template).  One benchmark family and one model family are held out
    completely: any template whose cases touch the held family on either
    bundle side moves to the test split.  Rendering is not used anywhere in
    this corpus, so the renderer axis is structurally not applicable and
    recorded as such.
    """

    if not 0 < held_out_fraction < 1:
        raise ValueError("held_out_fraction must be in (0, 1)")
    template_families: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for case in cases:
        meta = metadata[case.case_id]
        name = str(meta["template"])
        # Family exposure counts BOTH bundles: a held-out family must not
        # appear on either side of any training case.
        pair = (
            tuple(sorted({case.left.source, case.right.source})),
            tuple(sorted({
                case.left.requested_model, case.right.requested_model,
            })),
        )
        if template_families.setdefault(name, pair) != pair:
            raise ValueError(f"template {name!r} carries mixed family tags")
    template_names = sorted(template_families)

    def family_templates(kind_index: int, family: str) -> set[str]:
        return {
            name for name, pair in template_families.items()
            if family in pair[kind_index]
        }

    # Hold out one complete benchmark family and one complete model family
    # (chosen deterministically from the seed), then top up with whole
    # templates to reach the requested fraction.
    benchmark_families = sorted({
        family for pair in template_families.values() for family in pair[0]
    })
    model_families = sorted({
        family for pair in template_families.values() for family in pair[1]
    })
    held_benchmark = min(
        benchmark_families, key=lambda name: _template_order_token(name, seed)
    )
    held_model = min(
        model_families, key=lambda name: _template_order_token(name, seed + 1)
    )
    held = family_templates(0, held_benchmark) | family_templates(1, held_model)
    target = max(1, int(len(template_names) * held_out_fraction))
    for name in sorted(
        template_names, key=lambda item: _template_order_token(item, seed + 2)
    ):
        if len(held) >= target:
            break
        held.add(name)
    if len(held) >= len(template_names):
        raise ValueError("degenerate template split; adjust held_out_fraction")

    train = [
        case for case in cases if metadata[case.case_id]["template"] not in held
    ]
    test = [
        case for case in cases if metadata[case.case_id]["template"] in held
    ]
    if not train or not test:
        raise ValueError("degenerate template split; adjust held_out_fraction")
    overlap = {
        metadata[case.case_id]["template"] for case in train
    } & {metadata[case.case_id]["template"] for case in test}
    if overlap:
        raise ValueError(f"template leakage across split: {sorted(overlap)}")
    return {
        "train": train,
        "test": test,
        "held_out_templates": sorted(held),
        "held_out_benchmark_family": held_benchmark,
        "held_out_model_family": held_model,
        "renderer_axis": "not_applicable_no_rendering_used",
    }


def _labels(cases: Sequence[ComparisonCase]) -> list[str]:
    return [evaluate_comparison(case)["label"] for case in cases]


def _matrix(cases: Sequence[ComparisonCase]) -> tuple[Any, list[str]]:
    import numpy

    names = sorted({
        name for case in cases for name in featurize(case)
    })
    rows = []
    for case in cases:
        features = featurize(case)
        assert_feature_hygiene(features)
        rows.append([features.get(name, 0.0) for name in names])
    return numpy.asarray(rows, dtype=float), names


def _classification_metrics(gold: list[str], predicted: list[str]) -> dict[str, Any]:
    per_class: dict[str, Any] = {}
    for label in _CLASSES:
        relevant = [p for g, p in zip(gold, predicted) if g == label]
        per_class[label] = {
            "support": len(relevant),
            "recall": (
                sum(p == label for p in relevant) / len(relevant)
                if relevant else None
            ),
        }
    defined = [
        entry["recall"] for entry in per_class.values()
        if entry["recall"] is not None
    ]
    f1_terms = []
    for label in _CLASSES:
        true_positive = sum(
            g == label and p == label for g, p in zip(gold, predicted)
        )
        predicted_positive = sum(p == label for p in predicted)
        actual_positive = sum(g == label for g in gold)
        if actual_positive == 0:
            continue
        precision = (
            true_positive / predicted_positive if predicted_positive else 0.0
        )
        recall = true_positive / actual_positive
        f1_terms.append(
            0.0 if precision + recall == 0
            else 2 * precision * recall / (precision + recall)
        )
    invalid = per_class["incompatible"]
    return {
        "per_class_recall": per_class,
        "macro_recall": sum(defined) / len(defined) if defined else None,
        "macro_f1": sum(f1_terms) / len(f1_terms) if f1_terms else None,
        "invalid_comparison_recall": invalid["recall"],
        "invalid_comparison_false_negative_rate": (
            None if invalid["recall"] is None else 1 - invalid["recall"]
        ),
    }


def evaluate_linear_baselines(
    cases: Sequence[ComparisonCase],
    metadata: Mapping[str, Mapping[str, Any]],
    adversarial: Sequence[tuple[ComparisonCase, str]],
    *, seed: int,
) -> dict[str, Any]:
    try:
        import numpy
        from sklearn.linear_model import LogisticRegression
        from sklearn.svm import LinearSVC
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise ValueError(
            "SYN-002 evaluation requires the 'synthetic' optional dependency "
            "group (numpy, scikit-learn)"
        ) from exc

    split = split_cases(cases, metadata, seed=seed)
    train, test = split["train"], split["test"]
    matrix_train, names = _matrix(train)
    gold_train = _labels(train)

    def project(subset: Sequence[ComparisonCase]) -> Any:
        rows = []
        for case in subset:
            features = featurize(case)
            assert_feature_hygiene(features)
            rows.append([features.get(name, 0.0) for name in names])
        return numpy.asarray(rows, dtype=float)

    matrix_test = project(test)
    gold_test = _labels(test)
    adversarial_cases = [case for case, _ in adversarial]
    matrix_adv = project(adversarial_cases)
    gold_adv = [intended for _, intended in adversarial]

    logistic = LogisticRegression(
        max_iter=2000, random_state=seed, C=1.0, solver="lbfgs",
        class_weight="balanced",
    ).fit(matrix_train, gold_train)
    svm = LinearSVC(
        C=1.0, random_state=seed, max_iter=20000, class_weight="balanced",
    ).fit(matrix_train, gold_train)

    report: dict[str, Any] = {
        "schema_version": "ura-syn-compat-report/1",
        "label_source": "deterministic_rules_authoritative",
        "claim_scope": CLAIM_SCOPE,
        "split": {
            "n_train": len(train),
            "n_test": len(test),
            "train_classes": sorted(set(gold_train)),
            "held_out_templates": split["held_out_templates"],
            "held_out_benchmark_family": split["held_out_benchmark_family"],
            "held_out_model_family": split["held_out_model_family"],
            "renderer_axis": split["renderer_axis"],
        },
        "feature_names": names,
        "rules": {
            "note": (
                "labels are produced by the rules, so rule metrics are "
                "identically perfect by construction and stated only to "
                "anchor the comparison"
            ),
            "invalid_comparison_recall": 1.0,
            "adversarial_catch_rate": 1.0,
        },
        "models": {},
    }

    for name, model in (("logistic_regression", logistic), ("linear_svm", svm)):
        predicted = list(model.predict(matrix_test))
        adversarial_predicted = list(model.predict(matrix_adv))
        entry = _classification_metrics(gold_test, predicted)
        entry["adversarial"] = {
            "n_cases": len(gold_adv),
            "agreement_with_intended": (
                sum(p == g for p, g in zip(adversarial_predicted, gold_adv))
                / len(gold_adv)
            ),
        }
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(matrix_test)
            classes = list(model.classes_)

            def probability_of(row_index: int, label: str) -> float:
                # A class absent from training (possible under whole-family
                # holdout) has zero predicted probability by definition.
                if label not in classes:
                    return 0.0
                return float(probabilities[row_index][classes.index(label)])

            brier = float(numpy.mean([
                sum(
                    (
                        probability_of(i, label)
                        - (1.0 if label == gold_test[i] else 0.0)
                    ) ** 2
                    for label in _CLASSES
                )
                for i in range(len(gold_test))
            ]))
            confidence = probabilities.max(axis=1)
            correct = numpy.asarray([
                classes[int(k)] == gold_test[i]
                for i, k in enumerate(probabilities.argmax(axis=1))
            ])
            bins = numpy.clip(
                (confidence * 10).astype(int), 0, 9
            )
            ece = 0.0
            for bucket in range(10):
                mask = bins == bucket
                if not mask.any():
                    continue
                ece += (
                    abs(float(correct[mask].mean()) - float(confidence[mask].mean()))
                    * float(mask.mean())
                )
            selective = []
            for threshold in (0.5, 0.7, 0.8, 0.9, 0.95):
                kept = confidence >= threshold
                selective.append({
                    "confidence_threshold": threshold,
                    "coverage": float(kept.mean()),
                    "selective_risk": (
                        float(1 - correct[kept].mean()) if kept.any() else None
                    ),
                })
            adv_conf = logistic.predict_proba(matrix_adv).max(axis=1)
            ood_scores = numpy.concatenate([1 - confidence, 1 - adv_conf])
            ood_gold = numpy.concatenate([
                numpy.zeros(len(confidence)), numpy.ones(len(adv_conf)),
            ])
            order = numpy.argsort(ood_scores)
            ranks = numpy.empty(len(order), dtype=float)
            ranks[order] = numpy.arange(1, len(order) + 1)
            n_pos = float(ood_gold.sum())
            n_neg = float(len(ood_gold) - n_pos)
            auroc = (
                (ranks[ood_gold == 1].sum() - n_pos * (n_pos + 1) / 2)
                / (n_pos * n_neg)
                if n_pos and n_neg else None
            )
            entry["calibration"] = {
                "brier_score": brier,
                "ece_10bin": float(ece),
            }
            entry["selective_prediction"] = selective
            entry["ood"] = {
                "definition": (
                    "score=1-max_probability; OOD set = hand-authored "
                    "adversarial cases vs held-out-template test cases"
                ),
                "auroc": None if auroc is None else float(auroc),
            }
        else:
            entry["calibration"] = {
                "note": (
                    "margin classifier without calibrated probabilities; "
                    "probabilistic calibration reported for the logistic "
                    "baseline only"
                ),
            }
        report["models"][name] = entry
    return report
