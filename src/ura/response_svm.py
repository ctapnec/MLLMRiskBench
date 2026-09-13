"""Lightweight response-label fidelity and audit-prioritization experiments.

No target adapter, network client, model weights or campaign metric is changed.
Labels describe an automated teacher, not independent human ground truth.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import math
import random
import re

VALID_LABELS = frozenset({"safe", "refusal", "over_refusal", "violation"})
TASKS = ("harmful_compliance", "over_refusal", "judge_disagreement")
FEATURES = ("prompt", "response", "prompt_response")
CLAIM = "Automated-label fidelity on retained text responses; not human-validated safety"


def connected_groups(rows: list[dict]) -> list[str]:
    """Unite shared inputs, source clusters, exact normalized prompts and prior groups."""
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owners = {}
    for i, row in enumerate(rows):
        prompt = re.sub(r"\s+", " ", row["prompt"]).strip()
        if not prompt or not row.get("input_id") or not row.get("source_cluster_id"):
            raise ValueError("Split grouping requires prompt, input and source-cluster identity")
        keys = [("input", row["input_id"]),
                ("cluster", row["source"], row["source_cluster_id"]),
                ("prompt", hashlib.sha256(prompt.encode()).hexdigest())]
        if row.get("group"):
            keys.append(("prior_group", row["group"]))
        for key in keys:
            if key in owners:
                parent[find(i)] = find(owners[key])
            else:
                owners[key] = i
    members = defaultdict(list)
    for i, row in enumerate(rows):
        members[find(i)].append(row["input_id"])
    names = {root: min(ids) for root, ids in members.items()}
    return [names[find(i)] for i in range(len(rows))]


def split_groups(rows: list[dict], seed: int) -> dict[str, str]:
    groups = sorted(set(row["group"] for row in rows))
    if len(groups) < 5:
        raise ValueError("At least five independent input groups are required")
    random.Random(seed).shuffle(groups)
    a, b = int(.6 * len(groups)), int(.8 * len(groups))
    return {group: "train" if i < a else "validation" if i < b else "test"
            for i, group in enumerate(groups)}


def target_label(row: dict, task: str) -> int | None:
    label, expected = row.get("label"), row.get("expected_behavior")
    if label not in VALID_LABELS:
        return None
    if task == "harmful_compliance":
        return int(label == "violation") if expected == "refuse" else None
    if task == "over_refusal":
        return int(label == "over_refusal") if expected in {"safe_answer", "comply_safely"} else None
    if task == "judge_disagreement":
        native = row.get("local_label")
        return int((label == "violation") != (native == "violation")) \
            if expected == "refuse" and native in VALID_LABELS else None
    raise ValueError("Unknown response-classification task")


def clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit // 2] + "\n" + text[-(limit - limit // 2):]


def feature_matrices(parts: dict[str, list[dict]], variant: str, max_chars: int):
    """Explicit field allowlist. Never fit vocabulary/IDF on validation or test."""
    from scipy.sparse import hstack
    from sklearn.feature_extraction.text import TfidfVectorizer

    fields = ("prompt", "response") if variant == "prompt_response" else (variant,)
    if variant not in FEATURES:
        raise ValueError("Unknown text feature set")
    matrices = {part: [] for part in parts}
    vocabulary = []
    for field in fields:
        texts = {part: [clip_text(row[field], max_chars) for row in rows]
                 for part, rows in parts.items()}
        for analyzer, ngrams in (("word", (1, 2)), ("char", (3, 5))):
            vectorizer = TfidfVectorizer(analyzer=analyzer, ngram_range=ngrams,
                                        sublinear_tf=True, max_features=30000,
                                        dtype=__import__("numpy").float64)
            matrices["train"].append(vectorizer.fit_transform(texts["train"]))
            vocabulary.extend(field + ":" + value for value in vectorizer.get_feature_names_out())
            for part in ("validation", "test"):
                matrices[part].append(vectorizer.transform(texts[part]))
    return {part: hstack(blocks, format="csr") for part, blocks in matrices.items()}, vocabulary


def support(rows: list[dict], task: str) -> dict:
    return dict(responses=len(rows), groups=len({r["group"] for r in rows}),
                inputs=len({r["input_id"] for r in rows}),
                classes=dict(Counter(str(target_label(r, task)) for r in rows)),
                positive_groups=len({r["group"] for r in rows if target_label(r, task) == 1}),
                negative_groups=len({r["group"] for r in rows if target_label(r, task) == 0}),
                truncated=sum(bool(r.get("truncated")) for r in rows))


def metric_summary(y, prediction, score) -> dict:
    from sklearn.metrics import (average_precision_score, confusion_matrix,
                                 f1_score, precision_recall_fscore_support)

    precision, recall, _, count = precision_recall_fscore_support(
        y, prediction, labels=[0, 1], zero_division=0)
    return dict(macro_f1=float(f1_score(y, prediction, labels=[0, 1], average="macro", zero_division=0)),
                average_precision=float(average_precision_score(y, score)) if len(set(y)) == 2 else None,
                confusion=confusion_matrix(y, prediction, labels=[0, 1]).tolist(),
                class_precision=precision.tolist(), class_recall=recall.tolist(), support=count.tolist())


def bootstrap_f1(y, prediction, groups, *, repeats: int, seed: int) -> list[float]:
    """Cluster-resample confusion counts without copying long responses each time."""
    import numpy as np

    counts = defaultdict(lambda: np.zeros((2, 2), dtype=int))
    for truth, pred, group in zip(y, prediction, groups):
        counts[group][truth, pred] += 1
    values = np.asarray([counts[g] for g in sorted(counts)])
    rng = np.random.default_rng(seed)
    estimates = []
    for _ in range(repeats):
        matrix = values[rng.integers(0, len(values), len(values))].sum(axis=0)
        scores = []
        for k in (0, 1):
            denominator = matrix[k, :].sum() + matrix[:, k].sum()
            scores.append(2 * matrix[k, k] / denominator if denominator else 0.0)
        estimates.append(sum(scores) / 2)
    return [float(v) for v in np.quantile(estimates, [.025, .975])]


def review_curve(rows: list[dict], y, score) -> list[dict]:
    # Identity only breaks exact score ties; it is never a learned feature.
    order = sorted(range(len(rows)), key=lambda i: (-float(score[i]), rows[i]["id"]))
    positives = int(sum(y))
    result = []
    for fraction in (.1, .2, .4):
        n = math.ceil(fraction * len(order))
        captured = int(sum(y[i] for i in order[:n]))
        result.append(dict(review_fraction=n / len(order), reviewed=n, captured=captured,
                           dispute_recall=captured / positives if positives else None,
                           precision=captured / n, random_expected_recall=n / len(order)))
    return result


def derived_disagreement_baselines(rows: list[dict], predictions: list[dict], *, bootstrap=1000, seed=0):
    """Compare a third SVM with the first SVM plus the already known local verdict.

    Operates only on saved out-of-sample predictions; no fitting or provider call.
    Teacher labels are used to score this baseline, never to construct its score.
    """
    by_id = {row["id"]: row for row in rows}
    candidates = defaultdict(list)
    for prediction in predictions:
        if prediction["task"] == "harmful_compliance" and prediction["estimator"] == "linear_svm":
            original = by_id[prediction["id"]]
            row = dict(original, group=prediction.get("group", original["group"]))
            if target_label(row, "judge_disagreement") is not None:
                candidates[(prediction["protocol"], prediction["features"])].append((row, prediction))
    reports = []
    for (protocol, features), pairs in sorted(candidates.items()):
        selected = [r for r, _ in pairs]
        truth = [target_label(r, "judge_disagreement") for r in selected]
        native = [int(r["local_label"] == "violation") for r in selected]
        predicted = [p["prediction"] ^ local for (_, p), local in zip(pairs, native)]
        scores = [(-1 if local else 1) * p["score"] for (_, p), local in zip(pairs, native)]
        summary = metric_summary(truth, predicted, scores)
        summary["macro_f1_cluster_ci95"] = bootstrap_f1(truth, predicted,
            [r["group"] for r in selected], repeats=bootstrap, seed=seed)
        reports.append(dict(task="judge_disagreement", protocol=protocol, features=features,
            estimator="harmful_svm_plus_local_verdict", support=support(selected, "judge_disagreement"),
            test=summary, review_curve=review_curve(selected, truth, scores),
            additional_fits=0, uses_local_verdict=True))
    return reports


def evaluate_study(rows: list[dict], *, seed=0, max_chars=20000, bootstrap=1000,
                   holdout_models=(), holdout_corpora=(), progress=None) -> tuple[dict, list[dict]]:
    import numpy as np
    from sklearn.dummy import DummyClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import LinearSVC
    from threadpoolctl import threadpool_limits

    if not rows or max_chars < 100 or bootstrap < 100:
        raise ValueError("Need data, at least 100 feature characters and 100 bootstrap draws")
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError("Duplicate response identities in analysis dataset")
    if len({r["judge_condition"] for r in rows}) != 1:
        raise ValueError("Choose one exact teacher judging condition")
    if any(r.get("modality") != "text" or r.get("framework") != "replay"
           or not r.get("response", "").strip() or r.get("label") not in VALID_LABELS for r in rows):
        raise ValueError("The primary dataset requires labelled, nonempty static text outputs")
    groups = connected_groups(rows)
    rows = [dict(row, group=group) for row, group in zip(rows, groups)]
    split = split_groups(rows, seed)
    records, predictions = [], []
    protocols = [("group_holdout", None, None)]
    protocols += [("unseen_model:" + name, "model", name) for name in holdout_models]
    protocols += [("unseen_corpus:" + name, "corpus", name) for name in holdout_corpora]
    for task in TASKS:
        applicable = [r for r in rows if target_label(r, task) is not None]
        for protocol, field, value in protocols:
            parts = {part: [] for part in ("train", "validation", "test")}
            for row in applicable:
                part = split[row["group"]]
                held = field is not None and (row[field].startswith(value) if field == "model" else row[field] == value)
                if field is None or (part == "test" and held) or (part != "test" and not held):
                    parts[part].append(row)
            sizes = {part: support(values, task) for part, values in parts.items()}
            if any(sizes[p]["positive_groups"] < 2 or sizes[p]["negative_groups"] < 2 for p in sizes):
                records.append(dict(task=task, protocol=protocol, status="insufficient_class_group_support", support=sizes))
                continue
            assert not any({r["group"] for r in parts[a]} & {r["group"] for r in parts[b]}
                           for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")))
            y = {part: np.array([target_label(r, task) for r in values]) for part, values in parts.items()}
            for variant in FEATURES:
                if progress:
                    progress(dict(task=task, protocol=protocol, features=variant, stage="fitting"))
                with threadpool_limits(limits=2):
                    x, _ = feature_matrices(parts, variant, max_chars)
                    candidates = []
                    for c in (.1, 1.0, 10.0):
                        model = LinearSVC(C=c, class_weight="balanced", max_iter=10000, random_state=seed)
                        model.fit(x["train"], y["train"])
                        val = metric_summary(y["validation"], model.predict(x["validation"]),
                                             model.decision_function(x["validation"]))["macro_f1"]
                        candidates.append((val, c, model))
                    _, chosen_c, model = max(candidates, key=lambda item: (item[0], -item[1]))
                    estimators = [("linear_svm", model, chosen_c)]
                    if variant == "prompt_response":
                        lr = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed)
                        lr.fit(x["train"], y["train"])
                        dummy = DummyClassifier(strategy="most_frequent").fit(x["train"], y["train"])
                        estimators += [("logistic_regression", lr, 1.0), ("majority", dummy, None)]
                    for name, fitted, c in estimators:
                        pred = fitted.predict(x["test"])
                        score = fitted.decision_function(x["test"]) if name != "majority" \
                            else np.full(len(pred), float(np.mean(y["train"])))
                        summary = metric_summary(y["test"], pred, score)
                        summary["macro_f1_cluster_ci95"] = bootstrap_f1(
                            y["test"], pred, [r["group"] for r in parts["test"]], repeats=bootstrap, seed=seed)
                        facets = []
                        for axis in ("corpus", "model", "local_condition", "truncated"):
                            for level in sorted({str(r.get(axis)) for r in parts["test"]}):
                                indices = [i for i, r in enumerate(parts["test"]) if str(r.get(axis)) == level]
                                facets.append(dict(axis=axis, value=level, responses=len(indices),
                                    **metric_summary(y["test"][indices], pred[indices], score[indices])))
                        record = dict(task=task, protocol=protocol, status="evaluated", estimator=name,
                            features=variant, C=c, support=sizes, test=summary, facets=facets,
                            validation_candidates=[dict(C=v[1], macro_f1=v[0]) for v in candidates]
                            if name == "linear_svm" else [])
                        if task == "judge_disagreement":
                            record["review_curve"] = review_curve(parts["test"], y["test"], score)
                        records.append(record)
                        predictions.extend(dict(id=r["id"], input_id=r["input_id"], group=r["group"],
                            task=task, protocol=protocol, estimator=name, features=variant,
                            truth=int(truth), prediction=int(p), score=float(s))
                            for r, truth, p, s in zip(parts["test"], y["test"], pred, score))
    report = dict(status="analysis_complete", claim_scope=CLAIM, human_validated=False,
        target_calls=0, judge_calls=0, seed=seed, bootstrap_draws=bootstrap,
        max_feature_characters=max_chars, threads=2, teacher=rows[0]["judge_condition"],
        selected_responses=len(rows), independent_groups=len(set(groups)),
        clipped_fields={field: sum(len(r[field]) > max_chars for r in rows) for field in ("prompt", "response")},
        split_membership=[dict(id=r["id"], group=r["group"], split=split[r["group"]]) for r in rows],
        experiments=records, runtime=dict(numpy=np.__version__, sklearn=__import__("sklearn").__version__))
    report["derived_disagreement_baselines"] = derived_disagreement_baselines(
        rows, predictions, bootstrap=bootstrap, seed=seed)
    return report, predictions
