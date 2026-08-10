"""Conformance tests for AutoDAN-Turbo and Giskard native evaluator runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import ura.adapters.giskard as giskard_module
from ura.adapters._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
)
from ura.adapters.autodan import AutoDANTurboAttacker
from ura.adapters.base import AttackBudget
from ura.adapters.giskard import GiskardAttacker
from ura.data_models import DataPoint, RiskCategory


def _datapoint() -> DataPoint:
    return DataPoint(
        id="native-engine-case",
        source="fixture",
        modalities=["text"],
        payload_text="seed",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _autodan_result_dir(root: Path, *, unknown_retrieval: bool = False) -> Path:
    root.mkdir(parents=True)
    warm_library = {
        "Strategy One": {
            "Strategy": "Strategy One",
            "Definition": "First definition",
            "Example": ["warm prompt"],
        }
    }
    lifelong_library = {
        **warm_library,
        "Strategy Two": {
            "Strategy": "Strategy Two",
            "Definition": "Second definition",
            "Example": ["lifelong prompt"],
        },
    }
    warm_attack = [
        {
            "request": "warm request",
            "prompt": "warm prompt",
            "response": "warm response",
            "assessment": "warm assessment",
            "score": 9.0,
            "attacker": "warm attacker system",
            "scorer": "warm scorer system",
            "iteration": 0,
            "epoch": 0,
            "request_id": 0,
            "stage": "warm_up",
        }
    ]
    retrieved = {
        "Strategy": "Missing" if unknown_retrieval else "Strategy One",
        "Definition": "First definition",
        "Example": "warm prompt",
    }
    lifelong_attack = warm_attack + [
        {
            "request": "lifelong request",
            "prompt": "lifelong prompt",
            "response": "lifelong response",
            "assessment": "lifelong assessment",
            "score": 7.5,
            # Keep the misspelling: it is the official upstream field name.
            "retrival_strategy": json.dumps([retrieved]),
            "attacker": "lifelong attacker system",
            "scorer": "lifelong scorer system",
            "iteration": 0,
            "epoch": 1,
            "request_id": 0,
            "stage": "lifelong",
        }
    ]
    warm_summary = [
        {
            "request": "warm request",
            "summarizer": "warm summarizer system",
            "weak_prompt": "weak warm prompt",
            "strong_prompt": "warm prompt",
            "strategy": json.dumps(
                {"Strategy": "Strategy One", "Definition": "First definition"}
            ),
            "score_difference": 3.0,
            "stage": "warm_up",
        }
    ]
    lifelong_summary = warm_summary + [
        {
            "request": "lifelong request",
            "summarizer": "lifelong summarizer system",
            "weak_prompt": "weak lifelong prompt",
            "strong_prompt": "lifelong prompt",
            "strategy": json.dumps(
                {"Strategy": "Strategy Two", "Definition": "Second definition"}
            ),
            "score_difference": 2.5,
            "stage": "lifelong",
        }
    ]
    _write_json(root / "warm_up_strategy_library.json", warm_library)
    _write_json(root / "warm_up_attack_log.json", warm_attack)
    _write_json(root / "warm_up_summarizer_log.json", warm_summary)
    _write_json(root / "lifelong_strategy_library.json", lifelong_library)
    _write_json(root / "lifelong_attack_log.json", lifelong_attack)
    _write_json(root / "lifelong_summarizer_log.json", lifelong_summary)
    # The importer retains these official checkpoints as opaque lineage only.
    (root / "warm_up_strategy_library.pkl").write_bytes(b"opaque warm pickle")
    (root / "lifelong_strategy_library.pkl").write_bytes(b"opaque lifelong pickle")
    AutoDANTurboAttacker.write_run_manifest(
        root,
        run_id="autodan-run-1",
        variant="standard",
        model_roles={
            "attacker": "source/attacker",
            "target": "target/model",
            "scorer": "source/scorer",
            "summarizer": "source/summarizer",
            "embedding": "source/embedding",
        },
        epochs=2,
        warm_up_iterations=1,
        lifelong_iterations=1,
        warm_up_requests=1,
        lifelong_requests=1,
        dataset_sha256="d" * 64,
    )
    return root


def test_autodan_imports_complete_target_conditioned_run(tmp_path: Path) -> None:
    results = _autodan_result_dir(tmp_path / "autodan")
    manifest = results / "ura_autodan_run_manifest.json"
    expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
    imported = AutoDANTurboAttacker(
        target_model="target/model", variant="standard"
    ).import_run(results, expected_manifest_sha256=expected)

    assert imported.engine == "autodan_turbo"
    assert imported.common_metric_eligible is False
    assert imported.runner_replay_eligible is False
    assert len(imported.source_artifacts) == 9
    assert len(imported.cases) == 2
    assert imported.cases[0].native_outcome == "native_break_score_reached"
    assert imported.cases[1].native_scores == {"danger_score_1_to_10": 7.5}
    assert imported.cases[1].native_details["retrieved_strategy_ids"] == [
        "Strategy One"
    ]
    assert imported.model_roles["attacker"] == "source/attacker"
    assert imported.native_aggregates["lifelong_strategy_ids"] == [
        "Strategy One",
        "Strategy Two",
    ]


def test_autodan_fails_closed_on_hash_or_strategy_lineage_mismatch(
    tmp_path: Path,
) -> None:
    results = _autodan_result_dir(tmp_path / "tampered")
    (results / "lifelong_attack_log.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ExternalEngineOutputError, match="SHA-256 mismatch"):
        AutoDANTurboAttacker().import_run(results)

    invalid = _autodan_result_dir(
        tmp_path / "unknown-strategy", unknown_retrieval=True
    )
    with pytest.raises(ExternalEngineOutputError, match="unknown strategy ID"):
        AutoDANTurboAttacker().import_run(invalid)


def _scan_result_dir(root: Path, report: dict | None = None) -> Path:
    root.mkdir(parents=True)
    _write_json(
        root / "scan_report.json",
        report
        if report is not None
        else {
            "LLMPromptInjectionDetector": {
                "major": ["The scan found a prompt-injection issue."]
            },
            "LLMHarmfulContentDetector": {},
        },
    )
    (root / "scan_report.html").write_text(
        "<html><body>native report</body></html>", encoding="utf-8"
    )
    GiskardAttacker.write_scan_manifest(
        root,
        run_id="giskard-scan-1",
        target_model="target/model",
        scanner_model="judge/model",
        embedding_model="embedding/model",
        dataset_id="scan-dataset",
        dataset_sha256="a" * 64,
        scan_parameters={"only": ["llm_prompt_injection"]},
    )
    return root


def test_giskard_scan_import_preserves_native_report_without_asr(
    tmp_path: Path,
) -> None:
    results = _scan_result_dir(tmp_path / "scan")
    imported = GiskardAttacker(target_model="target/model").import_scan_run(results)

    assert imported.engine == "giskard_v2_scan"
    assert imported.upstream_version == "2.19.2"
    assert imported.common_metric_eligible is False
    assert imported.import_accounting["reported_issues"] == 1
    assert imported.cases[0].native_outcome == "reported_issue:major"
    assert imported.cases[0].target_outputs == []
    assert imported.native_aggregates["reported_issue_counts"]["major"] == 1


def test_giskard_scan_empty_report_is_retained_but_not_certified(
    tmp_path: Path,
) -> None:
    results = _scan_result_dir(tmp_path / "scan-empty", report={})
    imported = GiskardAttacker().import_run(results)
    assert imported.cases[0].native_outcome == "no_issues_in_native_report"
    assert imported.cases[0].native_details["not_a_safety_certification"] is True


def _raget_result_dir(root: Path) -> Path:
    root.mkdir(parents=True)
    samples = [
        {
            "id": "q1",
            "question": "Question one?",
            "reference_answer": "Answer one.",
            "reference_context": "Context one.",
            "conversation_history": [],
            "metadata": {"question_type": "simple", "topic": "topic-a"},
        },
        {
            "id": "q2",
            "question": "Question two?",
            "reference_answer": "Answer two.",
            "reference_context": "Context two.",
            "conversation_history": [{"role": "user", "content": "Earlier"}],
            "metadata": {"question_type": "out of scope", "topic": "topic-b"},
        },
    ]
    (root / "testset.jsonl").write_text(
        "\n".join(json.dumps(item) for item in samples), encoding="utf-8"
    )
    _write_json(
        root / "agent_answer.json",
        [
            {"message": "Answer one.", "documents": ["doc-1"]},
            {"message": "Wrong answer.", "documents": None},
        ],
    )
    _write_json(
        root / "metrics_results.json",
        {
            "q1": {
                "correctness": True,
                "correctness_reason": "Matches reference.",
                "context_precision": 0.75,
            },
            "q2": {
                "correctness": False,
                "correctness_reason": "Does not match reference.",
                "context_precision": 0.25,
            },
        },
    )
    _write_json(root / "report_details.json", {"recommendation": "Improve routing."})
    (root / "report.html").write_text(
        "<html><body>native RAGET report</body></html>", encoding="utf-8"
    )
    GiskardAttacker.write_raget_manifest(
        root,
        run_id="giskard-raget-1",
        target_model="rag/target",
        evaluator_model="judge/model",
        dataset_id="rag-testset",
        dataset_sha256="b" * 64,
        evaluate_parameters={"agent_description": "A test RAG agent"},
    )
    return root


def test_giskard_raget_imports_official_save_family_and_zero_to_one_scores(
    tmp_path: Path,
) -> None:
    results = _raget_result_dir(tmp_path / "raget")
    imported = GiskardAttacker(target_model="rag/target").import_raget_run(results)

    assert imported.engine == "giskard_v2_raget"
    assert imported.common_metric_eligible is False
    assert imported.native_aggregates["correctness"] == 0.5
    assert imported.native_aggregates["component_scores_0_to_1"]["ROUTING"] == 0.0
    assert imported.native_aggregates["component_scores_0_to_1"]["KNOWLEDGE_BASE"] == 0.0
    assert imported.cases[0].native_scores == {"context_precision": 0.75}
    assert imported.cases[1].native_outcome == "incorrect"
    assert imported.import_accounting == {
        "questions": 2,
        "correct": 1,
        "incorrect": 1,
        "knowledge_base_retained": 0,
    }


def test_giskard_raget_fails_on_unaligned_native_records(tmp_path: Path) -> None:
    root = tmp_path / "raget-invalid"
    root.mkdir()
    sample = {
        "id": "q1",
        "question": "Question?",
        "reference_answer": "Answer.",
        "reference_context": "Context.",
        "conversation_history": [],
        "metadata": {"question_type": "simple", "topic": "topic-a"},
    }
    (root / "testset.jsonl").write_text(json.dumps(sample), encoding="utf-8")
    _write_json(root / "agent_answer.json", [{"message": "Answer.", "documents": None}])
    _write_json(root / "metrics_results.json", {"different-id": {"correctness": True}})
    _write_json(root / "report_details.json", {"recommendation": "None"})
    (root / "report.html").write_text("<html>report</html>", encoding="utf-8")
    GiskardAttacker.write_raget_manifest(
        root,
        run_id="bad-raget",
        target_model="rag/target",
        evaluator_model="judge/model",
        dataset_id="rag-testset",
        dataset_sha256="c" * 64,
    )
    with pytest.raises(ExternalEngineOutputError, match="do not exactly match"):
        GiskardAttacker().import_raget_run(root)


def test_giskard_run_scan_calls_real_v2_surface_not_prompt_exporter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}

    class FakeReport:
        def to_json(self, path: Path) -> None:
            _write_json(path, {"Detector": {"minor": ["Issue"]}})

        def to_html(self, path: Path) -> None:
            path.write_text("<html>scan</html>", encoding="utf-8")

    def scan(model, dataset, **kwargs):
        observed.update(model=model, dataset=dataset, kwargs=kwargs)
        return FakeReport()

    monkeypatch.setattr(
        giskard_module,
        "_require_giskard_v2",
        lambda: SimpleNamespace(__version__="2.19.2", scan=scan),
    )
    model = object()
    dataset = object()
    imported = GiskardAttacker(target_model="target/model").run_scan(
        model,
        dataset,
        tmp_path / "live-scan-artifacts",
        run_id="explicit-scan",
        scanner_model="judge/model",
        dataset_id="dataset",
        dataset_sha256="e" * 64,
        scan_kwargs={"only": ["Detector"]},
    )

    assert observed == {
        "model": model,
        "dataset": dataset,
        "kwargs": {"only": ["Detector"]},
    }
    assert imported.engine == "giskard_v2_scan"


@pytest.mark.parametrize("adapter", [AutoDANTurboAttacker(), GiskardAttacker()])
def test_native_evaluators_do_not_offer_target_free_generate(adapter) -> None:
    with pytest.raises(ExternalEngineConformanceError):
        list(adapter.generate(_datapoint(), AttackBudget(max_queries=1)))
