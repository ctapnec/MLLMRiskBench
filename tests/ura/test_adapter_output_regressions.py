"""Fail-closed regressions for generated-attack outputs and Runner coverage."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

import ura.adapters.asb as asb_module
import ura.adapters.harmbench as harmbench_module
import ura.adapters.t3mp3st as t3mp3st_module
import experiments.capture_t3mp3st as t3mp3st_capture_module
from experiments.capture_t3mp3st import (
    capture_bundle as capture_t3mp3st_bundle,
    load_input_list as load_t3mp3st_input_list,
)
from ura.adapters._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    require_generated_texts,
)
from ura.adapters._engine_runtime import EngineExecution
from ura.adapters.autodan import AutoDANTurboAttacker
from ura.adapters.base import AttackBudget, AttackSession, BaseAttacker
from ura.attacker_input_contract import (
    AttackerInputContract,
    text_only_transfer_contract,
)
from ura.adapters.easyjailbreak import EasyJailbreakAttacker
from ura.adapters.fuzzyai import FuzzyAIAttacker
from ura.adapters.giskard import GiskardAttacker
from ura.adapters.h4rm3l import H4rm3lAttacker
from ura.adapters.harmbench import HarmBenchAttacker
from ura.adapters.ideator import IDEATORAttacker
from ura.adapters.petri import PetriAttacker
from ura.adapters.purplellama import PurpleLlamaAttacker
from ura.adapters.spikee import SpikeeAttacker
from ura.adapters.t3mp3st import T3MP3STAttacker, build_plan_bundle
from ura.data_models import (
    Attempt,
    DataPoint,
    DialogTurn,
    MediaRef,
    Response,
    RiskCategory,
)
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner
from ura.targets.api import MockTarget


def _datapoint() -> DataPoint:
    return DataPoint(
        id="fail-closed-dp",
        source="unit",
        modalities=["text"],
        payload_text="harmful seed request",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _budget(seed: int = 0) -> AttackBudget:
    return AttackBudget(max_queries=2, max_turns=2, seed=seed)


def _t3_response(*, codename: str = "OPERATION LAB GLASS") -> dict:
    gate = {
        "status": "degraded",
        "score": 82,
        "blockers": [],
        "warnings": ["Receipt-gated work remains planning-only."],
        "criteria": ["Scope is explicit and target-bound"],
        "nextApproval": "human_review:synthetic-model",
    }
    orders = []
    for index in range(2):
        orders.append({
            "id": f"wo_{index}",
            "family": "ai_red_team",
            "title": f"Safe model probe {index}",
            "hypothesis": "The model may follow adversarial context.",
            "suspectedBoundary": "model instruction hierarchy",
            "target": "synthetic-model",
            "assignedArchetype": "analyst",
            "kind": "prove" if index == 0 else "disprove",
            "safeProbe": f"Synthetic planning probe {index}",
            "expectedSignal": "A text response clarifies the boundary.",
            "evidenceArtifact": "response transcript",
            "falsifier": "The target consistently follows the safe instruction.",
            "retest": "Repeat against the same frozen target configuration.",
            "requiresReceipt": False,
            "toolHints": ["manual-review"],
            "priority": index + 1,
            "status": "ready",
        })
    plan = {
        "id": "plan-1",
        "codename": codename,
        "summary": "Planning-only probes for a synthetic model target.",
        "targets": [{"address": "synthetic-model"}],
        "objectives": [{"description": "Evaluate instruction following."}],
        "operators": [{"archetype": "analyst"}],
        "opsecLevel": "silent",
        "phaseStrategy": [],
        "roe": {"scope": ["synthetic-model"], "destructiveAllowed": False},
        "contingencies": [],
        "complexity": "low",
        "rationale": "No execution is needed.",
        "missionFamily": "ai_red_team",
        "huntLanes": [{"family": "ai_red_team"}],
        "authorityReceipts": [],
        "evidenceContract": {"requiredArtifacts": ["response transcript"]},
        "workOrders": orders,
        "toolPlan": [{"family": "ai_red_team"}],
        "critic": {"weirdRoute": "context collision"},
        "missionGate": gate,
        "learning": {"replaySuites": ["frozen-target"]},
        "createdAt": 1,
    }
    review = {
        "status": gate["status"],
        "score": gate["score"],
        "blockers": list(gate["blockers"]),
        "warnings": list(gate["warnings"]),
        "strengths": ["The plan is bounded."],
        "requiredReceipts": [],
        "coverage": {"ai_red_team": 1},
        "recommendedNextActions": ["Replay the prompts against the model only."],
    }
    return {"success": True, "plan": plan, "review": review, "missionGate": gate}


def _t3_points() -> list[DataPoint]:
    return [
        _datapoint().model_copy(
            update={"id": "t3-row-1", "payload_text": "first harmful seed request"}
        ),
        _datapoint().model_copy(
            update={"id": "t3-row-2", "payload_text": "second harmful seed request"}
        ),
    ]


def _write_t3_json(path: Path, value: object) -> str:
    raw = (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _completed(command) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")


class _EngineRuntimeFixture:
    admitted = True

    def __init__(
        self,
        engine: str,
        *,
        result: object,
        artifacts: dict[str, bytes] | None = None,
    ) -> None:
        self.engine = engine
        self.result = result
        self.artifacts = artifacts or {}

    def public_descriptor(self) -> dict:
        return {"schema": "test-runtime/1", "status": "verified"}

    def execute(
        self, _operation: str, _payload: object, **_kwargs: object
    ) -> EngineExecution:
        return EngineExecution(
            result=self.result,
            artifacts=self.artifacts,
            request_sha256="a" * 64,
            runtime=self.public_descriptor(),
        )


def test_generated_text_validator_rejects_non_strings_and_blank_values() -> None:
    with pytest.raises(ExternalEngineOutputError, match="no valid generated prompts"):
        require_generated_texts([None, 0, {}, "   "], feature="test engine")
    assert require_generated_texts(
        ["  keep attack whitespace  ", "second"], feature="test engine", limit=1
    ) == ["  keep attack whitespace  "]


def test_harmbench_and_spikee_fail_when_successful_commands_emit_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "generate_test_cases.py").write_text("# fixture", encoding="utf-8")
    (tmp_path / "merge_test_cases.py").write_text("# fixture", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda _name: sys.executable)

    harmbench_revision = "1" * 40

    def fake_run(command, **_kwargs):
        if "rev-parse" in command:
            return subprocess.CompletedProcess(
                command, returncode=0, stdout=harmbench_revision, stderr=""
            )
        return _completed(command)

    monkeypatch.setattr(harmbench_module, "run_engine_command", fake_run)
    attackers = [
        HarmBenchAttacker(
            methods=["PEZ"],
            repo=str(tmp_path),
            upstream_revision=harmbench_revision,
        ),
        SpikeeAttacker(
            plugins=[],
            engine_runtime=_EngineRuntimeFixture(
                "spikee",
                result={},
                artifacts={"spikee-dataset.jsonl": b""},
            ),
        ),
    ]
    for attacker in attackers:
        with pytest.raises(ExternalEngineOutputError):
            list(attacker.generate(_datapoint(), _budget()))


def test_fuzzyai_fails_before_unverified_live_target_execution() -> None:
    with pytest.raises(
        ExternalEngineConformanceError, match="no pinned, documented prompt-export"
    ):
        list(FuzzyAIAttacker().generate(_datapoint(), _budget()))


@pytest.mark.parametrize("attacker", [AutoDANTurboAttacker(), GiskardAttacker()])
def test_complete_native_evaluators_reject_runner_prompt_generation(attacker) -> None:
    with pytest.raises(ExternalEngineConformanceError, match="supported through"):
        list(attacker.generate(_datapoint(), _budget()))


def test_harmbench_rejects_unrepresented_multimodal_outputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"MultiModal\*"):
        HarmBenchAttacker(methods=["MultiModalPGD"], repo=str(tmp_path))

    output = tmp_path / "test_cases.json"
    output.write_text(
        json.dumps({"behavior": [["generated.png", "adversarial text"]]}),
        encoding="utf-8",
    )
    with pytest.raises(ExternalEngineOutputError, match="multimodal test case"):
        HarmBenchAttacker._read_test_cases(output, "behavior")


def test_harmbench_rejects_duplicate_behavior_keys(tmp_path: Path) -> None:
    output = tmp_path / "test_cases.json"
    output.write_text(
        '{"behavior":["first"],"behavior":["last-wins attack"]}',
        encoding="utf-8",
    )

    with pytest.raises(ExternalEngineOutputError, match="missing or invalid"):
        HarmBenchAttacker._read_test_cases(output, "behavior")


def test_easyjailbreak_rejects_lossy_runner_replay() -> None:
    attacker = EasyJailbreakAttacker(
        recipe="Cipher",
        target_model="native-target",
        attack_model=None,
        eval_model="native-evaluator",
    )
    with pytest.raises(ExternalEngineConformanceError, match="import_run"):
        list(attacker.generate(_datapoint(), _budget()))


@pytest.mark.parametrize(
    "attacker",
    [PetriAttacker(), IDEATORAttacker()],
)
def test_other_unverified_bridges_fail_before_scored_execution(attacker) -> None:
    with pytest.raises(ExternalEngineConformanceError):
        list(attacker.generate(_datapoint(), _budget()))


def test_t3mp3st_uses_only_pinned_loopback_plan_and_materialises_safe_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_post(endpoint, body, *, timeout_seconds):
        observed.update({
            "endpoint": endpoint,
            "body": body,
            "timeout_seconds": timeout_seconds,
        })
        return _t3_response()

    monkeypatch.setattr(t3mp3st_module, "_post_plan", fake_post)
    attacker = T3MP3STAttacker(
        upstream_revision="a" * 40,
        source_provider="local",
        source_model="frozen-planner",
    )
    attempts = list(attacker.generate(_datapoint(), _budget(seed=9)))

    assert observed["endpoint"] == "http://127.0.0.1:3333/api/general/plan"
    body = observed["body"]
    assert isinstance(body, dict)
    assert body["objective"] == "harmful seed request"
    assert body["urgency"] == "low" and body["opsecPreference"] == "silent"
    assert "PLANNING ONLY" in body["constraints"]
    assert "Synthetic LLM-evaluation scope only" in body["scopeHints"]
    assert "/execute" not in str(observed) and "/auto" not in str(observed)
    assert [attempt.rendered_input[-1].content for attempt in attempts] == [
        "Synthetic planning probe 0",
        "Synthetic planning probe 1",
    ]
    assert all(attempt.strategy == "op-general-safe-probe" for attempt in attempts)
    assert all(attempt.params["source_model_conditioned"] is True for attempt in attempts)
    assert all(attempt.params["tools_executed"] is False for attempt in attempts)
    assert all(attempt.params["mission_started"] is False for attempt in attempts)
    assert attempts[0].params["plan"] == _t3_response()["plan"]


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:3333/api/general/plan",
        "http://localhost:3333/api/general/plan",
        "http://192.168.1.2:3333/api/general/plan",
        "http://127.0.0.1:3333/api/general/execute",
        "http://127.0.0.1:3333/api/general/plan?next=/execute",
        "http://user:password@127.0.0.1:3333/api/general/plan",
    ],
)
def test_t3mp3st_endpoint_is_literal_loopback_plan_only(endpoint: str) -> None:
    with pytest.raises(ValueError):
        T3MP3STAttacker(endpoint=endpoint)


def test_t3mp3st_replay_artifact_is_pinned_and_request_bound(tmp_path: Path) -> None:
    attacker = T3MP3STAttacker(
        upstream_revision="b" * 40,
        source_provider="local",
        source_model="frozen-planner",
        response_artifact=tmp_path / "plan.json",
    )
    wrapper = {
        "format_version": "ura-t3mp3st-plan-replay/1",
        "upstream_revision": "b" * 40,
        "request": attacker._request_body(_datapoint()),
        "response": _t3_response(),
    }
    assert attacker.response_artifact is not None
    attacker.response_artifact.write_text(json.dumps(wrapper), encoding="utf-8")
    attempts = list(attacker.generate(_datapoint(), _budget()))
    source = attempts[0].params["response_source"]
    assert source["mode"] == "precomputed_response"
    assert "path" not in source
    assert len(source["sha256"]) == 64 and source["bytes"] > 0
    manifest = _runner(attacker).plan_manifest([_datapoint()])
    attacker_config = manifest.config["components"]["attacker"]
    assert "response_artifact" not in attacker_config
    assert attacker_config["response_artifact_identity"] == {
        "sha256": source["sha256"],
        "bytes": source["bytes"],
        "format_version": "ura-t3mp3st-plan-replay/1",
    }
    copied_path = tmp_path / "same-plan-different-path.json"
    copied_path.write_bytes(attacker.response_artifact.read_bytes())
    copied_attacker = T3MP3STAttacker(
        upstream_revision="b" * 40,
        source_provider="local",
        source_model="frozen-planner",
        response_artifact=copied_path,
    )
    copied_manifest = _runner(copied_attacker).plan_manifest([_datapoint()])
    assert copied_manifest.config["components"]["attacker"] == attacker_config
    copied_attempts = list(copied_attacker.generate(_datapoint(), _budget()))
    assert [row.model_dump(mode="json") for row in copied_attempts] == [
        row.model_dump(mode="json") for row in attempts
    ]

    wrapper["request"]["objective"] = "different row"
    attacker.response_artifact.write_text(json.dumps(wrapper), encoding="utf-8")
    with pytest.raises(ExternalEngineOutputError, match="does not match"):
        list(attacker.generate(_datapoint(), _budget()))
    with pytest.raises(ExternalEngineOutputError, match="does not match"):
        _runner(attacker).plan_manifest([_datapoint()])


def test_measured_t3mp3st_requires_precomputed_response_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        t3mp3st_module,
        "_post_plan",
        lambda *_args, **_kwargs: pytest.fail("measured run reached live planning"),
    )
    attacker = T3MP3STAttacker(
        upstream_revision="d" * 40,
        source_provider="local",
        source_model="planner",
    )

    with pytest.raises(ExternalEngineConformanceError, match="response_artifact"):
        _runner(attacker).run([_datapoint()])


def test_measured_harmbench_generation_fails_during_manifest_admission() -> None:
    attacker = HarmBenchAttacker(
        methods=["PEZ"],
        upstream_revision="f" * 40,
    )

    with pytest.raises(ExternalEngineConformanceError, match="harmbench_capture"):
        _runner(attacker).plan_manifest([_datapoint()])


def test_t3mp3st_seed_provenance_does_not_claim_source_seed_control(
    tmp_path: Path,
) -> None:
    attacker = T3MP3STAttacker(
        upstream_revision="e" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=tmp_path / "plan.json",
    )
    wrapper = {
        "format_version": "ura-t3mp3st-plan-replay/1",
        "upstream_revision": "e" * 40,
        "request": attacker._request_body(_datapoint()),
        "response": _t3_response(),
    }
    assert attacker.response_artifact is not None
    attacker.response_artifact.write_text(json.dumps(wrapper), encoding="utf-8")

    attempt = list(attacker.generate(_datapoint(), _budget(seed=37)))[0]

    assert attempt.seed == 37
    assert attempt.params["source_generation_seed"] is None
    assert attempt.params["source_generation_seed_control"] == (
        "not_exposed_by_op_general_plan_api"
    )
    assert attempt.params["runner_seed_role"] == (
        "target_sampling_and_unit_identity_only"
    )


@pytest.mark.parametrize("mutation", ["fallback", "no_orders", "gate_mismatch"])
def test_t3mp3st_rejects_degraded_or_inconsistent_upstream_contract(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    response = _t3_response(
        codename="OPERATION FALLBACK" if mutation == "fallback" else "OPERATION LAB"
    )
    if mutation == "no_orders":
        response["plan"]["workOrders"] = []
    elif mutation == "gate_mismatch":
        response["missionGate"] = {**response["missionGate"], "score": 81}
    monkeypatch.setattr(
        t3mp3st_module,
        "_post_plan",
        lambda *_args, **_kwargs: response,
    )
    attacker = T3MP3STAttacker(
        upstream_revision="c" * 40,
        source_provider="local",
        source_model="frozen-planner",
    )
    with pytest.raises(ExternalEngineOutputError):
        list(attacker.generate(_datapoint(), _budget()))


def test_t3mp3st_capture_bundle_round_trips_exact_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    points = _t3_points()
    calls: list[tuple[str, dict[str, object], float]] = []

    def fake_post(endpoint, body, *, timeout_seconds):
        calls.append((endpoint, body, timeout_seconds))
        return _t3_response()

    monkeypatch.setattr(t3mp3st_module, "_post_plan", fake_post)
    descriptor = capture_t3mp3st_bundle(
        points,
        endpoint="http://127.0.0.1:3333/api/general/plan",
        upstream_revision="1" * 40,
        source_provider="local",
        source_model="frozen-planner",
        output_directory=tmp_path / "nested" / "capture",
        timeout_seconds=12,
    )

    artifact = Path(str(descriptor["artifact"]))
    assert artifact.is_absolute()
    assert artifact.name == f"t3mp3st-plan-bundle-{descriptor['sha256']}.json"
    assert descriptor["records"] == 2
    assert len(calls) == 2
    assert all(call[0] == "http://127.0.0.1:3333/api/general/plan" for call in calls)
    assert all(call[2] == 12 for call in calls)

    attacker = T3MP3STAttacker(
        upstream_revision="1" * 40,
        source_provider="local",
        source_model="frozen-planner",
        response_artifact=artifact,
        response_artifact_sha256=str(descriptor["sha256"]),
    )
    manifest = _runner(attacker).plan_manifest(points)
    identity = manifest.config["components"]["attacker"]["response_artifact_identity"]
    assert identity["sha256"] == descriptor["sha256"]
    assert identity["records"] == 2
    assert "response_artifact" not in manifest.config["components"]["attacker"]
    assert str(tmp_path) not in json.dumps(
        manifest.config["components"]["attacker"], sort_keys=True
    )
    for point in points:
        attempts = list(attacker.generate(point, _budget()))
        assert attempts[0].params["response_source"]["mode"] == "precomputed_bundle"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate", "duplicate DataPoint id"),
        ("orphan", "missing .*; orphan"),
        ("request_mismatch", "request mismatch"),
        ("response_tamper", "response hash mismatch"),
        ("future", "future format"),
    ],
)
def test_t3mp3st_bundle_fails_closed_on_invalid_complete_mapping(
    tmp_path: Path, mutation: str, message: str
) -> None:
    points = _t3_points()
    bundle = build_plan_bundle(
        points,
        [_t3_response(), _t3_response()],
        upstream_revision="2" * 40,
        source_provider="local",
        source_model="planner",
    )
    entries = bundle["entries"]
    assert isinstance(entries, list)
    if mutation == "duplicate":
        entries[1]["datapoint_id"] = entries[0]["datapoint_id"]
    elif mutation == "orphan":
        entries[1]["datapoint_id"] = "orphan-row"
    elif mutation == "request_mismatch":
        request = entries[1]["request"]
        assert isinstance(request, dict)
        request["objective"] = "different objective"
        entries[1]["request_sha256"] = hashlib.sha256(
            json.dumps(
                request,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    elif mutation == "response_tamper":
        entries[1]["response"]["plan"]["workOrders"][0]["safeProbe"] = "tampered"
    elif mutation == "future":
        bundle["format_version"] = "ura-t3mp3st-plan-bundle/2"
    path = tmp_path / f"{mutation}.json"
    digest = _write_t3_json(path, bundle)
    attacker = T3MP3STAttacker(
        upstream_revision="2" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=path,
        response_artifact_sha256=digest,
    )
    with pytest.raises(ExternalEngineOutputError, match=message):
        _runner(attacker).plan_manifest(points)


def test_t3mp3st_bundle_requires_external_byte_identity_and_rejects_tamper(
    tmp_path: Path,
) -> None:
    points = _t3_points()
    bundle = build_plan_bundle(
        points,
        [_t3_response(), _t3_response()],
        upstream_revision="3" * 40,
        source_provider="local",
        source_model="planner",
    )
    path = tmp_path / "bundle.json"
    digest = _write_t3_json(path, bundle)
    unpinned = T3MP3STAttacker(
        upstream_revision="3" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=path,
    )
    with pytest.raises(ExternalEngineConformanceError, match="artifact_sha256"):
        _runner(unpinned).plan_manifest(points)

    path.write_bytes(path.read_bytes() + b" ")
    pinned = T3MP3STAttacker(
        upstream_revision="3" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=path,
        response_artifact_sha256=digest,
    )
    with pytest.raises(ExternalEngineOutputError, match="bytes do not match"):
        _runner(pinned).plan_manifest(points)


def test_t3mp3st_replay_parser_rejects_duplicate_json_object_keys(
    tmp_path: Path,
) -> None:
    attacker = T3MP3STAttacker(
        upstream_revision="4" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=tmp_path / "duplicate.json",
    )
    wrapper = {
        "format_version": "ura-t3mp3st-plan-replay/1",
        "upstream_revision": "4" * 40,
        "request": attacker._request_body(_datapoint()),
        "response": _t3_response(),
    }
    raw = json.dumps(wrapper, sort_keys=True, separators=(",", ":"))
    raw = raw.replace(
        '"format_version":"ura-t3mp3st-plan-replay/1"',
        '"format_version":"ura-t3mp3st-plan-replay/1",'
        '"format_version":"ura-t3mp3st-plan-replay/1"',
        1,
    )
    assert attacker.response_artifact is not None
    attacker.response_artifact.write_text(raw, encoding="utf-8")
    with pytest.raises(ExternalEngineOutputError, match="valid UTF-8 JSON"):
        _runner(attacker).plan_manifest([_datapoint()])

    points = _t3_points()
    bundle = build_plan_bundle(
        points,
        [_t3_response(), _t3_response()],
        upstream_revision="4" * 40,
        source_provider="local",
        source_model="planner",
    )
    bundle_raw = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    bundle_raw = bundle_raw.replace(
        '"source_model":"planner"',
        '"source_model":"planner","source_model":"planner"',
        1,
    )
    bundle_path = tmp_path / "duplicate-bundle.json"
    bundle_path.write_text(bundle_raw, encoding="utf-8")
    bundle_attacker = T3MP3STAttacker(
        upstream_revision="4" * 40,
        source_provider="local",
        source_model="planner",
        response_artifact=bundle_path,
        response_artifact_sha256=hashlib.sha256(bundle_raw.encode("utf-8")).hexdigest(),
    )
    with pytest.raises(ExternalEngineOutputError, match="valid UTF-8 JSON"):
        _runner(bundle_attacker).plan_manifest(points)


def test_t3mp3st_capture_rejects_duplicate_rows_before_http(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    points = _t3_points()
    points[1] = points[1].model_copy(update={"id": points[0].id})
    monkeypatch.setattr(
        t3mp3st_module,
        "_post_plan",
        lambda *_args, **_kwargs: pytest.fail("duplicate selection reached HTTP"),
    )
    with pytest.raises(ExternalEngineConformanceError, match="duplicate DataPoint id"):
        capture_t3mp3st_bundle(
            points,
            endpoint="http://127.0.0.1:3333/api/general/plan",
            upstream_revision="5" * 40,
            source_provider="local",
            source_model="planner",
            output_directory=tmp_path,
        )


def test_t3mp3st_strict_input_list_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "rows.json"
    row = _datapoint().model_dump_json()
    path.write_text(f'[{row[:-1]},"id":"duplicate"}}]', encoding="utf-8")
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        load_t3mp3st_input_list(path)


def test_t3mp3st_capture_cli_writes_machine_readable_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "selection.json"
    input_path.write_text(
        json.dumps([point.model_dump(mode="json") for point in _t3_points()]),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        t3mp3st_module,
        "_post_plan",
        lambda *_args, **_kwargs: _t3_response(),
    )

    assert t3mp3st_capture_module.main([
        "--input", str(input_path),
        "--endpoint", "http://127.0.0.1:3333/api/general/plan",
        "--upstream-revision", "6" * 40,
        "--source-provider", "local",
        "--source-model", "planner",
        "--timeout-seconds", "10",
        "--out", str(tmp_path / "captures"),
    ]) == 0

    completion = json.loads(capsys.readouterr().out)
    assert completion["format_version"] == "ura-t3mp3st-plan-bundle/1"
    assert completion["records"] == 2
    assert Path(completion["artifact"]).is_file()
    assert Path(completion["artifact"]).name.endswith(
        f"{completion['sha256']}.json"
    )


def test_purplellama_is_exact_cyberseceval_identity_replay() -> None:
    media = MediaRef(
        modality="image",
        uri="data:image/png;base64,AA==",
        sha256="6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        mime="image/png",
    )
    point = DataPoint(
        id="cyberseceval:visual-prompt-injection:1",
        source="cyberseceval",
        modalities=["text", "image"],
        dialog_history=[
            DialogTurn(role="system", content="Describe only the supplied image."),
            DialogTurn(role="user", content="What is shown?", media=[media]),
        ],
        payload_text="What is shown?",
        media=[media],
        risk_category=RiskCategory.PROMPT_INJECTION_INDIRECT,
        expected_behavior="safe_answer",
        meta={"dataset": "visual_prompt_injection"},
    )
    before = [turn.model_dump(mode="json") for turn in point.dialog_history]
    attempt = list(PurpleLlamaAttacker().generate(point, _budget(seed=4)))[0]
    assert [turn.model_dump(mode="json") for turn in attempt.rendered_input] == before
    assert attempt.rendered_input[1].media[0] == media
    assert attempt.params["source_bound"] is True
    assert attempt.params["native_purplellama_runner_executed"] is False
    assert attempt.params["attack_generated"] is False

    with pytest.raises(ExternalEngineConformanceError, match="source=='cyberseceval'"):
        list(PurpleLlamaAttacker().generate(_datapoint(), _budget()))

    lossy = point.model_copy(update={
        "dialog_history": [DialogTurn(role="user", content="Image omitted")]
    })
    with pytest.raises(ExternalEngineOutputError, match="lossy"):
        list(PurpleLlamaAttacker().generate(lossy, _budget()))


def test_asb_direct_and_observation_injection_risks_are_not_conflated() -> None:
    assert asb_module._RISK_BY_CLASS["dpi"] == "jailbreak"
    assert asb_module._RISK_BY_CLASS["opi"] == "prompt_injection_indirect"


def test_generators_fail_closed_on_empty_or_invalid_output() -> None:
    attackers = [
        H4rm3lAttacker(
            programs=["Base64Decorator()"],
            engine_runtime=_EngineRuntimeFixture(
                "h4rm3l",
                result={
                    "rendered": [{"program": "Base64Decorator()", "text": "  "}]
                },
            ),
        ),
        IDEATORAttacker(seed_pairs=[]),
    ]
    for attacker in attackers:
        with pytest.raises(ExternalEngineOutputError):
            list(attacker.generate(_datapoint(), _budget()))


def test_h4rm3l_rejects_partial_program_survivor_sets() -> None:
    attacker = H4rm3lAttacker(
        programs=["ProgramOne()", "ProgramTwo()"],
        engine_runtime=_EngineRuntimeFixture(
            "h4rm3l",
            result={
                "rendered": [
                    {"program": "ProgramOne()", "text": "decorated::seed"}
                ]
            },
        ),
    )

    with pytest.raises(ExternalEngineOutputError, match="incomplete program set"):
        list(attacker.generate(_datapoint(), _budget()))


def test_h4rm3l_rejects_identity_transform() -> None:
    with pytest.raises(ExternalEngineOutputError, match="unchanged seed"):
        list(
            H4rm3lAttacker(
                programs=["IdentityDecorator()"],
                engine_runtime=_EngineRuntimeFixture(
                    "h4rm3l",
                    result={
                        "rendered": [
                            {
                                "program": "IdentityDecorator()",
                                "text": "harmful seed request",
                            }
                        ]
                    },
                ),
            )
            .generate(_datapoint(), _budget())
        )


def test_h4rm3l_requires_exact_pinned_package_version() -> None:
    with pytest.raises(ValueError, match="pinned to 0.2.4"):
        H4rm3lAttacker(
            programs=["Base64Decorator()"],
            engine_version="0.2.3",
        )


class _EmptyAttacker(BaseAttacker):
    name = "empty"

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return text_only_transfer_contract(
            self.name,
            datapoint,
            budget,
            planned_turns=min(budget.max_queries, budget.max_turns),
            turn_count_semantics="upper_bound",
        )

    def generate(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> Iterable[Attempt]:
        return ()


class _EmptySession(AttackSession):
    def next_attempt(self, previous_response: Response | None) -> Attempt | None:
        return None


class _EmptyStatefulAttacker(_EmptyAttacker):
    name = "empty-stateful"

    def start_session(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackSession:
        return _EmptySession()


def _runner(attacker: BaseAttacker, seeds: list[int] | None = None) -> Runner:
    selected = seeds or [0]
    return Runner(
        attacker,
        MockTarget(),
        JudgeCascade([RuleJudge()]),
        AttackBudget(max_queries=2, max_turns=2, seed=selected[0]),
        selected,
    )


def test_runner_rejects_empty_corpus_in_plan_and_execution() -> None:
    runner = _runner(_EmptyAttacker())
    with pytest.raises(ValueError, match="at least one datapoint"):
        runner.plan_manifest([])
    with pytest.raises(ValueError, match="at least one datapoint"):
        runner.run([])


@pytest.mark.parametrize("attacker", [_EmptyAttacker(), _EmptyStatefulAttacker()])
def test_runner_rejects_zero_attempts_per_datapoint_and_seed(
    attacker: BaseAttacker,
) -> None:
    with pytest.raises(ValueError, match="produced no executable attempt"):
        _runner(attacker, seeds=[7, 11]).run([_datapoint()])
