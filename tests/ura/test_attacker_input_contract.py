"""Prospective attacker-input contracts fail before target execution."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from ura.adapters.base import AttackBudget, BaseAttacker
from ura.adapters.crescendo import CrescendoAttacker
from ura.adapters.deepteam import DeepTeamAttacker
from ura.adapters.h4rm3l import H4rm3lAttacker
from ura.adapters.harmbench import HarmBenchAttacker
from ura.adapters.ideator import IDEATORAttacker
from ura.adapters.nanogcg import NanoGCGAttacker
from ura.adapters.purplellama import PurpleLlamaAttacker
from ura.adapters.pyrit import PyRITAttacker
from ura.adapters.replay import ReplayAttacker
from ura.adapters.spikee import SpikeeAttacker
from ura.adapters.t3mp3st import T3MP3STAttacker
from ura.attacker_input_contract import (
    AttackerInputContract,
    AttackerInputContractError,
    attacker_input_payload_sha256,
    deserialize_attacker_input_contract,
    deserialize_attacker_input_plan,
    grid_attacker_input_plan_payload,
    validate_attempts_against_attacker_input_plan,
)
from ura.data_models import (
    Attempt,
    DataPoint,
    DialogTurn,
    Judgment,
    MediaRef,
    Response,
    RiskCategory,
    ToolCall,
)


_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _budget(turns: int = 4) -> AttackBudget:
    return AttackBudget(max_queries=turns, max_turns=turns, seed=0)


def _text_datapoint(*, source: str = "unit") -> DataPoint:
    return DataPoint(
        id=f"{source}-text",
        source=source,
        modalities=["text"],
        dialog_history=[DialogTurn(role="user", content="source objective")],
        payload_text="source objective",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _tool_datapoint(*, source: str = "unit") -> DataPoint:
    return DataPoint(
        id=f"{source}-tool",
        source=source,
        modalities=["text", "tool"],
        dialog_history=[
            DialogTurn(role="user", content="use the tool"),
            DialogTurn(
                role="assistant",
                content="calling",
                tool_call=ToolCall(name="shell", arguments={"cmd": "noop"}),
            ),
        ],
        payload_text="use the tool",
        risk_category=RiskCategory.AGENTIC_MISUSE,
        expected_behavior="refuse",
        is_agentic=True,
    )


def _media(path: Path, payload: bytes) -> MediaRef:
    path.write_bytes(payload)
    return MediaRef(
        modality="image",
        path=str(path),
        sha256=hashlib.sha256(payload).hexdigest(),
        mime="image/png",
    )


def _image_datapoint(tmp_path: Path, *, complete_dialog: bool) -> DataPoint:
    first = _media(tmp_path / "first.png", _PNG)
    second = _media(tmp_path / "second.png", _PNG + b"distinct")
    return DataPoint(
        id="unit-image",
        source="unit",
        modalities=["text", "image"],
        dialog_history=[
            DialogTurn(
                role="user",
                content="source objective",
                media=[first, second] if complete_dialog else [first],
            )
        ],
        payload_text="source objective",
        media=[first, second],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _runner_attackers(image_path: Path) -> list[BaseAttacker]:
    return [
        ReplayAttacker(),
        CrescendoAttacker(),
        PyRITAttacker(),
        DeepTeamAttacker(),
        T3MP3STAttacker(),
        NanoGCGAttacker(suffix=" !suffix", suffix_source="unit"),
        H4rm3lAttacker(),
        SpikeeAttacker(),
        IDEATORAttacker(seed_pairs=[("paired text", str(image_path))]),
        PurpleLlamaAttacker(),
        HarmBenchAttacker(methods=["DirectRequest"]),
    ]


def test_all_runner_attackers_reject_tool_source_before_a_target_contract(
    tmp_path: Path,
) -> None:
    image_path = tmp_path / "ideator.png"
    image_path.write_bytes(_PNG)
    for attacker in _runner_attackers(image_path):
        source = "cyberseceval" if attacker.name == "purplellama" else "unit"
        with pytest.raises(
            AttackerInputContractError, match="typed tool runtime.*before any target call"
        ):
            attacker.plan_target_inputs(_tool_datapoint(source=source), _budget())


def test_replay_rejects_loss_of_second_same_modality_asset(tmp_path: Path) -> None:
    datapoint = _image_datapoint(tmp_path, complete_dialog=False)
    with pytest.raises(AttackerInputContractError, match="omit top-level source media"):
        ReplayAttacker().plan_target_inputs(datapoint, _budget())


def test_replay_rejects_loss_of_repeated_identical_asset(tmp_path: Path) -> None:
    repeated = _media(tmp_path / "repeated.png", _PNG)
    datapoint = DataPoint(
        id="unit-repeated-image",
        source="unit",
        modalities=["text", "image"],
        dialog_history=[
            DialogTurn(role="user", content="source objective", media=[repeated])
        ],
        payload_text="source objective",
        media=[repeated, repeated],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    with pytest.raises(AttackerInputContractError, match="omit top-level source media"):
        ReplayAttacker().plan_target_inputs(datapoint, _budget())


def test_replay_preserves_ordered_repeated_identical_asset_occurrences(
    tmp_path: Path,
) -> None:
    repeated = _media(tmp_path / "twice.png", _PNG)
    datapoint = DataPoint(
        id="unit-repeated-delivery",
        source="unit",
        modalities=["text", "image"],
        dialog_history=[
            DialogTurn(
                role="user", content="source objective", media=[repeated, repeated]
            )
        ],
        payload_text="source objective",
        media=[repeated, repeated],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    contract = ReplayAttacker().plan_target_inputs(datapoint, _budget())
    assert len(contract.source_media) == 1
    assert contract.source_media_occurrences == (
        contract.source_media[0].media_id,
        contract.source_media[0].media_id,
    )
    assert contract.turns[0].media_ids == contract.source_media_occurrences


@pytest.mark.parametrize(
    "attacker",
    [
        PyRITAttacker(),
        DeepTeamAttacker(),
        T3MP3STAttacker(),
        NanoGCGAttacker(suffix=" !suffix", suffix_source="unit"),
        H4rm3lAttacker(),
        SpikeeAttacker(),
        HarmBenchAttacker(methods=["DirectRequest"]),
    ],
    ids=lambda attacker: attacker.name,
)
def test_text_transfer_bridges_reject_physical_source_before_generation(
    attacker: BaseAttacker, tmp_path: Path
) -> None:
    with pytest.raises(AttackerInputContractError, match="text-only source"):
        attacker.plan_target_inputs(
            _image_datapoint(tmp_path, complete_dialog=True), _budget()
        )


def test_crescendo_declares_setup_and_evaluable_physical_combinations(
    tmp_path: Path,
) -> None:
    contract = CrescendoAttacker().plan_target_inputs(
        _image_datapoint(tmp_path, complete_dialog=True), _budget(4)
    )
    assert [turn.combination for turn in contract.turns] == [
        ("text",),
        ("text",),
        ("text", "image"),
        ("text", "image"),
    ]
    assert [turn.policy_evaluable for turn in contract.turns] == [
        False,
        False,
        True,
        True,
    ]
    source_ids = {item.media_id for item in contract.source_media}
    assert len(source_ids) == 2
    assert set(contract.turns[2].media_ids) == source_ids
    assert set(contract.turns[3].media_ids) == source_ids
    assert len(contract.turns[2].media_ids) == 2
    assert len(contract.turns[3].media_ids) == 4


def test_identity_replay_contract_binds_every_source_media_identity(
    tmp_path: Path,
) -> None:
    contract = ReplayAttacker().plan_target_inputs(
        _image_datapoint(tmp_path, complete_dialog=True), _budget()
    )
    assert contract.source_combination == ("text", "image")
    assert contract.turns[0].combination == ("text", "image")
    assert contract.turns[0].source_media_policy == "all"
    assert set(contract.turns[0].media_ids) == {
        item.media_id for item in contract.source_media
    }


def test_ideator_contract_hashes_generated_image_and_exposes_no_path(
    tmp_path: Path,
) -> None:
    image_path = tmp_path / "ideator-seed.png"
    image_path.write_bytes(_PNG)
    attacker = IDEATORAttacker(seed_pairs=[["paired text", str(image_path)]])
    contract = attacker.plan_target_inputs(_text_datapoint(), _budget(1))
    assert contract.source_combination == ("text",)
    assert contract.turns[0].combination == ("text", "image")
    assert contract.generated_media[0].sha256 == hashlib.sha256(_PNG).hexdigest()
    assert contract.generated_media[0].bytes == len(_PNG)
    assert contract.turns[0].bound_text_sha256 == hashlib.sha256(
        b"paired text"
    ).hexdigest()
    assert contract.turns[0].bound_text_bytes == len(b"paired text")
    assert str(image_path) not in repr(contract.manifest_payload())
    attempt = list(attacker.generate(_text_datapoint(), _budget(1)))[0]
    assert attempt.rendered_input[-1].media[0].sha256 == contract.generated_media[0].sha256
    assert str(image_path) not in repr(attempt.params)
    assert attempt.params["image_identity"]["sha256"] == contract.generated_media[0].sha256


def test_ideator_contract_preserves_repeated_generated_image_occurrences(
    tmp_path: Path,
) -> None:
    image_path = tmp_path / "reused-seed.png"
    image_path.write_bytes(_PNG)
    attacker = IDEATORAttacker(
        seed_pairs=[
            ("paired text one", str(image_path)),
            ("paired text two", str(image_path)),
        ]
    )
    contract = attacker.plan_target_inputs(_text_datapoint(), _budget(2))
    assert len(contract.generated_media) == 1
    assert contract.turns[0].media_ids == contract.turns[1].media_ids
    attempts = list(attacker.generate(_text_datapoint(), _budget(2)))
    assert len(attempts) == 2
    assert [item.rendered_input[-1].media[0].sha256 for item in attempts] == [
        contract.generated_media[0].sha256,
        contract.generated_media[0].sha256,
    ]


def test_all_runner_adapters_expose_a_path_free_text_contract(tmp_path: Path) -> None:
    image_path = tmp_path / "ideator.png"
    image_path.write_bytes(_PNG)
    expected = {
        "replay": (1, "exact"),
        "crescendo": (4, "exact"),
        "pyrit": (1, "exact"),
        "deepteam": (1, "exact"),
        "t3mp3st": (4, "upper_bound"),
        "nanogcg": (1, "exact"),
        "h4rm3l": (4, "exact"),
        "spikee": (4, "upper_bound"),
        "ideator": (1, "exact"),
        "purplellama": (1, "exact"),
        "harmbench": (1, "exact"),
    }
    for attacker in _runner_attackers(image_path):
        source = "cyberseceval" if attacker.name == "purplellama" else "unit"
        contract = attacker.plan_target_inputs(_text_datapoint(source=source), _budget())
        turns, semantics = expected[attacker.name]
        assert len(contract.turns) == turns
        assert contract.turn_count_semantics == semantics
        assert contract.contract_id.startswith("attacker-input-")
        assert contract.manifest_payload()["contract_id"] == contract.contract_id


def test_strict_contract_and_plan_deserializers_recompute_all_identities() -> None:
    contract = ReplayAttacker().plan_target_inputs(_text_datapoint(), _budget(1))
    payload = contract.manifest_payload()
    assert deserialize_attacker_input_contract(payload) == contract

    runner_plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **payload}],
    }
    digest = attacker_input_payload_sha256(runner_plan)
    assert deserialize_attacker_input_plan(
        runner_plan, expected_sha256=digest
    ) == {("replay", contract.datapoint_id, 0): contract}

    grid_plan = grid_attacker_input_plan_payload({
        ("arm", "replay", contract.datapoint_id, 0): contract
    })
    assert deserialize_attacker_input_plan(grid_plan) == {
        ("arm", "replay", contract.datapoint_id, 0): contract
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda plan: plan["entries"][0].update({"seed": True}),
        lambda plan: plan["entries"][0].update({"unexpected": "field"}),
        lambda plan: plan["entries"][0]["turns"][0].update(
            {"combination": ["text", "image"]}
        ),
        lambda plan: plan["entries"].append(deepcopy(plan["entries"][0])),
    ],
    ids=("strict-seed-type", "extra-field", "stale-contract-id", "duplicate-key"),
)
def test_strict_plan_deserializer_rejects_schema_id_and_duplicate_mutations(
    mutation,
) -> None:
    contract = ReplayAttacker().plan_target_inputs(_text_datapoint(), _budget(1))
    plan = grid_attacker_input_plan_payload({
        ("arm", "replay", contract.datapoint_id, 0): contract
    })
    mutation(plan)
    unsigned = {"schema": plan["schema"], "entries": plan["entries"]}
    plan["sha256"] = attacker_input_payload_sha256(unsigned)
    with pytest.raises(AttackerInputContractError):
        deserialize_attacker_input_plan(plan)


def test_strict_plan_deserializer_rejects_stale_external_and_embedded_sha() -> None:
    contract = ReplayAttacker().plan_target_inputs(_text_datapoint(), _budget(1))
    runner_plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **contract.manifest_payload()}],
    }
    with pytest.raises(AttackerInputContractError, match="external SHA-256"):
        deserialize_attacker_input_plan(runner_plan, expected_sha256="0" * 64)

    grid_plan = grid_attacker_input_plan_payload({
        ("arm", "replay", contract.datapoint_id, 0): contract
    })
    grid_plan["sha256"] = "0" * 64
    with pytest.raises(AttackerInputContractError, match="SHA-256/content"):
        deserialize_attacker_input_plan(grid_plan)


def test_all_eleven_runner_adapters_rejoin_realized_attempts_to_their_plan(
    tmp_path: Path,
) -> None:
    image_path = tmp_path / "ideator-positive.png"
    image_path.write_bytes(_PNG)
    for attacker in _runner_attackers(image_path):
        source = "cyberseceval" if attacker.name == "purplellama" else "unit"
        contract = attacker.plan_target_inputs(
            _text_datapoint(source=source), _budget(4)
        )
        media_by_id = {
            item.media_id: item
            for item in (*contract.source_media, *contract.generated_media)
        }
        attempts: list[Attempt] = []
        responses: list[Response] = []
        judgments: list[Judgment] = []
        for turn in contract.turns:
            media = [
                MediaRef(
                    modality=media_by_id[media_id].modality,
                    path=media_by_id[media_id].delivery_path or str(image_path),
                    sha256=media_by_id[media_id].sha256,
                    mime=media_by_id[media_id].mime,
                )
                for media_id in turn.media_ids
            ]
            content = (
                "paired text"
                if turn.bound_text_sha256 is not None
                else "realized challenge"
            )
            attempt = _attempt_for_planned_turn(
                contract,
                turn.logical_turn,
                content=content,
                media=media,
            )
            response, judgment = _response_and_judgment(contract, attempt)
            attempts.append(attempt)
            responses.append(response)
            judgments.append(judgment)
        plan = {
            "schema": "ura-attacker-input-plan/1",
            "entries": [{"seed": 0, **contract.manifest_payload()}],
        }
        contracts = validate_attempts_against_attacker_input_plan(
            plan,
            attempts,
            responses,
            judgments,
            target_modalities=("text", "image"),
            expected_sha256=attacker_input_payload_sha256(plan),
            expected_count=1,
        )
        assert set(contracts) == {
            (attacker.name, f"{source}-text", 0)
        }


def _attempt_for_planned_turn(
    contract: AttackerInputContract,
    logical_turn: int,
    *,
    content: str = "realized challenge",
    media: list[MediaRef] | None = None,
) -> Attempt:
    turn = contract.turns[logical_turn]
    stateful = contract.attacker == "crescendo"
    evaluable_turns = [
        item.logical_turn for item in contract.turns if item.policy_evaluable
    ]
    challenge_index = (
        evaluable_turns.index(logical_turn)
        if stateful and turn.policy_evaluable
        else (None if stateful else 0)
    )
    challenge_horizon = len(evaluable_turns) if stateful else 1
    behavior = "refuse" if turn.policy_evaluable else "comply_safely"
    return Attempt(
        id=f"{contract.datapoint_id}::{contract.attacker}::s0::t{logical_turn}",
        datapoint_id=contract.datapoint_id,
        attacker=contract.attacker,
        target="fixture-target",
        turn_index=logical_turn,
        rendered_input=[DialogTurn(
            role="user",
            content=content if "text" in turn.combination else None,
            media=list(media or []),
        )],
        seed=0,
        params={
            "attacker_input_contract_id": contract.contract_id,
            "planned_target_input": turn.manifest_payload(),
            "policy_evaluable_turn": turn.policy_evaluable,
            "policy_challenge_index": challenge_index,
            "policy_challenge_horizon": challenge_horizon,
            "turn_expected_behavior": behavior,
            "planning_expected_behavior": "refuse",
            "planning_exact_modality_combination": list(
                contract.source_combination
            ),
            "response_conditioned": stateful,
            "replayed_transcript": False,
            "attack_fingerprint": f"fingerprint-{logical_turn}",
            "transfer_key": f"transfer-{logical_turn}",
            "transferable": not stateful,
        },
        run_id="fixture-run",
    )


def _label(combination: tuple[str, ...]) -> str:
    for modality in ("video", "audio", "image"):
        if modality in combination:
            return modality
    return "tool" if "tool" in combination else "text"


def _response_and_judgment(
    contract: AttackerInputContract,
    attempt: Attempt,
    *,
    label: str = "safe",
    cascade_confident: bool = False,
    target_modalities: tuple[str, ...] = ("text", "image"),
) -> tuple[Response, Judgment]:
    turn = contract.turns[attempt.turn_index]
    source_modality = _label(contract.source_combination)
    delivered_modality = _label(turn.combination)
    effective_modality = (
        delivered_modality if delivered_modality in target_modalities else "text"
    )
    response = Response(
        attempt_id=attempt.id,
        target="fixture-target",
        output_turns=[DialogTurn(role="assistant", content="safe response")],
        raw={
            "run_id": "fixture-run",
            "attack_fingerprint": attempt.params["attack_fingerprint"],
            "transfer_key": attempt.params["transfer_key"],
            "transferable": attempt.params["transferable"],
            "requested_seed": 0,
            "target_sampling_control": "fixture",
        },
        run_id="fixture-run",
    )
    raw = {
        "run_id": "fixture-run",
        "datapoint_id": attempt.datapoint_id,
        "attacker": attempt.attacker,
        "seed": 0,
        "turn_index": attempt.turn_index,
        "target": "fixture-target",
        "model": "fixture-target",
        "attack_fingerprint": attempt.params["attack_fingerprint"],
        "transfer_key": attempt.params["transfer_key"],
        "transferable": attempt.params["transferable"],
        "response_conditioned": attempt.params["response_conditioned"],
        "replayed_transcript": False,
        "requested_seed": 0,
        "target_sampling_control": "fixture",
        "policy_evaluable_turn": turn.policy_evaluable,
        "policy_challenge_index": attempt.params["policy_challenge_index"],
        "policy_challenge_horizon": attempt.params["policy_challenge_horizon"],
        "turn_expected_behavior": attempt.params["turn_expected_behavior"],
        "expected_behavior": attempt.params["turn_expected_behavior"],
        "planning_exact_modality_combination": list(
            contract.source_combination
        ),
        "modality": source_modality,
        "source_modality": source_modality,
        "delivered_modality": delivered_modality,
        "effective_modality": effective_modality,
        "target_input_delivered": True,
        "target_modalities": list(target_modalities),
        "is_multimodal": bool(
            set(contract.source_combination) & {"image", "audio", "video"}
        ),
    }
    if cascade_confident:
        raw["cascade_confident"] = True
    return response, Judgment(
        attempt_id=attempt.id,
        judge="fixture",
        label=label,
        score=1.0 if label == "violation" else 0.0,
        raw=raw,
        run_id="fixture-run",
    )


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("policy_evaluable_turn", False),
        ("policy_challenge_index", 1),
        ("policy_challenge_horizon", 2),
        ("turn_expected_behavior", "safe_answer"),
        ("expected_behavior", "safe_answer"),
        ("modality", "image"),
        ("source_modality", "image"),
        ("delivered_modality", "image"),
        ("effective_modality", "image"),
        ("target_input_delivered", False),
        ("target_modalities", ["text", "image"]),
        ("is_multimodal", True),
    ],
)
def test_realized_lineage_rejects_each_judgment_estimand_drift(
    field: str,
    changed: object,
) -> None:
    contract = ReplayAttacker().plan_target_inputs(_text_datapoint(), _budget(1))
    plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **contract.manifest_payload()}],
    }
    attempt = _attempt_for_planned_turn(contract, 0)
    response, judgment = _response_and_judgment(
        contract, attempt, target_modalities=("text",)
    )
    drifted = judgment.model_copy(update={
        "raw": {**judgment.raw, field: changed},
    })

    with pytest.raises(AttackerInputContractError, match="Judgment policy/modality"):
        validate_attempts_against_attacker_input_plan(
            plan,
            [attempt],
            [response],
            [drifted],
            target_modalities=("text",),
            expected_sha256=attacker_input_payload_sha256(plan),
            expected_count=1,
        )


def test_realized_lineage_rejects_joint_attempt_response_judgment_drift() -> None:
    contract = ReplayAttacker().plan_target_inputs(_text_datapoint(), _budget(1))
    plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **contract.manifest_payload()}],
    }
    attempt = _attempt_for_planned_turn(contract, 0)
    response, judgment = _response_and_judgment(
        contract, attempt, target_modalities=("text",)
    )
    drifted_attempt = attempt.model_copy(update={
        "params": {**attempt.params, "policy_challenge_horizon": 2},
    })
    drifted_response = response.model_copy(update={
        "raw": {**response.raw, "requested_seed": 1},
    })
    drifted_judgment = judgment.model_copy(update={
        "raw": {
            **judgment.raw,
            "policy_challenge_horizon": 2,
            "requested_seed": 1,
        },
    })

    with pytest.raises(AttackerInputContractError, match="challenge index/horizon"):
        validate_attempts_against_attacker_input_plan(
            plan,
            [drifted_attempt],
            [drifted_response],
            [drifted_judgment],
            target_modalities=("text",),
            expected_sha256=attacker_input_payload_sha256(plan),
            expected_count=1,
        )


def test_horizon_validator_allows_only_bound_crescendo_terminal_prefix() -> None:
    contract = CrescendoAttacker().plan_target_inputs(_text_datapoint(), _budget(4))
    plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **contract.manifest_payload()}],
    }
    attempts = [_attempt_for_planned_turn(contract, index) for index in range(3)]
    paired = [
        _response_and_judgment(
            contract,
            attempt,
            label="violation" if index == 2 else "safe",
            cascade_confident=index == 2,
        )
        for index, attempt in enumerate(attempts)
    ]
    responses = [item[0] for item in paired]
    judgments = [item[1] for item in paired]
    validate_attempts_against_attacker_input_plan(
        plan,
        attempts,
        responses,
        judgments,
        target_modalities=("text", "image"),
        expected_sha256=attacker_input_payload_sha256(plan),
        expected_count=1,
    )

    unjustified = [
        *judgments[:-1],
        judgments[-1].model_copy(update={"label": "safe", "score": 0.0}),
    ]
    with pytest.raises(AttackerInputContractError, match="terminal violation"):
        validate_attempts_against_attacker_input_plan(
            plan,
            attempts,
            responses,
            unjustified,
            target_modalities=("text", "image"),
            expected_sha256=attacker_input_payload_sha256(plan),
            expected_count=1,
        )


def test_horizon_validator_accepts_declared_upper_bound_prefix() -> None:
    contract = T3MP3STAttacker().plan_target_inputs(
        _text_datapoint(), _budget(4)
    )
    plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [{"seed": 0, **contract.manifest_payload()}],
    }
    attempt = _attempt_for_planned_turn(contract, 0)
    response, judgment = _response_and_judgment(contract, attempt)
    validate_attempts_against_attacker_input_plan(
        plan,
        [attempt],
        [response],
        [judgment],
        target_modalities=("text", "image"),
        expected_sha256=attacker_input_payload_sha256(plan),
        expected_count=1,
    )
