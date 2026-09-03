"""Pre-scrutiny readiness gate for every generative local target.

The gate uses only benign, deterministic questions and synthetic images. It is
transport-neutral across the harness's vLLM and Ollama targets and produces no
security metric. A target must pass before a new diagnostic or measured
security lane may use it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import random
import re
import struct
import time
import sys
import zlib
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT))

from experiments.local_targets import detect_gpu_hardware  # noqa: E402
from experiments.run_matrix import (  # noqa: E402
    _load_local_config,
    _require_local_hardware_fit,
    build_target,
)
from ura.data_models import DialogTurn, MediaRef, Response  # noqa: E402
from ura.targets.base import TargetAnswerError  # noqa: E402
from ura.targets.local import (  # noqa: E402
    DEFAULT_LOCAL_GENERATION_TOKENS,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    MAX_OLLAMA_NUM_PREDICT,
    MAX_VLLM_GENERATION_TOKENS,
)
from ura.model_acquisition import (  # noqa: E402
    ModelAcquisitionError,
    write_document_create_only,
)
from ura.model_acquisition_runtime import (  # noqa: E402
    admit_managed_model_runtime,
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    hf_offline_environment_overrides,
    public_selection_descriptor,
)

LEGACY_SCHEMA = "ura-local-model-readiness/1"
SCHEMA = "ura-local-model-readiness/2"
READINESS_SEED = 20260829
TEXT_SAMPLE_SIZE = 10
TEXT_MIN_CORRECT = 5
VISION_SAMPLE_SIZE = 5
VISION_MIN_CORRECT = 2
PROFILE_DEFAULT_GENERATION_TOKENS = DEFAULT_LOCAL_GENERATION_TOKENS
PROFILE_MAXIMUM_GENERATION_TOKENS = min(
    MAX_VLLM_GENERATION_TOKENS, MAX_OLLAMA_NUM_PREDICT
)
PROFILE_REQUEST_DEADLINE_SECONDS = DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS
TEXT_BANK = (
    ("sum-7-5", "Reply with only the integer result of 7 + 5.", r"\b12\b"),
    ("product-9-3", "Reply with only the integer result of 9 times 3.", r"\b27\b"),
    ("difference-18-11", "Reply with only the integer result of 18 - 11.", r"\b7\b"),
    ("capital-france", "Reply with only the capital city of France.", r"\bparis\b"),
    (
        "freezing-water",
        "Reply with only the Celsius freezing point of water as an integer.",
        r"\b0\b",
    ),
    ("opposite-north", "Reply with only the opposite cardinal direction to north.", r"\bsouth\b"),
    (
        "sort-integers",
        "Reply with only these integers in ascending order, comma-separated: 8, 2, 5.",
        r"\b2\s*,\s*5\s*,\s*8\b",
    ),
    ("uppercase-thesis", "Reply with only the uppercase form of the word thesis.", r"\bTHESIS\b"),
    (
        "earth-satellite",
        "Reply with only the common four-letter name of Earth's natural satellite.",
        r"\bmoon\b",
    ),
    ("days-week", "Reply with only the number of days in a standard week.", r"\b7\b"),
    (
        "mix-red-blue",
        "Reply with only the common color produced by mixing red and blue.",
        r"\bpurple\b",
    ),
    ("cat-spanish", "Reply with only the Spanish word for cat.", r"\bgato\b"),
    ("binary-six", "Reply with only the base-2 representation of decimal 6.", r"\b110\b"),
    ("even-sequence", "Reply with only the next integer in this sequence: 2, 4, 6.", r"\b8\b"),
    ("water-formula", "Reply with only the chemical formula for water.", r"\bH2O\b"),
    ("earth-orbit", "Reply with only true or false: Earth orbits the Sun.", r"\btrue\b"),
    ("alphabet-first", "Reply with only the first letter of the English alphabet.", r"\bA\b"),
    ("minutes-hour", "Reply with only the number of minutes in one hour.", r"\b60\b"),
    ("plural-mouse", "Reply with only the usual English plural of mouse.", r"\bmice\b"),
    ("square-five", "Reply with only the integer square of 5.", r"\b25\b"),
)
COLORS = {
    "black": (0, 0, 0),
    "blue": (0, 0, 255),
    "green": (0, 180, 0),
    "orange": (255, 128, 0),
    "purple": (128, 0, 180),
    "red": (255, 0, 0),
    "white": (255, 255, 255),
    "yellow": (255, 230, 0),
}


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def readiness_policy() -> dict[str, object]:
    return {
        "generation_conditions": [
            PROFILE_DEFAULT_GENERATION_TOKENS,
            PROFILE_MAXIMUM_GENERATION_TOKENS,
        ],
        "generation_selection": "highest_passing_condition",
        "nonresponses_count_as_incorrect": True,
        "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
        "readiness_seed": READINESS_SEED,
        "text_max_nonresponses_at_passing_threshold": TEXT_SAMPLE_SIZE - TEXT_MIN_CORRECT,
        "text_min_correct": TEXT_MIN_CORRECT,
        "text_sample_size": TEXT_SAMPLE_SIZE,
        "vision_max_nonresponses_at_passing_threshold": VISION_SAMPLE_SIZE - VISION_MIN_CORRECT,
        "vision_min_correct": VISION_MIN_CORRECT,
        "vision_sample_size": VISION_SAMPLE_SIZE,
    }


def legacy_readiness_policy() -> dict[str, object]:
    """Return the immutable policy carried by retained schema /1 receipts."""

    return {
        "nonresponses_count_as_incorrect": True,
        "readiness_seed": READINESS_SEED,
        "text_max_nonresponses_at_passing_threshold": TEXT_SAMPLE_SIZE - TEXT_MIN_CORRECT,
        "text_min_correct": TEXT_MIN_CORRECT,
        "text_sample_size": TEXT_SAMPLE_SIZE,
        "vision_max_nonresponses_at_passing_threshold": VISION_SAMPLE_SIZE - VISION_MIN_CORRECT,
        "vision_min_correct": VISION_MIN_CORRECT,
        "vision_sample_size": VISION_SAMPLE_SIZE,
    }


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
    )


def _split_image(left: tuple[int, int, int], right: tuple[int, int, int]) -> bytes:
    width = height = 64
    raw = bytearray()
    for _y in range(height):
        raw.append(0)
        for x in range(width):
            raw.extend(left if x < width // 2 else right)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), level=9))
        + _png_chunk(b"IEND", b"")
    )


def _image_ref(left: str, right: str) -> MediaRef:
    data = _split_image(COLORS[left], COLORS[right])
    encoded = base64.b64encode(data).decode("ascii")
    return MediaRef(
        modality="image",
        uri=f"data:image/png;base64,{encoded}",
        sha256=hashlib.sha256(data).hexdigest(),
        mime="image/png",
        meta={"readiness_fixture": True, "width": 64, "height": 64},
    )


def _response_text(response: Response) -> str:
    return "\n".join(
        turn.content or "" for turn in response.output_turns if turn.role == "assistant"
    ).strip()


def _observation(response: Response, text: str) -> dict[str, object]:
    termination = response.raw.get("finish_reason", response.raw.get("done_reason"))
    generation = response.raw.get("generation")
    return {
        "characters": len(text),
        "latency_ms": round(float(response.latency_ms), 3),
        "outcome": "generated_text" if text else "model_nonresponse",
        "preview": text[:500],
        "termination_reason": termination,
        "tokens": dict(response.tokens),
        "effective_generation": dict(generation) if isinstance(generation, dict) else {},
    }


def _failed_observation(
    exc: TargetAnswerError, *, latency_ms: float
) -> dict[str, object]:
    return {
        "characters": 0,
        "effective_generation": {},
        "error_category": exc.category,
        "error_type": type(exc).__name__,
        "latency_ms": round(latency_ms, 3),
        "outcome": "model_nonresponse",
        "preview": "",
        "termination_reason": None,
        "tokens": {},
    }


def _run_text(target: Any) -> dict[str, object]:
    selected = random.Random(READINESS_SEED).sample(TEXT_BANK, TEXT_SAMPLE_SIZE)
    rows: list[dict[str, object]] = []
    for index, (question_id, prompt, expected) in enumerate(selected):
        started = time.perf_counter()
        try:
            response = target.generate(
                [DialogTurn(role="user", content=prompt)], seed=READINESS_SEED + index
            )
            text = _response_text(response)
            observation = _observation(response, text)
        except TargetAnswerError as exc:
            text = ""
            observation = _failed_observation(
                exc, latency_ms=(time.perf_counter() - started) * 1000.0
            )
        rows.append(
            {
                **observation,
                "correct": re.search(expected, text, flags=re.IGNORECASE) is not None,
                "expected_pattern": expected,
                "prompt": prompt,
                "question_id": question_id,
            }
        )
    correct = sum(bool(row["correct"]) for row in rows)
    nonresponses = sum(row["outcome"] == "model_nonresponse" for row in rows)
    return {
        "correct": correct,
        "minimum_correct": TEXT_MIN_CORRECT,
        "nonresponses": nonresponses,
        "observations": rows,
        "passed": correct >= TEXT_MIN_CORRECT,
        "sample_seed": READINESS_SEED,
        "sample_size": TEXT_SAMPLE_SIZE,
    }


def _run_vision(target: Any) -> dict[str, object]:
    pairs = [(left, right) for left in COLORS for right in COLORS if left != right]
    selected = random.Random(READINESS_SEED).sample(pairs, VISION_SAMPLE_SIZE)
    rows: list[dict[str, object]] = []
    for index, (left, right) in enumerate(selected):
        started = time.perf_counter()
        try:
            response = target.generate(
                [
                    DialogTurn(
                        role="user",
                        content="Name the left and right colors. Reply only as LEFT=<color>;RIGHT=<color>.",
                        media=[_image_ref(left, right)],
                    )
                ],
                seed=READINESS_SEED + 100 + index,
            )
            text = _response_text(response)
            observation = _observation(response, text)
        except TargetAnswerError as exc:
            text = ""
            observation = _failed_observation(
                exc, latency_ms=(time.perf_counter() - started) * 1000.0
            )
        left_match = re.search(rf"\b{re.escape(left)}\b", text, flags=re.IGNORECASE)
        right_match = re.search(rf"\b{re.escape(right)}\b", text, flags=re.IGNORECASE)
        rows.append(
            {
                **observation,
                "correct": bool(
                    left_match and right_match and left_match.start() < right_match.start()
                ),
                "expected_left": left,
                "expected_right": right,
                "image_id": f"split-colors-{index + 1}",
                "prompt": "Name the left and right colors.",
            }
        )
    correct = sum(bool(row["correct"]) for row in rows)
    nonresponses = sum(row["outcome"] == "model_nonresponse" for row in rows)
    return {
        "correct": correct,
        "minimum_correct": VISION_MIN_CORRECT,
        "nonresponses": nonresponses,
        "observations": rows,
        "passed": correct >= VISION_MIN_CORRECT,
        "sample_seed": READINESS_SEED,
        "sample_size": VISION_SAMPLE_SIZE,
    }


def _set_generation_tokens(target: Any, spec: str, value: int) -> None:
    if spec.startswith("vllm:"):
        target.max_tokens = value
    elif spec.startswith("ollama:"):
        target.num_predict = value
    else:
        raise ValueError("readiness profile supports only vLLM or Ollama")


def _run_condition(
    target: Any,
    *,
    spec: str,
    modalities: list[str],
    generation_tokens: int,
) -> dict[str, object]:
    _set_generation_tokens(target, spec, generation_tokens)
    text = _run_text(target)
    vision = _run_vision(target) if "image" in modalities else None
    observations = [*text["observations"]]
    if vision is not None:
        observations.extend(vision["observations"])
    deadline_failures = sum(
        1
        for observation in observations
        if observation.get("error_category") == "generation_timeout"
        or float(observation.get("latency_ms") or 0.0)
        >= PROFILE_REQUEST_DEADLINE_SECONDS * 1000.0
    )
    return {
        "deadline_failures": deadline_failures,
        "generation_tokens": generation_tokens,
        "passed": bool(
            text["passed"]
            and (vision is None or vision["passed"])
            and deadline_failures == 0
        ),
        "text": text,
        "vision": vision,
    }


def _validate_probe_result(
    value: object,
    *,
    sample_size: int,
    minimum_correct: int,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"local-model {label} readiness evidence is invalid")
    correct = value.get("correct")
    nonresponses = value.get("nonresponses")
    if (
        isinstance(correct, bool)
        or not isinstance(correct, int)
        or isinstance(nonresponses, bool)
        or not isinstance(nonresponses, int)
        or value.get("passed") is not (correct >= minimum_correct)
        or value.get("sample_size") != sample_size
        or value.get("minimum_correct") != minimum_correct
        or not 0 <= correct <= sample_size
        or not 0 <= nonresponses <= sample_size - correct
        or not isinstance(value.get("observations"), list)
        or len(value["observations"]) != sample_size
    ):
        raise ValueError(f"local-model {label} readiness evidence is invalid")
    return value


def validate_readiness(value: object, *, expected_spec: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") not in {LEGACY_SCHEMA, SCHEMA}:
        raise ValueError("local-model readiness receipt schema is invalid")
    expected_policy = (
        legacy_readiness_policy()
        if value.get("schema") == LEGACY_SCHEMA
        else readiness_policy()
    )
    if value.get("policy") != expected_policy or value.get("status") != "verified":
        raise ValueError("local-model readiness policy is not terminal-passed")
    if expected_spec is not None and value.get("requested_spec") != expected_spec:
        raise ValueError("local-model readiness receipt names another target")
    modalities = value.get("modalities")
    text = value.get("text")
    vision = value.get("vision")
    execution = value.get("execution_profile")
    if not isinstance(modalities, list) or "text" not in modalities or not isinstance(text, dict):
        raise ValueError("local-model readiness modalities are invalid")
    _validate_probe_result(
        text,
        sample_size=TEXT_SAMPLE_SIZE,
        minimum_correct=TEXT_MIN_CORRECT,
        label="text",
    )
    if text.get("passed") is not True:
        raise ValueError("local-model text readiness evidence is invalid")
    if "image" in modalities:
        _validate_probe_result(
            vision,
            sample_size=VISION_SAMPLE_SIZE,
            minimum_correct=VISION_MIN_CORRECT,
            label="vision",
        )
        if vision.get("passed") is not True:
            raise ValueError("local-model vision readiness evidence is invalid")
    elif vision is not None:
        raise ValueError("text-only readiness receipt contains vision evidence")
    if value.get("schema") == LEGACY_SCHEMA:
        if execution is not None:
            raise ValueError("legacy local-model readiness receipt changed")
        return value
    if (
        not isinstance(execution, dict)
        or set(execution)
        != {
            "conditions",
            "per_request_deadline_seconds",
            "selected_generation_tokens",
            "selection_basis",
        }
        or execution.get("per_request_deadline_seconds")
        != PROFILE_REQUEST_DEADLINE_SECONDS
        or execution.get("selection_basis") != "highest_passing_condition"
        or not isinstance(execution.get("conditions"), list)
        or [item.get("generation_tokens") for item in execution["conditions"]]
        != list(readiness_policy()["generation_conditions"])
    ):
        raise ValueError("local-model execution profile is invalid")
    passing: list[int] = []
    for condition in execution["conditions"]:
        if not isinstance(condition, dict) or set(condition) != {
            "deadline_failures", "generation_tokens", "passed", "text", "vision"
        }:
            raise ValueError("local-model execution condition is invalid")
        condition_text = _validate_probe_result(
            condition["text"],
            sample_size=TEXT_SAMPLE_SIZE,
            minimum_correct=TEXT_MIN_CORRECT,
            label="text condition",
        )
        condition_vision = condition["vision"]
        vision_passed = True
        if "image" in modalities:
            condition_vision = _validate_probe_result(
                condition_vision,
                sample_size=VISION_SAMPLE_SIZE,
                minimum_correct=VISION_MIN_CORRECT,
                label="vision condition",
            )
            vision_passed = bool(condition_vision["passed"])
        elif condition_vision is not None:
            raise ValueError("text-only execution condition contains vision evidence")
        deadline_failures = condition["deadline_failures"]
        if (
            isinstance(deadline_failures, bool)
            or not isinstance(deadline_failures, int)
            or deadline_failures < 0
            or deadline_failures > TEXT_SAMPLE_SIZE + (
                VISION_SAMPLE_SIZE if "image" in modalities else 0
            )
        ):
            raise ValueError("local-model execution deadline evidence is invalid")
        expected_passed = bool(
            condition_text["passed"]
            and vision_passed
            and deadline_failures == 0
        )
        if condition["passed"] is not expected_passed:
            raise ValueError("local-model execution condition status is invalid")
        if expected_passed:
            passing.append(int(condition["generation_tokens"]))
    selected = max(passing) if passing else None
    if execution.get("selected_generation_tokens") != selected or selected is None:
        raise ValueError("local-model execution profile has no passing condition")
    selected_condition = next(
        item for item in execution["conditions"] if item["generation_tokens"] == selected
    )
    if text != selected_condition["text"] or vision != selected_condition["vision"]:
        raise ValueError("local-model selected readiness evidence changed")
    return value


def _read_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("readiness receipt must be a regular file no larger than 16 MiB")
    return json.loads(path.read_text(encoding="ascii"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local")
    parser.add_argument("--local-config", type=Path)
    parser.add_argument("--local-config-sha256", default="")
    parser.add_argument("--model-acquisition-plan-only", action="store_true")
    parser.add_argument("--model-acquisition-plan-dir", type=Path)
    parser.add_argument("--model-acquisition-plan", type=Path)
    parser.add_argument("--model-acquisition-plan-sha256", default="")
    parser.add_argument("--model-acquisition-receipt", type=Path)
    parser.add_argument("--model-acquisition-receipt-sha256", default="")
    parser.add_argument("--model-acquisition-store", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--profile-registry", type=Path)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--sha256", default="")
    parser.add_argument("--expected-spec")
    args = parser.parse_args(argv)

    if args.validate is not None:
        if not args.sha256 or re.fullmatch(r"[0-9a-f]{64}", args.sha256) is None:
            parser.error("--validate requires --sha256")
        raw = args.validate.read_bytes()
        if hashlib.sha256(raw).hexdigest() != args.sha256:
            raise ValueError("local-model readiness receipt SHA-256 differs")
        value = validate_readiness(_read_json(args.validate), expected_spec=args.expected_spec)
        print(
            json.dumps(
                {"readiness_id": value["readiness_id"], "status": "validated"}, sort_keys=True
            )
        )
        return 0
    if not args.local or args.local_config is None:
        parser.error("readiness derivation requires --local and --local-config")
    if not args.local.startswith(("vllm:", "ollama:")):
        parser.error("readiness supports only local vLLM or Ollama targets")

    hardware = detect_gpu_hardware()
    local_configs, _artifact = _load_local_config(
        str(args.local_config),
        [args.local],
        hardware=hardware,
        expected_sha256=args.local_config_sha256,
    )
    config = local_configs[args.local]
    config["timeout"] = PROFILE_REQUEST_DEADLINE_SECONDS
    if args.local.startswith("vllm:"):
        config["max_tokens"] = PROFILE_DEFAULT_GENERATION_TOKENS
    else:
        config["num_predict"] = PROFILE_DEFAULT_GENERATION_TOKENS
    requirements = collect_run_requirements(
        target_specs=[args.local],
        local_configs=local_configs,
        judge_names=[],
        judge_model="",
        attacker_names=[],
        attacker_configs={},
    )
    selection = build_runtime_selection(
        requirements,
        input_bindings={
            "local_configs_sha256": _sha(local_configs),
            "readiness_policy_sha256": _sha(readiness_policy()),
        },
    )
    if args.model_acquisition_plan_only:
        if args.out is not None or args.model_acquisition_plan_dir is None:
            parser.error("plan-only requires --model-acquisition-plan-dir and forbids --out")
        if not requirements.requirements:
            raise ModelAcquisitionError("selected readiness target needs no Hub acquisition")
        plan = build_runtime_plan(selection)
        _path, digest = write_document_create_only(
            args.model_acquisition_plan_dir,
            plan,
            identifier=plan["plan_id"],
            suffix="plan.json",
        )
        print(json.dumps({"plan_id": plan["plan_id"], "plan_sha256": digest}, sort_keys=True))
        return 0
    if args.out is None:
        parser.error("readiness derivation requires --out")

    acquisition_values = (
        args.model_acquisition_plan,
        args.model_acquisition_plan_sha256,
        args.model_acquisition_receipt,
        args.model_acquisition_receipt_sha256,
        args.model_acquisition_store,
    )
    model_runtime = None
    acquisition: dict[str, object]
    if requirements.requirements:
        if not all(acquisition_values):
            raise ModelAcquisitionError(
                "vLLM readiness requires its exact acquisition plan and receipt"
            )
        import os

        os.environ.update(hf_offline_environment_overrides())
        model_runtime, acquisition = admit_managed_model_runtime(
            selection=selection,
            plan_path=args.model_acquisition_plan,
            plan_sha256=args.model_acquisition_plan_sha256,
            receipt_path=args.model_acquisition_receipt,
            receipt_sha256=args.model_acquisition_receipt_sha256,
            managed_store=args.model_acquisition_store,
        )
    else:
        if any(acquisition_values):
            raise ModelAcquisitionError("Ollama readiness forbids Hub acquisition arguments")
        acquisition = {
            "selection": public_selection_descriptor(selection),
            "status": "not_required",
        }

    target = build_target(
        args.local,
        local_identity=config,
        model_runtime=model_runtime,
        managed_model_role="vllm_target",
    )
    if args.local.startswith("vllm:"):
        _require_local_hardware_fit(target, args.local, config, hardware)
    try:
        conditions = [
            _run_condition(
                target,
                spec=args.local,
                modalities=list(config["modalities"]),
                generation_tokens=generation_tokens,
            )
            for generation_tokens in readiness_policy()["generation_conditions"]
        ]
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            close()
    passing = [
        condition for condition in conditions if condition["passed"] is True
    ]
    selected = max(
        passing,
        key=lambda condition: int(condition["generation_tokens"]),
        default=None,
    )
    text = selected["text"] if selected is not None else conditions[0]["text"]
    vision = selected["vision"] if selected is not None else conditions[0]["vision"]
    status = "verified" if selected is not None else "failed"
    receipt: dict[str, object] = {
        "acquisition": acquisition,
        "local_config_sha256": _sha(local_configs),
        "modalities": list(config["modalities"]),
        "execution_profile": {
            "conditions": conditions,
            "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
            "selected_generation_tokens": (
                int(selected["generation_tokens"]) if selected is not None else None
            ),
            "selection_basis": "highest_passing_condition",
        },
        "policy": readiness_policy(),
        "readiness_id": "0" * 64,
        "requested_spec": args.local,
        "resolved_target": str(target.name),
        "schema": SCHEMA,
        "status": status,
        "text": text,
        "vision": vision,
    }
    receipt["readiness_id"] = _sha(receipt)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("xb") as handle:
        handle.write(_canonical(receipt))
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    if status == "verified":
        from experiments.local_model_profiles import update_registry

        update_registry(
            spec=args.local,
            local_config=config,
            readiness_path=args.out,
            readiness_sha256=digest,
            readiness=receipt,
            path=args.profile_registry,
        )
    print(
        json.dumps(
            {"readiness_id": receipt["readiness_id"], "sha256": digest, "status": status},
            sort_keys=True,
        )
    )
    return 0 if status == "verified" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, TypeError, ValueError, ModelAcquisitionError) as exc:
        print(f"local-model readiness failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
