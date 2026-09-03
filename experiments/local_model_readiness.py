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
import os
import random
import re
import signal
import struct
import subprocess
import tempfile
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
    validate_ollama_think,
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
BOUNDED_SCHEMA = "ura-local-model-readiness/2"
CAP_STRESS_SCHEMA = "ura-local-model-readiness/3"
SCHEMA = "ura-local-model-readiness/4"
PROBE_SCHEMA = "ura-local-model-readiness-probe/1"
PROBE_START_SCHEMA = "ura-local-model-readiness-probe-start/1"
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
PROFILE_PROBE_SETUP_DEADLINE_SECONDS = 600.0
PROFILE_GENERATION_TOKEN_CANDIDATES = (
    PROFILE_MAXIMUM_GENERATION_TOKENS,
    16_384,
    8_192,
    4_096,
    2_048,
    1_024,
    512,
    256,
)
PROFILE_STRESS_MINIMUM_FRACTION = 0.95
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
        "generation_conditions": list(PROFILE_GENERATION_TOKEN_CANDIDATES),
        "generation_selection": "first_descending_stress_pass",
        "generation_stress_by_modality": {
            "text": "reach_cap_under_deadline",
            "image": "nonempty_under_deadline",
        },
        "generation_stress_minimum_fraction": PROFILE_STRESS_MINIMUM_FRACTION,
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


def cap_stress_readiness_policy() -> dict[str, object]:
    """Return the immutable policy carried by retained schema /3 receipts."""

    policy = readiness_policy()
    policy.pop("generation_stress_by_modality")
    return policy


def bounded_readiness_policy() -> dict[str, object]:
    """Return the immutable policy carried by retained schema /2 receipts."""

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
        "thinking_output_observed": (
            response.raw.get("thinking_output_observed") is True
        ),
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
        "thinking_output_observed": False,
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


def _configure_readiness_condition(
    spec: str,
    config: dict[str, object],
) -> dict[str, object]:
    """Bind hardware-fit context and the selected model's thinking mode."""

    config["timeout"] = PROFILE_REQUEST_DEADLINE_SECONDS
    if spec.startswith("vllm:"):
        tensor_parallel_size = config.get("tensor_parallel_size", 2)
        gpu_memory_utilization = config.get("gpu_memory_utilization", 0.90)
        config["max_model_len"] = -1
        config["max_tokens"] = PROFILE_MAXIMUM_GENERATION_TOKENS
        config["tensor_parallel_size"] = tensor_parallel_size
        config["gpu_memory_utilization"] = gpu_memory_utilization
        return {
            "gpu_memory_utilization": gpu_memory_utilization,
            "max_model_len": -1,
            "tensor_parallel_size": tensor_parallel_size,
        }
    if spec.startswith("ollama:"):
        config["num_ctx"] = "fit"
        config["num_predict"] = PROFILE_MAXIMUM_GENERATION_TOKENS
        thinking = config.get("think", False)
        config["think"] = thinking
        return {"num_ctx": "fit", "think": thinking}
    raise ValueError("readiness supports only local vLLM or Ollama targets")


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


def _stress_dialog(
    generation_tokens: int,
    *,
    image: bool,
) -> list[DialogTurn]:
    prompt = (
        "This is a generation-throughput calibration, not a knowledge test. "
        f"Emit at least {generation_tokens} tokens by repeating the sequence "
        "alpha beta gamma delta epsilon followed by a space. Do not summarize, "
        "explain, conclude, or stop voluntarily; continue until the runtime "
        "generation limit stops you."
    )
    return [
        DialogTurn(
            role="user",
            content=prompt,
            media=[_image_ref("red", "blue")] if image else [],
        )
    ]


def _run_generation_stress(
    target: Any,
    *,
    generation_tokens: int,
    image: bool,
    require_cap: bool = True,
) -> dict[str, object]:
    started = time.perf_counter()
    try:
        response = target.generate(
            _stress_dialog(generation_tokens, image=image),
            seed=READINESS_SEED + (10_000 if image else 1_000) + generation_tokens,
        )
        text = _response_text(response)
        observation = _observation(response, text)
    except TargetAnswerError as exc:
        observation = _failed_observation(
            exc,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    completion_tokens = observation["tokens"].get("completion", 0)
    if isinstance(completion_tokens, bool) or not isinstance(completion_tokens, int):
        completion_tokens = 0
    minimum_tokens = max(
        1,
        (generation_tokens * int(PROFILE_STRESS_MINIMUM_FRACTION * 100) + 99) // 100,
    )
    latency_ms = float(observation.get("latency_ms") or 0.0)
    reached_cap = bool(
        observation.get("termination_reason") == "length"
        and completion_tokens >= minimum_tokens
    )
    deadline_passed = bool(
        observation.get("error_category") != "generation_timeout"
        and latency_ms < PROFILE_REQUEST_DEADLINE_SECONDS * 1000.0
    )
    return {
        **observation,
        "deadline_passed": deadline_passed,
        "minimum_completion_tokens": minimum_tokens,
        # This is a throughput calibration, not an answer-quality result. A
        # reasoning model may place these deliberately repetitive tokens in
        # its separate thinking field. The later responsiveness survey still
        # requires visible, correct answers at the selected cap.
        "passed": bool(
            (reached_cap or not require_cap)
            and deadline_passed
            and (
                observation.get("outcome") == "generated_text"
                or observation.get("thinking_output_observed") is True
            )
        ),
        "reached_generation_cap": reached_cap,
        "requested_generation_tokens": generation_tokens,
    }


def _write_probe_start_marker(
    path: Path,
    *,
    kind: str,
    requested_spec: str,
    generation_tokens: int,
) -> None:
    """Publish the instant a child begins its one stress generation request."""

    marker = {
        "generation_tokens": generation_tokens,
        "kind": kind,
        "requested_spec": requested_spec,
        "schema": PROBE_START_SCHEMA,
        "started_monotonic_ns": time.monotonic_ns(),
    }
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(_canonical(marker))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run_marked_generation_stress(
    target: Any,
    *,
    marker: Path,
    kind: str,
    requested_spec: str,
    generation_tokens: int,
    image: bool,
) -> dict[str, object]:
    """Prepare a lazy engine, publish request start, and run one stress call."""

    preflight = getattr(target, "preflight_base", None)
    if callable(preflight):
        # vLLM constructs its engine lazily. Keep engine loading and graph
        # capture outside request time; the first real generation remains the
        # measured stress request.
        preflight()
    _write_probe_start_marker(
        marker,
        kind=kind,
        requested_spec=requested_spec,
        generation_tokens=generation_tokens,
    )
    return _run_generation_stress(
        target,
        generation_tokens=generation_tokens,
        image=image,
        require_cap=not image,
    )


def _read_probe_start_marker(
    path: Path,
    *,
    kind: str,
    requested_spec: str,
    generation_tokens: int,
) -> int:
    marker = _read_json(path)
    if (
        not isinstance(marker, dict)
        or set(marker)
        != {
            "generation_tokens",
            "kind",
            "requested_spec",
            "schema",
            "started_monotonic_ns",
        }
        or marker.get("schema") != PROBE_START_SCHEMA
        or marker.get("kind") != kind
        or marker.get("requested_spec") != requested_spec
        or marker.get("generation_tokens") != generation_tokens
        or isinstance(marker.get("started_monotonic_ns"), bool)
        or not isinstance(marker.get("started_monotonic_ns"), int)
        or marker["started_monotonic_ns"] <= 0
    ):
        raise ValueError("isolated local-model probe start marker is invalid")
    return int(marker["started_monotonic_ns"])


def _terminate_isolated_probe(process: subprocess.Popen[bytes]) -> None:
    """Terminate one private probe process and wait until its GPU owner exits."""

    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - live readiness runs on the Linux rig
            process.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=5.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - live readiness runs on the Linux rig
            process.kill()
    except (OSError, ProcessLookupError):
        pass
    process.wait(timeout=5.0)


def _deadline_stress_probe(
    *,
    kind: str,
    requested_spec: str,
    resolved_target: str,
    generation_tokens: int,
) -> dict[str, object]:
    observation = _failed_observation(
        TargetAnswerError(
            f"local-model stress request reached the configured hard "
            f"{PROFILE_REQUEST_DEADLINE_SECONDS:g}s deadline",
            category="generation_timeout",
        ),
        latency_ms=PROFILE_REQUEST_DEADLINE_SECONDS * 1000.0,
    )
    minimum_tokens = max(
        1,
        (
            generation_tokens * int(PROFILE_STRESS_MINIMUM_FRACTION * 100)
            + 99
        )
        // 100,
    )
    return {
        "generation_tokens": generation_tokens,
        "kind": kind,
        "requested_spec": requested_spec,
        "resolved_target": resolved_target,
        "result": {
            **observation,
            "deadline_passed": False,
            "minimum_completion_tokens": minimum_tokens,
            "passed": False,
            "reached_generation_cap": False,
            "requested_generation_tokens": generation_tokens,
        },
        "schema": PROBE_SCHEMA,
    }


def _reset_after_deadline(target: Any, observation: dict[str, object]) -> None:
    """Discard a timed-out local runtime before another probe is submitted."""

    if observation.get("deadline_passed") is True:
        return
    close = getattr(target, "close", None)
    if not callable(close):
        raise RuntimeError("timed-out local readiness target has no cleanup hook")
    close()


def _profile_generation_conditions(
    target: Any,
    *,
    spec: str,
    modalities: list[str],
) -> tuple[list[dict[str, object]], int | None]:
    """Start at the maximum and lower it until one cap meets the deadline."""

    conditions: list[dict[str, object]] = []
    for generation_tokens in PROFILE_GENERATION_TOKEN_CANDIDATES:
        _set_generation_tokens(target, spec, generation_tokens)
        stress_text = _run_generation_stress(
            target,
            generation_tokens=generation_tokens,
            image=False,
            require_cap=True,
        )
        _reset_after_deadline(target, stress_text)
        stress_vision = (
            _run_generation_stress(
                target,
                generation_tokens=generation_tokens,
                image=True,
                require_cap=False,
            )
            if "image" in modalities
            else None
        )
        if stress_vision is not None:
            _reset_after_deadline(target, stress_vision)
        observations = [stress_text]
        if stress_vision is not None:
            observations.append(stress_vision)
        deadline_failures = sum(
            observation.get("deadline_passed") is not True
            for observation in observations
        )
        condition = {
            "deadline_failures": deadline_failures,
            "generation_tokens": generation_tokens,
            "passed": bool(
                all(observation.get("passed") is True for observation in observations)
            ),
            "stress_text": stress_text,
            "stress_vision": stress_vision,
        }
        conditions.append(condition)
        if condition["passed"] is True:
            break
    selected = (
        int(conditions[-1]["generation_tokens"])
        if conditions and conditions[-1]["passed"] is True
        else None
    )
    return conditions, selected


def _probe_argv(
    args: argparse.Namespace,
    *,
    kind: str,
    generation_tokens: int,
    out: Path,
    start_marker: Path | None = None,
) -> list[str]:
    """Build one private child invocation for exactly one model load/probe."""

    command = [
        sys.executable,
        "-m",
        "experiments.local_model_readiness",
        "--local",
        args.local,
        "--local-config",
        str(args.local_config),
        "--local-config-sha256",
        args.local_config_sha256,
        "--out",
        str(out),
        "--isolated-probe",
        kind,
        "--generation-tokens",
        str(generation_tokens),
    ]
    for flag, value in (
        ("--probe-start-marker", start_marker),
        ("--model-acquisition-plan", args.model_acquisition_plan),
        ("--model-acquisition-plan-sha256", args.model_acquisition_plan_sha256),
        ("--model-acquisition-receipt", args.model_acquisition_receipt),
        ("--model-acquisition-receipt-sha256", args.model_acquisition_receipt_sha256),
        ("--model-acquisition-store", args.model_acquisition_store),
    ):
        if value:
            command.extend((flag, str(value)))
    return command


def _run_isolated_probe(
    args: argparse.Namespace,
    *,
    kind: str,
    generation_tokens: int,
    expected_target: str,
    out: Path,
) -> dict[str, object]:
    """Run one probe in a process whose exit is the GPU-cleanup boundary."""

    stress = kind.startswith("stress-")
    start_marker = out.with_suffix(out.suffix + ".started") if stress else None
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter/module argv
        _probe_argv(
            args,
            kind=kind,
            generation_tokens=generation_tokens,
            out=out,
            start_marker=start_marker,
        ),
        cwd=_REPO_ROOT,
        start_new_session=os.name == "posix",
    )
    timed_out = False
    if start_marker is not None:
        setup_deadline = time.monotonic() + PROFILE_PROBE_SETUP_DEADLINE_SECONDS
        while not start_marker.exists():
            returncode = process.poll()
            if returncode is not None:
                break
            if time.monotonic() >= setup_deadline:
                _terminate_isolated_probe(process)
                raise ValueError("isolated local-model probe setup exceeded its deadline")
            time.sleep(0.05)
        if start_marker.exists():
            try:
                started_ns = _read_probe_start_marker(
                    start_marker,
                    kind=kind,
                    requested_spec=args.local,
                    generation_tokens=generation_tokens,
                )
            except Exception:
                _terminate_isolated_probe(process)
                raise
            remaining = max(
                0.0,
                PROFILE_REQUEST_DEADLINE_SECONDS
                - (time.monotonic_ns() - started_ns) / 1_000_000_000.0,
            )
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_isolated_probe(process)
    else:
        process.wait()
    if timed_out:
        value = _deadline_stress_probe(
            kind=kind,
            requested_spec=args.local,
            resolved_target=expected_target,
            generation_tokens=generation_tokens,
        )
        with out.open("xb") as handle:
            handle.write(_canonical(value))
    elif process.returncode != 0:
        raise ValueError(f"isolated local-model {kind} probe failed")
    else:
        value = _read_json(out)
    if (
        not isinstance(value, dict)
        or set(value) != {
            "generation_tokens",
            "kind",
            "requested_spec",
            "resolved_target",
            "result",
            "schema",
        }
        or value.get("schema") != PROBE_SCHEMA
        or value.get("kind") != kind
        or value.get("requested_spec") != args.local
        or value.get("generation_tokens") != generation_tokens
        or not isinstance(value.get("resolved_target"), str)
        or not value["resolved_target"]
        or not isinstance(value.get("result"), dict)
    ):
        raise ValueError("isolated local-model probe artifact is invalid")
    return value


def _profile_generation_conditions_isolated(
    args: argparse.Namespace,
    *,
    modalities: list[str],
    expected_target: str,
    work: Path,
) -> tuple[list[dict[str, object]], int | None]:
    """Profile caps with a fresh OS process for every text/image observation."""

    conditions: list[dict[str, object]] = []
    for generation_tokens in PROFILE_GENERATION_TOKEN_CANDIDATES:
        text_probe = _run_isolated_probe(
            args,
            kind="stress-text",
            generation_tokens=generation_tokens,
            expected_target=expected_target,
            out=work / f"stress-text-{generation_tokens}.json",
        )
        if text_probe["resolved_target"] != expected_target:
            raise ValueError("isolated local-model probe target identity differs")
        stress_text = text_probe["result"]
        stress_vision = None
        # A failed text stress already rejects this cap. Do not spend another
        # load and request on the image variant until the text condition fits.
        if "image" in modalities and stress_text.get("passed") is True:
            vision_probe = _run_isolated_probe(
                args,
                kind="stress-image",
                generation_tokens=generation_tokens,
                expected_target=expected_target,
                out=work / f"stress-image-{generation_tokens}.json",
            )
            if vision_probe["resolved_target"] != expected_target:
                raise ValueError("isolated local-model probe target identity differs")
            stress_vision = vision_probe["result"]
        observations = [stress_text]
        if stress_vision is not None:
            observations.append(stress_vision)
        condition = {
            "deadline_failures": sum(
                observation.get("deadline_passed") is not True
                for observation in observations
            ),
            "generation_tokens": generation_tokens,
            "passed": all(
                observation.get("passed") is True for observation in observations
            ),
            "stress_text": stress_text,
            "stress_vision": stress_vision,
        }
        conditions.append(condition)
        if condition["passed"] is True:
            break
    selected = (
        int(conditions[-1]["generation_tokens"])
        if conditions and conditions[-1]["passed"] is True
        else None
    )
    return conditions, selected


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


def _validate_stress_result(
    value: object,
    *,
    generation_tokens: int,
    label: str,
    require_cap: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"local-model {label} stress evidence is invalid")
    latency_ms = value.get("latency_ms")
    tokens = value.get("tokens")
    if (
        isinstance(latency_ms, bool)
        or not isinstance(latency_ms, (int, float))
        or float(latency_ms) < 0.0
        or not isinstance(tokens, dict)
    ):
        raise ValueError(f"local-model {label} stress evidence is invalid")
    completion_tokens = tokens.get("completion", 0)
    if (
        isinstance(completion_tokens, bool)
        or not isinstance(completion_tokens, int)
        or completion_tokens < 0
    ):
        raise ValueError(f"local-model {label} stress token evidence is invalid")
    minimum_tokens = max(
        1,
        (generation_tokens * int(PROFILE_STRESS_MINIMUM_FRACTION * 100) + 99) // 100,
    )
    reached_cap = bool(
        value.get("termination_reason") == "length"
        and completion_tokens >= minimum_tokens
    )
    deadline_passed = bool(
        value.get("error_category") != "generation_timeout"
        and float(latency_ms) < PROFILE_REQUEST_DEADLINE_SECONDS * 1000.0
    )
    expected_passed = bool(
        (reached_cap or not require_cap)
        and deadline_passed
        and (
            value.get("outcome") == "generated_text"
            or value.get("thinking_output_observed") is True
        )
    )
    if (
        value.get("requested_generation_tokens") != generation_tokens
        or value.get("minimum_completion_tokens") != minimum_tokens
        or value.get("reached_generation_cap") is not reached_cap
        or value.get("deadline_passed") is not deadline_passed
        or value.get("passed") is not expected_passed
    ):
        raise ValueError(f"local-model {label} stress status is invalid")
    return value


def validate_readiness(value: object, *, expected_spec: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") not in {
        LEGACY_SCHEMA,
        BOUNDED_SCHEMA,
        CAP_STRESS_SCHEMA,
        SCHEMA,
    }:
        raise ValueError("local-model readiness receipt schema is invalid")
    schema = value.get("schema")
    expected_policy = {
        LEGACY_SCHEMA: legacy_readiness_policy,
        BOUNDED_SCHEMA: bounded_readiness_policy,
        CAP_STRESS_SCHEMA: cap_stress_readiness_policy,
        SCHEMA: readiness_policy,
    }[schema]()
    if value.get("policy") != expected_policy or value.get("status") != "verified":
        raise ValueError("local-model readiness policy is not terminal-passed")
    if expected_spec is not None and value.get("requested_spec") != expected_spec:
        raise ValueError("local-model readiness receipt names another target")
    requested_spec = value.get("requested_spec")
    if not isinstance(requested_spec, str) or not requested_spec.startswith(
        ("vllm:", "ollama:")
    ):
        raise ValueError("local-model readiness target is invalid")
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
    if schema in {CAP_STRESS_SCHEMA, SCHEMA}:
        if (
            not isinstance(execution, dict)
            or set(execution)
            != {
                "conditions",
                "local_execution",
                "per_request_deadline_seconds",
                "selected_generation_tokens",
                "selection_basis",
            }
            or execution.get("per_request_deadline_seconds")
            != PROFILE_REQUEST_DEADLINE_SECONDS
            or execution.get("selection_basis") != "first_descending_stress_pass"
            or not isinstance(execution.get("conditions"), list)
            or not execution["conditions"]
        ):
            raise ValueError("local-model execution profile is invalid")
        configured = list(PROFILE_GENERATION_TOKEN_CANDIDATES)
        observed = [
            item.get("generation_tokens")
            for item in execution["conditions"]
            if isinstance(item, dict)
        ]
        if (
            len(observed) != len(execution["conditions"])
            or len(observed) > len(configured)
            or observed != configured[: len(observed)]
        ):
            raise ValueError("local-model execution profile conditions are invalid")
        passing: list[int] = []
        for index, condition in enumerate(execution["conditions"]):
            if not isinstance(condition, dict) or set(condition) != {
                "deadline_failures",
                "generation_tokens",
                "passed",
                "stress_text",
                "stress_vision",
            }:
                raise ValueError("local-model execution condition is invalid")
            generation_tokens = int(condition["generation_tokens"])
            stress_text = _validate_stress_result(
                condition["stress_text"],
                generation_tokens=generation_tokens,
                label="text",
                require_cap=True,
            )
            stress_vision = condition["stress_vision"]
            observations = [stress_text]
            if "image" in modalities:
                if stress_vision is None:
                    if stress_text.get("passed") is True:
                        raise ValueError(
                            "local-model vision stress evidence is missing after "
                            "passing text"
                        )
                else:
                    stress_vision = _validate_stress_result(
                        stress_vision,
                        generation_tokens=generation_tokens,
                        label="vision",
                        require_cap=schema == CAP_STRESS_SCHEMA,
                    )
                    observations.append(stress_vision)
            elif stress_vision is not None:
                raise ValueError("text-only execution condition contains vision stress")
            deadline_failures = sum(
                observation.get("deadline_passed") is not True
                for observation in observations
            )
            expected_passed = bool(
                all(observation.get("passed") is True for observation in observations)
            )
            if (
                condition["deadline_failures"] != deadline_failures
                or condition["passed"] is not expected_passed
                or (index < len(execution["conditions"]) - 1 and expected_passed)
            ):
                raise ValueError("local-model execution condition status is invalid")
            if expected_passed:
                passing.append(generation_tokens)
        selected = passing[-1] if passing else None
        if execution.get("selected_generation_tokens") != selected or selected is None:
            raise ValueError("local-model execution profile has no passing condition")
        local_execution = execution.get("local_execution")
        if requested_spec.startswith("vllm:"):
            if schema == CAP_STRESS_SCHEMA:
                expected_local_execution = {"max_model_len": -1}
            else:
                expected_local_execution = local_execution
                if (
                    not isinstance(local_execution, dict)
                    or set(local_execution)
                    != {
                        "gpu_memory_utilization",
                        "max_model_len",
                        "tensor_parallel_size",
                    }
                    or local_execution.get("max_model_len") != -1
                    or isinstance(local_execution.get("tensor_parallel_size"), bool)
                    or local_execution.get("tensor_parallel_size") not in {1, 2}
                    or isinstance(local_execution.get("gpu_memory_utilization"), bool)
                    or not isinstance(
                        local_execution.get("gpu_memory_utilization"), (int, float)
                    )
                    or not 0.1
                    <= float(local_execution["gpu_memory_utilization"])
                    <= 0.95
                ):
                    expected_local_execution = None
        elif isinstance(local_execution, dict):
            try:
                thinking = validate_ollama_think(local_execution.get("think"))
            except ValueError as exc:
                raise ValueError("local-model execution condition changed") from exc
            expected_local_execution = {"num_ctx": "fit", "think": thinking}
        else:
            expected_local_execution = None
        if local_execution != expected_local_execution:
            raise ValueError("local-model execution condition changed")
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
        != list(bounded_readiness_policy()["generation_conditions"])
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
    parser.add_argument(
        "--isolated-probe",
        choices=("stress-text", "stress-image", "survey-text", "survey-image"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--generation-tokens", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--probe-start-marker", type=Path, help=argparse.SUPPRESS)
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
    local_execution = _configure_readiness_condition(args.local, config)
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
    if args.isolated_probe is not None:
        stress_probe = args.isolated_probe.startswith("stress-")
        if (
            args.profile_registry is not None
            or args.generation_tokens not in PROFILE_GENERATION_TOKEN_CANDIDATES
            or stress_probe != (args.probe_start_marker is not None)
        ):
            parser.error("isolated readiness probe arguments are invalid")
        if args.probe_start_marker is not None and (
            args.probe_start_marker.parent != args.out.parent
            or args.probe_start_marker
            != args.out.with_suffix(args.out.suffix + ".started")
        ):
            parser.error("isolated readiness probe start marker is invalid")
        if "image" in args.isolated_probe and "image" not in config["modalities"]:
            parser.error("image readiness probe requires an image-capable target")
        _set_generation_tokens(target, args.local, args.generation_tokens)
        try:
            if args.isolated_probe == "stress-text":
                result = _run_marked_generation_stress(
                    target,
                    marker=args.probe_start_marker,
                    kind=args.isolated_probe,
                    requested_spec=args.local,
                    generation_tokens=args.generation_tokens,
                    image=False,
                )
            elif args.isolated_probe == "stress-image":
                result = _run_marked_generation_stress(
                    target,
                    marker=args.probe_start_marker,
                    kind=args.isolated_probe,
                    requested_spec=args.local,
                    generation_tokens=args.generation_tokens,
                    image=True,
                )
            elif args.isolated_probe == "survey-text":
                result = _run_text(target)
            else:
                result = _run_vision(target)
        finally:
            close = getattr(target, "close", None)
            if callable(close):
                close()
        probe = {
            "generation_tokens": args.generation_tokens,
            "kind": args.isolated_probe,
            "requested_spec": args.local,
            "resolved_target": str(target.name),
            "result": result,
            "schema": PROBE_SCHEMA,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("xb") as handle:
            handle.write(_canonical(probe))
        print(json.dumps({"kind": args.isolated_probe, "status": "recorded"}, sort_keys=True))
        return 0
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".readiness-probes-", dir=args.out.parent
        ) as temporary:
            work = Path(temporary)
            conditions, selected_generation_tokens = (
                _profile_generation_conditions_isolated(
                    args,
                    modalities=list(config["modalities"]),
                    expected_target=str(target.name),
                    work=work,
                )
            )
            if selected_generation_tokens is not None:
                text_probe = _run_isolated_probe(
                    args,
                    kind="survey-text",
                    generation_tokens=selected_generation_tokens,
                    expected_target=str(target.name),
                    out=work / "survey-text.json",
                )
                if text_probe["resolved_target"] != str(target.name):
                    raise ValueError("isolated local-model probe target identity differs")
                text = text_probe["result"]
                if "image" in config["modalities"]:
                    vision_probe = _run_isolated_probe(
                        args,
                        kind="survey-image",
                        generation_tokens=selected_generation_tokens,
                        expected_target=str(target.name),
                        out=work / "survey-image.json",
                    )
                    if vision_probe["resolved_target"] != str(target.name):
                        raise ValueError(
                            "isolated local-model probe target identity differs"
                        )
                    vision = vision_probe["result"]
                else:
                    vision = None
            else:
                text = {"status": "not_run_no_safe_generation_cap"}
                vision = (
                    {"status": "not_run_no_safe_generation_cap"}
                    if "image" in config["modalities"]
                    else None
                )
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            close()
    status = (
        "verified"
        if selected_generation_tokens is not None
        and text.get("passed") is True
        and (vision is None or vision.get("passed") is True)
        else "failed"
    )
    receipt: dict[str, object] = {
        "acquisition": acquisition,
        "local_config_sha256": _sha(local_configs),
        "modalities": list(config["modalities"]),
        "execution_profile": {
            "conditions": conditions,
            "local_execution": local_execution,
            "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
            "selected_generation_tokens": selected_generation_tokens,
            "selection_basis": "first_descending_stress_pass",
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
