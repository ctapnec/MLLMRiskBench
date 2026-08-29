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

SCHEMA = "ura-local-model-readiness/1"
READINESS_SEED = 20260829
TEXT_SAMPLE_SIZE = 10
TEXT_MIN_CORRECT = 5
VISION_SAMPLE_SIZE = 5
VISION_MIN_CORRECT = 2
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
        "readiness_seed": READINESS_SEED,
        "text_min_correct": TEXT_MIN_CORRECT,
        "text_sample_size": TEXT_SAMPLE_SIZE,
        "vision_min_correct": VISION_MIN_CORRECT,
        "vision_sample_size": VISION_SAMPLE_SIZE,
        "zero_nonresponses_required": True,
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
    return {
        "characters": len(text),
        "latency_ms": round(float(response.latency_ms), 3),
        "outcome": "generated_text" if text else "model_nonresponse",
        "preview": text[:500],
        "tokens": dict(response.tokens),
    }


def _run_text(target: Any) -> dict[str, object]:
    selected = random.Random(READINESS_SEED).sample(TEXT_BANK, TEXT_SAMPLE_SIZE)
    rows: list[dict[str, object]] = []
    for index, (question_id, prompt, expected) in enumerate(selected):
        response = target.generate(
            [DialogTurn(role="user", content=prompt)], seed=READINESS_SEED + index
        )
        text = _response_text(response)
        rows.append(
            {
                **_observation(response, text),
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
        "passed": nonresponses == 0 and correct >= TEXT_MIN_CORRECT,
        "sample_seed": READINESS_SEED,
        "sample_size": TEXT_SAMPLE_SIZE,
    }


def _run_vision(target: Any) -> dict[str, object]:
    pairs = [(left, right) for left in COLORS for right in COLORS if left != right]
    selected = random.Random(READINESS_SEED).sample(pairs, VISION_SAMPLE_SIZE)
    rows: list[dict[str, object]] = []
    for index, (left, right) in enumerate(selected):
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
        left_match = re.search(rf"\b{re.escape(left)}\b", text, flags=re.IGNORECASE)
        right_match = re.search(rf"\b{re.escape(right)}\b", text, flags=re.IGNORECASE)
        rows.append(
            {
                **_observation(response, text),
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
        "passed": nonresponses == 0 and correct >= VISION_MIN_CORRECT,
        "sample_seed": READINESS_SEED,
        "sample_size": VISION_SAMPLE_SIZE,
    }


def validate_readiness(value: object, *, expected_spec: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("local-model readiness receipt schema is invalid")
    if value.get("policy") != readiness_policy() or value.get("status") != "verified":
        raise ValueError("local-model readiness policy is not terminal-passed")
    if expected_spec is not None and value.get("requested_spec") != expected_spec:
        raise ValueError("local-model readiness receipt names another target")
    modalities = value.get("modalities")
    text = value.get("text")
    vision = value.get("vision")
    if not isinstance(modalities, list) or "text" not in modalities or not isinstance(text, dict):
        raise ValueError("local-model readiness modalities are invalid")
    if (
        text.get("passed") is not True
        or text.get("sample_size") != TEXT_SAMPLE_SIZE
        or text.get("minimum_correct") != TEXT_MIN_CORRECT
        or text.get("nonresponses") != 0
        or not isinstance(text.get("correct"), int)
        or text["correct"] < TEXT_MIN_CORRECT
        or not isinstance(text.get("observations"), list)
        or len(text["observations"]) != TEXT_SAMPLE_SIZE
    ):
        raise ValueError("local-model text readiness evidence is invalid")
    if "image" in modalities:
        if (
            not isinstance(vision, dict)
            or vision.get("passed") is not True
            or vision.get("sample_size") != VISION_SAMPLE_SIZE
            or vision.get("minimum_correct") != VISION_MIN_CORRECT
            or vision.get("nonresponses") != 0
            or not isinstance(vision.get("correct"), int)
            or vision["correct"] < VISION_MIN_CORRECT
            or not isinstance(vision.get("observations"), list)
            or len(vision["observations"]) != VISION_SAMPLE_SIZE
        ):
            raise ValueError("local-model vision readiness evidence is invalid")
    elif vision is not None:
        raise ValueError("text-only readiness receipt contains vision evidence")
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
    if args.local.startswith("vllm:"):
        config["max_tokens"] = min(int(config.get("max_tokens", 512)), 256)
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
        text = _run_text(target)
        vision = _run_vision(target) if "image" in config["modalities"] else None
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            close()
    status = "verified" if text["passed"] and (vision is None or vision["passed"]) else "failed"
    receipt: dict[str, object] = {
        "acquisition": acquisition,
        "local_config_sha256": _sha(local_configs),
        "modalities": list(config["modalities"]),
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
