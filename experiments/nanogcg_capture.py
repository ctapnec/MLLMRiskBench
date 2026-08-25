"""Prepare one sealed, attributable NanoGCG suffix for later Runner replay.

Plan-only mode derives the exact surrogate acquisition request. Capture mode
consumes that plan, its receipt and sealed store under the verified NanoGCG venv,
performs one bounded GCG search, and writes provenance plus a replay config.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
for _bootstrap in (ROOT, ROOT / "src"):
    if str(_bootstrap) not in sys.path:
        sys.path.insert(0, str(_bootstrap))

from experiments.framework_runtime_installer import (  # noqa: E402
    RECEIPT_NAME as FRAMEWORK_RECEIPT_NAME,
    Layout,
    canonical_python_interpreter,
    load_lock,
    published_store,
    select_frameworks,
    verify_one,
)
from experiments.run_matrix import _select_corpus  # noqa: E402
from ura.adapters._native_artifacts import (  # noqa: E402
    json_sha256,
    read_binary_artifact,
)
from ura.converters.advbench import AdvBenchConverter  # noqa: E402
from ura.model_acquisition import (  # noqa: E402
    load_plan,
    load_receipt,
    write_document_create_only,
)
from ura.model_acquisition_runtime import (  # noqa: E402
    admit_managed_model_runtime,
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    hf_offline_environment_overrides,
    transformers_managed_snapshot_args,
)
from ura.project_revision import (  # noqa: E402
    load_project_revision_file,
    project_revision_binding,
    recheck_project_revision,
    validate_project_revision_binding,
)
from ura.strict_json import strict_json_loads  # noqa: E402


FORMAT_VERSION = "ura-nanogcg-suffix-capture/1"
MODEL_ID = "Qwen/Qwen2.5-0.5B-Instruct"
MODEL_REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
MODEL_LICENSE = "apache-2.0"
DEFAULT_CORPUS_NAME = "advbench_harmful"
DEFAULT_SOURCE_ROW_INDEX = 245
DEFAULT_LIMIT = 1
DEFAULT_SAMPLE_SEED = 105
DEFAULT_OPTIM_STRING = "x x x x x x x x x x x x x x x x x x x x"
RUN_MATRIX = ROOT / "experiments" / "run_matrix.py"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _source_selection(args: argparse.Namespace) -> dict[str, Any]:
    resolved, raw = read_binary_artifact(Path(args.source), max_bytes=4 * 1024 * 1024)
    rows = AdvBenchConverter().parse(resolved)
    _resolved_after, raw_after = read_binary_artifact(
        resolved, max_bytes=4 * 1024 * 1024
    )
    expected_ids = [f"advbench:{index}" for index in range(520)]
    if raw_after != raw or len(rows) != 520 or [row.id for row in rows] != expected_ids:
        raise ValueError("capture requires the stable 520-row AdvBench release")
    selected, indices, clusters, _population = _select_corpus(
        args.corpus_name, rows, args.limit, args.sample_seed
    )
    expected_id = f"advbench:{args.source_row_index}"
    if indices != [args.source_row_index] or clusters != [expected_id]:
        raise ValueError(
            "capture selection must choose its source row alone; "
            f"observed {[row.id for row in selected]!r}"
        )
    row = selected[0]
    goal = row.payload_text or ""
    target = row.meta.get("target")
    if not goal.strip() or not isinstance(target, str) or not target.strip():
        raise ValueError("selected AdvBench row lacks its exact goal/target pair")
    return {
        "runner_selection": {
            "corpus_name": args.corpus_name,
            "limit": args.limit,
            "sample_seed": args.sample_seed,
            "selected_source_ids": [expected_id],
        },
        "source_artifact": {
            "bytes": len(raw),
            "file": resolved.name,
            "records": len(rows),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "source_row": {
            "datapoint_id": row.id,
            "goal": goal,
            "goal_sha256": hashlib.sha256(goal.encode()).hexdigest(),
            "row_index": args.source_row_index,
            "target": target,
            "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
        },
    }


def _gcg_config(args: argparse.Namespace) -> dict[str, Any]:
    for field, minimum, maximum in (
        ("num_steps", 1, 1000),
        ("search_width", 1, 2048),
        ("topk", 1, 2048),
        ("n_replace", 1, 32),
        ("buffer_size", 0, 256),
    ):
        value = getattr(args, field)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"--{field.replace('_', '-')} must be in [{minimum}, {maximum}]")
    if args.batch_size is not None and not 1 <= args.batch_size <= 2048:
        raise ValueError("--batch-size must be in [1, 2048]")
    if not args.optim_str_init.strip() or len(args.optim_str_init.encode()) > 4096:
        raise ValueError("--optim-str-init must be nonblank and at most 4096 bytes")
    if args.device != "cuda" and re.fullmatch(r"cuda:[0-9]+", args.device) is None:
        raise ValueError("--device must be cuda or cuda:<index>")
    if args.torch_dtype not in {"float16", "bfloat16"}:
        raise ValueError("--torch-dtype must be float16 or bfloat16")
    return {
        "add_space_before_target": args.add_space_before_target,
        "allow_non_ascii": args.allow_non_ascii,
        "batch_size": args.batch_size,
        "buffer_size": args.buffer_size,
        "early_stop": args.early_stop,
        "filter_ids": args.filter_ids,
        "mellowmax_alpha": 1.0,
        "n_replace": args.n_replace,
        "num_steps": args.num_steps,
        "optim_str_init": args.optim_str_init,
        "probe_sampling_config": None,
        "search_width": args.search_width,
        "seed": args.gcg_seed,
        "topk": args.topk,
        "use_mellowmax": False,
        "use_prefix_cache": args.use_prefix_cache,
        "verbosity": "WARNING",
    }


def _framework_binding(lock_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    lock = load_lock(lock_path)
    entries = select_frameworks(lock, ["nanogcg"])
    if len(entries) != 1:
        raise ValueError("framework lock lacks one NanoGCG runtime")
    entry = entries[0]
    _path, lock_raw = read_binary_artifact(lock_path, max_bytes=4 * 1024 * 1024)
    artifact = entry["artifacts"][0]
    return lock, {
        "entry": entry,
        "binding": {
            "env_slug": entry["env_slug"],
            "framework": "nanogcg",
            "inventory_sha256": entry["expected_inventory"]["sha256"],
            "lock_id": lock["lock_id"],
            "lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
            "runtime": entry["runtime"],
            "version": entry["version"],
            "wheel_sha256": artifact["sha256"],
        },
    }


def _project(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt, descriptor = load_project_revision_file(
        Path(args.project_revision), args.project_revision_sha256, RUN_MATRIX
    )
    return receipt, project_revision_binding(receipt, descriptor)


def _runtime_selection(
    args: argparse.Namespace,
    *,
    source: Mapping[str, Any],
    gcg_config: Mapping[str, Any],
    framework: Mapping[str, Any],
    project: Mapping[str, Any],
):  # noqa: ANN201 - RuntimeSelection is the public API's return type
    requirements = collect_run_requirements(
        target_specs=[], local_configs={}, judge_names=[], judge_model="",
        attacker_names=["nanogcg"],
        attacker_configs={"nanogcg": {
            "model_id": args.model_id,
            "model_revision": args.model_revision,
        }},
    )
    config = {
        "device": args.device,
        "gcg": dict(gcg_config),
        "model_id": args.model_id,
        "model_revision": args.model_revision,
        "torch_dtype": args.torch_dtype,
    }
    return build_runtime_selection(
        requirements,
        input_bindings={
            "nanogcg_config": json_sha256(config),
            "nanogcg_framework_runtime": json_sha256(framework),
            "nanogcg_project_revision": json_sha256(project),
            "nanogcg_source_row": json_sha256(source),
        },
    )


def _verified_framework_runtime(
    args: argparse.Namespace,
    *,
    lock: Mapping[str, Any],
    framework: Mapping[str, Any],
) -> tuple[Layout, dict[str, Any]]:
    layout = Layout(
        Path(args.framework_env_root).absolute(),
        Path(args.framework_state_root).absolute(),
    )
    for root in (layout.env_root, layout.state_root):
        if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
            raise ValueError("framework roots must be resolved non-link directories")
    entry = framework["entry"]
    verify_one(entry, lock, layout)
    interpreter = canonical_python_interpreter(entry, lock, layout)
    try:
        correct_interpreter = os.path.samefile(sys.executable, interpreter)
    except OSError:
        correct_interpreter = False
    if not correct_interpreter:
        raise ValueError("capture must run under the verified NanoGCG interpreter")
    receipt_path = published_store(entry, lock, layout) / FRAMEWORK_RECEIPT_NAME
    _path, receipt_raw = read_binary_artifact(receipt_path, max_bytes=1024 * 1024)
    receipt = strict_json_loads(receipt_raw)
    if not isinstance(receipt, dict) or receipt.get("status") != "passed":
        raise ValueError("NanoGCG framework receipt is not passing")
    return layout, {
        **framework["binding"],
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
    }


def _cleanup_loaded(loaded: tuple[object, object]) -> None:
    model, _tokenizer = loaded
    to = getattr(model, "to", None)
    if callable(to):
        to("cpu")
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass


def _capture_result(
    args: argparse.Namespace,
    *,
    runtime: Any,
    requirement: Any,
    source: Mapping[str, Any],
    gcg_config: Mapping[str, Any],
) -> dict[str, Any]:
    import nanogcg
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    dtype = torch.float16 if args.torch_dtype == "float16" else torch.bfloat16

    def construct(snapshot: Path) -> tuple[object, object]:
        model_path, local_only = transformers_managed_snapshot_args(snapshot)
        tokenizer = AutoTokenizer.from_pretrained(model_path, **local_only)
        model = AutoModelForCausalLM.from_pretrained(
            model_path, torch_dtype=dtype, **local_only
        ).to(args.device)
        model.eval()
        return model, tokenizer

    loaded = runtime.construct(requirement, construct, cleanup=_cleanup_loaded)
    try:
        model, tokenizer = loaded
        result = runtime.private_execution(
            "nanogcg_surrogate",
            lambda: nanogcg.run(
                model, tokenizer,
                source["source_row"]["goal"],
                source["source_row"]["target"],
                nanogcg.GCGConfig(**dict(gcg_config)),
            ),
        )
        best_string = getattr(result, "best_string", None)
        best_loss = getattr(result, "best_loss", None)
        losses = getattr(result, "losses", None)
        strings = getattr(result, "strings", None)
        if (
            not isinstance(best_string, str) or not best_string.strip()
            or isinstance(best_loss, bool) or not isinstance(best_loss, (int, float))
            or not math.isfinite(float(best_loss))
            or not isinstance(losses, list) or not 1 <= len(losses) <= args.num_steps + 1
            or not isinstance(strings, list) or len(strings) != len(losses)
            or any(isinstance(loss, bool) or not isinstance(loss, (int, float))
                   or not math.isfinite(float(loss)) for loss in losses)
            or any(not isinstance(text, str) or not text.strip() for text in strings)
        ):
            raise ValueError("NanoGCG returned an invalid result trajectory")
        return {
            "best_loss": float(best_loss),
            "best_string": best_string,
            "losses": [float(loss) for loss in losses],
            "strings": list(strings),
        }
    finally:
        _cleanup_loaded(loaded)


def validate_capture(document: object) -> dict[str, Any]:
    """Validate the capture fields cited by the replay config."""

    if not isinstance(document, dict) or document.get("format_version") != FORMAT_VERSION:
        raise ValueError("invalid NanoGCG capture format")
    unsigned = {key: value for key, value in document.items() if key != "content_sha256"}
    if document.get("content_sha256") != json_sha256(unsigned):
        raise ValueError("NanoGCG capture content digest is stale")
    validate_project_revision_binding(
        document.get("project_revision"), allow_not_required=False
    )
    if document.get("surrogate") != {
        "license": MODEL_LICENSE, "repo_id": MODEL_ID, "revision": MODEL_REVISION,
    }:
        raise ValueError("NanoGCG surrogate identity is invalid")
    source = document.get("source")
    row = source.get("source_row") if isinstance(source, dict) else None
    if not isinstance(row, dict) or row.get("datapoint_id") != "advbench:245":
        raise ValueError("NanoGCG source identity is invalid")
    for field in ("goal", "target"):
        value = row.get(field)
        if not isinstance(value, str) or hashlib.sha256(value.encode()).hexdigest() != row.get(f"{field}_sha256"):
            raise ValueError("NanoGCG source content identity is stale")
    framework = document.get("framework_runtime")
    framework_receipt = framework.get("receipt") if isinstance(framework, dict) else None
    if (
        not isinstance(framework_receipt, dict)
        or framework_receipt.get("framework") != "nanogcg"
        or framework_receipt.get("version") != "0.3.0"
        or framework_receipt.get("status") != "passed"
        or framework_receipt.get("provider_calls") != 0
        or framework_receipt.get("model_calls") != 0
    ):
        raise ValueError("NanoGCG framework receipt is invalid")
    acquisition = document.get("model_acquisition")
    resource = acquisition.get("resource") if isinstance(acquisition, dict) else None
    runtime = acquisition.get("runtime") if isinstance(acquisition, dict) else None
    if (
        not isinstance(resource, dict)
        or resource.get("repo_id") != MODEL_ID
        or resource.get("revision") != MODEL_REVISION
        or resource.get("roles") != ["nanogcg_surrogate"]
        or not isinstance(resource.get("tree_sha256"), str)
        or _HEX64.fullmatch(resource["tree_sha256"]) is None
        or not isinstance(runtime, dict)
        or runtime.get("resources") != [{
            "repo_id": MODEL_ID,
            "revision": MODEL_REVISION,
            "roles": ["nanogcg_surrogate"],
        }]
    ):
        raise ValueError("NanoGCG acquisition provenance is invalid")
    result = document.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("best_string"), str) or not result["best_string"].strip():
        raise ValueError("NanoGCG captured suffix is blank")
    if document.get("execution") != {
        "framework_generation_calls": 1, "hosted_calls": 0, "target_calls": 0,
    }:
        raise ValueError("NanoGCG call accounting is invalid")
    return document


def _output_target(value: str) -> Path:
    requested = Path(value).expanduser().absolute()
    requested.parent.mkdir(parents=True, exist_ok=True)
    if (
        requested.parent.resolve(strict=True) != requested.parent
        or requested.exists() or requested.is_symlink()
    ):
        raise FileExistsError(f"refusing unsafe or existing output: {requested}")
    return requested


def _write_create_only(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _replay_config(
    best_string: str,
    artifact_sha256: str,
    *,
    captured_source_id: str,
    captured_target: str,
) -> dict[str, object]:
    """Return replay-only fields; capture knobs remain in the capture artifact."""

    return {"nanogcg": {
        "captured_surrogate_id": MODEL_ID,
        "captured_surrogate_revision": MODEL_REVISION,
        "captured_source_id": captured_source_id,
        "captured_target": captured_target,
        "suffix": best_string,
        "suffix_source": f"{FORMAT_VERSION}@sha256:{artifact_sha256}",
    }}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--corpus-name", default=DEFAULT_CORPUS_NAME)
    parser.add_argument("--source-row-index", type=int, default=DEFAULT_SOURCE_ROW_INDEX)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--sample-seed", type=int, default=DEFAULT_SAMPLE_SEED)
    parser.add_argument("--model-id", default=MODEL_ID)
    parser.add_argument("--model-revision", default=MODEL_REVISION)
    parser.add_argument("--framework-lock", required=True)
    parser.add_argument("--framework-env-root")
    parser.add_argument("--framework-state-root")
    parser.add_argument("--project-revision", required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--num-steps", type=int, default=20)
    parser.add_argument("--search-width", type=int, default=64)
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--topk", type=int, default=64)
    parser.add_argument("--n-replace", type=int, default=1)
    parser.add_argument("--buffer-size", type=int, default=0)
    parser.add_argument("--optim-str-init", default=DEFAULT_OPTIM_STRING)
    parser.add_argument("--gcg-seed", type=int, default=0)
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--torch-dtype", default="float16")
    parser.add_argument("--early-stop", action="store_true")
    parser.add_argument("--allow-non-ascii", action="store_true")
    parser.add_argument("--filter-ids", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--use-prefix-cache", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--add-space-before-target", action="store_true")
    parser.add_argument("--model-acquisition-plan-only", action="store_true")
    parser.add_argument("--model-acquisition-plan-dir")
    parser.add_argument("--model-acquisition-plan")
    parser.add_argument("--model-acquisition-plan-sha256")
    parser.add_argument("--model-acquisition-receipt")
    parser.add_argument("--model-acquisition-receipt-sha256")
    parser.add_argument("--model-acquisition-store")
    parser.add_argument("--artifact-out")
    parser.add_argument("--attacker-config-out")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.model_id != MODEL_ID or args.model_revision != MODEL_REVISION:
        raise ValueError("capture requires the pinned Qwen 0.5B surrogate")
    source = _source_selection(args)
    gcg_config = _gcg_config(args)
    project_receipt, project = _project(args)
    lock, framework = _framework_binding(Path(args.framework_lock).absolute())
    selection = _runtime_selection(
        args, source=source, gcg_config=gcg_config,
        framework=framework["binding"], project=project,
    )
    prospective_plan = build_runtime_plan(selection)
    acquisition_inputs = (
        args.model_acquisition_plan, args.model_acquisition_plan_sha256,
        args.model_acquisition_receipt, args.model_acquisition_receipt_sha256,
        args.model_acquisition_store,
    )
    if args.model_acquisition_plan_only:
        if not args.model_acquisition_plan_dir or any(acquisition_inputs):
            raise ValueError("plan-only mode needs only --model-acquisition-plan-dir")
        path, digest = write_document_create_only(
            Path(args.model_acquisition_plan_dir).absolute(), prospective_plan,
            identifier=prospective_plan["plan_id"], suffix="plan.json",
        )
        print(f"NanoGCG acquisition plan -> {path} (sha256:{digest})")
        return 0

    required = {
        "--framework-env-root": args.framework_env_root,
        "--framework-state-root": args.framework_state_root,
        "--model-acquisition-plan": args.model_acquisition_plan,
        "--model-acquisition-plan-sha256": args.model_acquisition_plan_sha256,
        "--model-acquisition-receipt": args.model_acquisition_receipt,
        "--model-acquisition-receipt-sha256": args.model_acquisition_receipt_sha256,
        "--model-acquisition-store": args.model_acquisition_store,
        "--artifact-out": args.artifact_out,
        "--attacker-config-out": args.attacker_config_out,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError("capture mode is missing: " + ", ".join(missing))
    artifact_out = _output_target(args.artifact_out)
    config_out = _output_target(args.attacker_config_out)
    if artifact_out == config_out:
        raise ValueError("capture and config outputs must differ")

    layout, framework_runtime = _verified_framework_runtime(
        args, lock=lock, framework=framework
    )
    plan = load_plan(
        args.model_acquisition_plan,
        expected_sha256=args.model_acquisition_plan_sha256,
    )
    if plan != prospective_plan:
        raise ValueError("NanoGCG acquisition plan differs from the derived request")
    receipt = load_receipt(
        args.model_acquisition_receipt,
        expected_sha256=args.model_acquisition_receipt_sha256,
        plan=plan,
    )
    runtime, runtime_descriptor = admit_managed_model_runtime(
        selection=selection,
        plan_path=args.model_acquisition_plan,
        plan_sha256=args.model_acquisition_plan_sha256,
        receipt_path=args.model_acquisition_receipt,
        receipt_sha256=args.model_acquisition_receipt_sha256,
        managed_store=args.model_acquisition_store,
    )
    requirements = [item for item in selection.requirements if item.role == "nanogcg_surrogate"]
    resources = [item for item in receipt["resources"] if "nanogcg_surrogate" in item["roles"]]
    if len(requirements) != 1 or len(resources) != 1:
        raise ValueError("NanoGCG acquisition lacks one surrogate resource")

    offline = hf_offline_environment_overrides()
    old_environment = {key: os.environ.get(key) for key in offline}
    os.environ.update(offline)
    try:
        result = _capture_result(
            args, runtime=runtime, requirement=requirements[0],
            source=source, gcg_config=gcg_config,
        )
        runtime_descriptor = runtime.admit()
        verify_one(framework["entry"], lock, layout)
        recheck_project_revision(project_receipt, RUN_MATRIX)
    finally:
        for key, value in old_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    unsigned = {
        "execution": {
            "framework_generation_calls": 1, "hosted_calls": 0, "target_calls": 0,
        },
        "format_version": FORMAT_VERSION,
        "framework_runtime": framework_runtime,
        "gcg_config": {
            "device": args.device, "nanogcg": gcg_config,
            "torch_dtype": args.torch_dtype,
        },
        "model_acquisition": {
            "resource": resources[0], "runtime": runtime_descriptor,
        },
        "project_revision": project,
        "result": result,
        "source": source,
        "surrogate": {
            "license": MODEL_LICENSE, "repo_id": MODEL_ID,
            "revision": MODEL_REVISION,
        },
    }
    capture = validate_capture({**unsigned, "content_sha256": json_sha256(unsigned)})
    artifact_raw = json.dumps(
        capture, ensure_ascii=False, indent=2, sort_keys=True
    ).encode() + b"\n"
    if len(artifact_raw) > 4 * 1024 * 1024:
        raise ValueError("NanoGCG capture exceeds 4 MiB")
    artifact_sha256 = hashlib.sha256(artifact_raw).hexdigest()
    config = _replay_config(
        result["best_string"],
        artifact_sha256,
        captured_source_id=source["source_row"]["datapoint_id"],
        captured_target=source["source_row"]["target"],
    )
    config_raw = json.dumps(
        config, ensure_ascii=False, indent=2, sort_keys=True
    ).encode() + b"\n"
    _write_create_only(artifact_out, artifact_raw)
    _write_create_only(config_out, config_raw)
    print(f"NanoGCG suffix capture -> {artifact_out} (sha256:{artifact_sha256})")
    print(f"NanoGCG replay config -> {config_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
