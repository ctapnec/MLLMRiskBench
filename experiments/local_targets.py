"""The vLLM local-target roster (CLI and console share one source).

The roster is the set of vLLM-supported models offered as free on-rig targets.
It is a checked-in curated default that the operator refreshes from vLLM's own
supported-models documentation for the exact vLLM version installed on the rig,
so the roster never drifts from what the rig's vLLM can actually serve.
Selecting a roster model runs it through ``--local`` and vLLM downloads the
weights automatically on first use.

This performs no provider call or scientific validation. ``--refresh`` makes
read-only HTTPS requests to the public vLLM documentation at the installed
version's tag; every other action is offline. Discovered revisions are left as
``OPERATOR_TODO`` - the operator pins each one before a measured run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Callable

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Doc paths tried within a vLLM ref (tag or branch); vLLM has moved the file.
_VLLM_DOC_PATHS = (
    "docs/source/models/supported_models.md",
    "docs/models/supported_models.md",
    "docs/source/models/generative_models.md",
)

#: Vision/audio hints to infer modalities from a repo id.
_IMAGE_HINTS = (
    "vl", "llava", "vision", "vlm", "internvl", "pixtral", "idefics",
    "paligemma", "-vl-", "qwen2-vl", "qwen2.5-vl", "qwen3-vl", "phi-3.5-vision",
    "llama-3.2-11b-vision", "llama-3.2-90b-vision", "gemma-3", "omni", "ocr",
)
_AUDIO_HINTS = ("audio", "ultravox", "qwen2-audio", "omni", "asr", "speech")

_ROSTER_LOCAL = "experiments/vllm-roster.json"
_ROSTER_EXAMPLE = "experiments/rig/vllm-roster.example.json"

# Conservative serving-only estimates. They deliberately include headroom for
# the engine and KV cache instead of presenting weight bytes as a fit promise.
_VRAM_GIB_PER_BILLION = {"none": 2.2, "bitsandbytes": 0.57,
                         "awq": 0.57, "gptq": 0.57, "fp8": 1.15}
_QUANTIZATIONS = frozenset(_VRAM_GIB_PER_BILLION)


def detect_gpu_hardware(
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, object]:
    """Best-effort, offline NVIDIA inventory with a harmless empty fallback."""

    invoke = runner or subprocess.run
    queries = (
        ("index,name,pci.bus_id,memory.total,compute_cap,driver_version", True),
        ("index,name,memory.total", False),
    )
    for query, extended in queries:
        try:
            result = invoke(
                ["nvidia-smi", f"--query-gpu={query}",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=3, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        gpus: list[dict[str, object]] = []
        for raw in result.stdout.splitlines():
            fields = [item.strip() for item in raw.split(",")]
            expected = 6 if extended else 3
            if len(fields) != expected:
                continue
            try:
                gpu_index = int(fields[0])
                memory_mib = int(fields[3] if extended else fields[2])
            except ValueError:
                continue
            if not fields[1] or memory_mib <= 0:
                continue
            gpu: dict[str, object] = {
                "index": gpu_index,
                "name": fields[1],
                "memory_total_mib": memory_mib,
                "vram_gib": round(memory_mib / 1024, 2),
            }
            if extended:
                gpu["pci_bus_id"] = fields[2]
                gpu["compute_capability"] = fields[4]
                gpu["driver_version"] = fields[5]
            gpus.append(gpu)
        if gpus:
            total_mib = sum(int(gpu["memory_total_mib"]) for gpu in gpus)
            return {
                "available": True,
                "source": "nvidia-smi",
                "gpu_count": len(gpus),
                "aggregate_vram_gib": round(total_mib / 1024, 2),
                "max_gpu_vram_gib": round(
                    max(int(gpu["memory_total_mib"]) for gpu in gpus) / 1024, 2
                ),
                "gpus": gpus,
            }
    return {
        "available": False, "source": "none", "gpu_count": 0,
        "aggregate_vram_gib": 0.0, "max_gpu_vram_gib": 0.0, "gpus": [],
    }


@lru_cache(maxsize=1)
def _cached_startup_gpu_hardware() -> dict[str, object]:
    return detect_gpu_hardware()


def startup_gpu_hardware() -> dict[str, object]:
    """One hardware probe per process, returned as an isolated copy."""

    return json.loads(json.dumps(_cached_startup_gpu_hardware()))


def infer_parameter_count_b(spec: str) -> float | None:
    """Infer a basic parameter count from conventional ``7B``/``350M`` ids."""

    matches = list(re.finditer(
        r"(?<![\d.])(\d+(?:\.\d+)?)\s*([bm])(?=$|[-_./])",
        spec, flags=re.IGNORECASE,
    ))
    if not matches:
        return None
    # A lone active-parameter marker (A13B) does not identify total loaded
    # weights.  A total-plus-active id such as 30B-A3B remains inferable as 30B.
    total_matches = [
        match for match in matches
        if match.start() == 0 or spec[match.start() - 1].lower() != "a"
    ]
    if not total_matches:
        return None
    values = [
        float(match.group(1)) * (0.001 if match.group(2).lower() == "m" else 1.0)
        for match in total_matches
    ]
    return max(values)


def model_hardware_profile(
    spec: str,
    entry: dict[str, object] | None,
    hardware: dict[str, object],
    *,
    default_quantization: str = "",
) -> dict[str, object]:
    """Resolve parameters, multi-GPU fit, and one exact quantization choice."""

    config = entry or {}
    raw_params = config.get("parameter_count_b")
    params = (
        float(raw_params)
        if isinstance(raw_params, (int, float)) and not isinstance(raw_params, bool)
        and float(raw_params) > 0
        else infer_parameter_count_b(spec)
    )
    parameter_count_basis = (
        "declared"
        if isinstance(raw_params, (int, float)) and not isinstance(raw_params, bool)
        and float(raw_params) > 0
        else "name_inferred" if params is not None else "unknown"
    )
    multi_gpu = config.get("multi_gpu_compatible")
    # Unknown vLLM roster entries are presumed tensor-parallel compatible. An
    # operator can set false for an architecture known not to support it.
    multi_gpu_compatible = multi_gpu if isinstance(multi_gpu, bool) else True
    multi_gpu_basis = "declared" if isinstance(multi_gpu, bool) else "assumed"
    physical_available = float(
        hardware.get(
            "aggregate_vram_gib" if multi_gpu_compatible else "max_gpu_vram_gib",
            0.0,
        ) or 0.0
    )
    utilization = config.get("gpu_memory_utilization", 0.90)
    utilization = (
        float(utilization)
        if isinstance(utilization, (int, float)) and not isinstance(utilization, bool)
        else 0.90
    )
    available = physical_available * utilization
    capabilities: list[float] = []
    capability_complete = True
    for gpu in hardware.get("gpus", []):
        if not isinstance(gpu, dict):
            capability_complete = False
            continue
        try:
            capabilities.append(float(str(gpu["compute_capability"])))
        except (KeyError, TypeError, ValueError):
            capability_complete = False
    bnb_supported: bool | None = (
        min(capabilities) >= 7.0
        if capabilities and capability_complete else None
    )
    compatibility_note = ""
    explicit = config.get("quantization")
    if isinstance(explicit, str) and explicit.strip():
        quantization = explicit.strip().lower()
        source = "model_override"
    elif default_quantization.strip():
        quantization = default_quantization.strip().lower()
        source = "command_override"
    elif params is not None and available > 0:
        full_precision = params * _VRAM_GIB_PER_BILLION["none"]
        if full_precision <= available:
            quantization = "none"
            source = "hardware_auto"
        elif bnb_supported is True:
            quantization = "bitsandbytes"
            source = "hardware_auto"
        else:
            quantization = "none"
            source = "hardware_auto_unavailable"
            compatibility_note = (
                "automatic bitsandbytes requires NVIDIA compute capability 7.0+"
                if bnb_supported is False else
                "automatic bitsandbytes requires a known NVIDIA compute capability 7.0+"
            )
    else:
        quantization = "none"
        source = "safe_fallback"
    if quantization not in _QUANTIZATIONS:
        raise ValueError(f"unsupported quantization {quantization!r} for {spec!r}")
    quantization_available: bool | None = None
    if quantization == "bitsandbytes":
        quantization_available = bnb_supported
        if bnb_supported is False and not compatibility_note:
            compatibility_note = (
                "bitsandbytes is not supported below NVIDIA compute capability 7.0"
            )
    estimated = (
        round(params * _VRAM_GIB_PER_BILLION[quantization], 2)
        if params is not None else None
    )
    fits = (
        estimated <= available
        if estimated is not None and available > 0 else None
    )
    if quantization == "bitsandbytes" and bnb_supported is False:
        fits = False
    gpu_count = int(hardware.get("gpu_count", 0) or 0)
    max_gpu_vram = (
        float(hardware.get("max_gpu_vram_gib", 0.0) or 0.0) * utilization
    )
    tensor_parallel_size = 1
    if (
        multi_gpu_compatible and gpu_count > 1 and estimated is not None
        and max_gpu_vram > 0 and estimated > max_gpu_vram
    ):
        tensor_parallel_size = min(
            gpu_count, max(2, int((estimated + max_gpu_vram - 0.01) // max_gpu_vram))
        )
    return {
        "parameter_count_b": params,
        "parameter_count_basis": parameter_count_basis,
        "multi_gpu_compatible": multi_gpu_compatible,
        "multi_gpu_support_basis": multi_gpu_basis,
        "recommended_tensor_parallel_size": tensor_parallel_size,
        "available_vram_gib": round(available, 2),
        "estimated_vram_gib": estimated,
        "recommended_quantization": quantization,
        "quantization_source": source,
        "quantization_available": quantization_available,
        "compatibility_note": compatibility_note,
        "fits": fits,
    }


def infer_modalities(spec: str) -> list[str]:
    # Match against the repo id only; the "vllm:" prefix itself contains "vl".
    lower = spec.lower()
    if lower.startswith("vllm:"):
        lower = lower[len("vllm:"):]
    mods = ["text"]
    if any(hint in lower for hint in _IMAGE_HINTS):
        mods.append("image")
    if any(hint in lower for hint in _AUDIO_HINTS):
        mods.append("audio")
    return mods


def installed_vllm_version() -> str | None:
    """The vLLM version to sync against: env override, then the import."""

    env = os.environ.get("VLLM_VERSION", "").strip().lstrip("v")
    if env:
        return env
    try:
        import vllm  # noqa: PLC0415 - optional heavy dependency, probed lazily

        return str(getattr(vllm, "__version__", "")).strip() or None
    except Exception:  # noqa: BLE001 - vllm is optional and may be absent
        return None


def load_roster(repo_root: Path = _REPO_ROOT) -> dict[str, object]:
    """The full roster document (with metadata), local override then example."""

    for candidate in (_ROSTER_LOCAL, _ROSTER_EXAMPLE):
        path = repo_root / candidate
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _models_map(document: dict[str, object]) -> dict[str, object]:
    models = document.get("models")
    if isinstance(models, dict):
        return models
    # Back-compat: a flat {spec: config} document is its own model map.
    return {k: v for k, v in document.items() if isinstance(v, dict)}


def roster_version(repo_root: Path = _REPO_ROOT) -> str | None:
    version = load_roster(repo_root).get("vllm_version")
    return str(version) if isinstance(version, str) and version else None


def roster_models(
    repo_root: Path = _REPO_ROOT,
    hardware: dict[str, object] | None = None,
    *,
    include_unfit: bool = False,
) -> list[dict[str, object]]:
    """``[{"spec", "modalities"}]`` for every vLLM roster entry."""

    detected = hardware if hardware is not None else detect_gpu_hardware()
    out: list[dict[str, object]] = []
    for spec, entry in _models_map(load_roster(repo_root)).items():
        mods = ["text"]
        if isinstance(entry, dict) and isinstance(entry.get("modalities"), list):
            mods = [str(m) for m in entry["modalities"] if isinstance(m, str)] or ["text"]
        config = entry if isinstance(entry, dict) else {}
        model = {
            "spec": str(spec), "modalities": mods,
            **model_hardware_profile(str(spec), config, detected),
        }
        if include_unfit or model["fits"] is True:
            out.append(model)
    return out


def _fetch(url: str, *, timeout: int = 20, max_bytes: int = 8_000_000) -> str:
    import urllib.request  # noqa: PLC0415 - stdlib, imported only on refresh

    request = urllib.request.Request(url, headers={"User-Agent": "ura-rig"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https vLLM doc URLs
        return response.read(max_bytes).decode("utf-8", errors="replace")


def parse_vllm_doc(markdown: str) -> list[str]:
    """Extract ``org/model`` HF identities from the vLLM supported-models doc.

    Only backtick code spans of exactly ``org/model`` shape count; a couple of
    non-model path prefixes seen in the doc (docs/, examples/, http URLs) are
    excluded so the roster stays model identities.
    """

    ids = set()
    excluded = ("docs", "examples", "http", "https", "tests", "vllm")
    for match in re.findall(r"`([A-Za-z0-9][\w.-]+/[\w.-]+)`", markdown):
        if match.count("/") != 1:
            continue
        if match.split("/", 1)[0].lower() in excluded:
            continue
        ids.add(match)
    return sorted(ids)


def _candidate_urls(version: str | None) -> list[str]:
    refs = []
    if version:
        refs.append("v" + version)
    refs.append("main")
    return [
        f"https://raw.githubusercontent.com/vllm-project/vllm/{ref}/{path}"
        for ref in refs for path in _VLLM_DOC_PATHS
    ]


def refresh_roster(
    repo_root: Path = _REPO_ROOT, *, version: str | None = None,
) -> dict[str, object]:
    """Fetch the version-matched vLLM doc and write the local roster.

    Resolves the vLLM version (argument, else the rig's installed version),
    fetches that tag's supported-models doc, merges the discovered identities
    with the existing roster (keeping operator-pinned revisions), and writes
    ``experiments/vllm-roster.json`` stamped with the version it synced to.
    Raises on total fetch failure.
    """

    resolved = (version or installed_vllm_version() or "").strip().lstrip("v") or None
    markdown = ""
    used_url = ""
    errors = []
    for url in _candidate_urls(resolved):
        try:
            markdown = _fetch(url)
            used_url = url
            break
        except Exception as exc:  # noqa: BLE001 - report any transport failure
            errors.append(f"{url}: {exc}")
    if not markdown:
        raise RuntimeError("could not fetch vLLM supported-models doc: "
                           + "; ".join(errors))
    existing = _models_map(load_roster(repo_root))
    models: dict[str, object] = dict(existing)
    for repo_id in parse_vllm_doc(markdown):
        spec = f"vllm:{repo_id}"
        if spec in models:
            continue
        models[spec] = {
            "revision": "OPERATOR_TODO",
            "modalities": infer_modalities(spec),
            "parameter_count_b": infer_parameter_count_b(spec),
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.85,
            "max_tokens": 4096,
        }
    document = {
        "vllm_version": resolved,
        "source_url": used_url,
        "models": dict(sorted(models.items())),
    }
    (repo_root / _ROSTER_LOCAL).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "The vLLM local-target roster shared by the CLI and rig console. "
            "Lists the roster, or refreshes it from vLLM's supported-models "
            "documentation for the installed vLLM version (read-only HTTPS)"
        )
    )
    parser.add_argument(
        "--refresh", action="store_true",
        help="fetch the version-matched vLLM doc and update the local roster",
    )
    parser.add_argument(
        "--vllm-version", default=None,
        help="override the vLLM version to sync against (default: the rig's "
             "installed vllm or $VLLM_VERSION)",
    )
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root) if args.repo_root else _REPO_ROOT
    if args.refresh:
        try:
            document = refresh_roster(repo_root, version=args.vllm_version)
        except Exception as exc:  # noqa: BLE001 - surface the transport error
            print(f"refresh failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "refreshed": True,
            "vllm_version": document.get("vllm_version"),
            "models": len(_models_map(document)),
            "source_url": document.get("source_url"),
        }))
        return 0
    hardware = detect_gpu_hardware()
    print(json.dumps({
        "vllm_version": roster_version(repo_root),
        "hardware": hardware,
        "models": roster_models(repo_root, hardware),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
