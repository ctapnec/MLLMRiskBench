"""The vLLM local-target roster (CLI and console share one source).

The roster is the set of vLLM-supported models offered as free on-rig targets.
It is a checked-in curated default that the operator refreshes from vLLM's own
supported-models documentation for the exact vLLM version installed on the rig,
so the roster never drifts from what the rig's vLLM can actually serve.
Selecting a roster model runs it through ``--local``. Hub-backed entries must
first pass the explicit sealed model-acquisition job; measured and preflight
runs use only the verified managed snapshot and never download implicitly.

This performs no provider call or scientific validation. ``--refresh`` makes
read-only HTTPS requests to the public vLLM documentation at the installed
version's tag; every other action is offline. Discovered revisions are left as
``OPERATOR_TODO`` - the operator pins each one before a measured run.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Callable

from ura.strict_json import strict_json_loads

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
_QUANTIZATION_BITS = {
    "none": 16,
    "fp8": 8,
    "bitsandbytes": 4,
    "awq": 4,
    "gptq": 4,
}

# Exact runtime/model/revision/quantization combinations that failed before a
# model call on the maintained rig. These are capability facts, not a blanket
# model blacklist: only the proven-bad precision is excluded from automatic
# selection and operator-visible alternatives (including BF16) remain.
_KNOWN_VLLM_QUANTIZATION_FAILURES = {
    (
        "0.27.1",
        "vllm:llava-hf/llava-v1.6-mistral-7b-hf",
        "2424fdd47412fccc66d91719126b420e9fbd7065",
        "fp8",
    ): (
        "vLLM 0.27.1 loaded this exact LLaVA revision in FP8, then failed "
        "during multimodal-encoder profiling when the scaled-matrix kernel "
        "used .view() on a non-contiguous tensor. This is a proven runtime/"
        "profile incompatibility, not a VRAM shortage; automatic selection "
        "will not retry FP8. BF16 remains available when its hardware fit is "
        "admitted."
    ),
    (
        "0.27.1",
        "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR",
        "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e",
        "bitsandbytes",
    ): (
        "vLLM 0.27.1 BitsAndBytes 4-bit loading failed for this exact "
        "GraySwan RR revision because its model integration has no "
        "packed_modules_mapping. This is a proven architecture/backend "
        "incompatibility, not a VRAM shortage; automatic selection will not "
        "retry BitsAndBytes. BF16 remains available when its hardware fit is "
        "admitted."
    ),
}


def known_vllm_quantization_issue(
    spec: str,
    revision: object,
    quantization: str,
    runtime_version: str | None,
) -> str:
    """Return an exact proven runtime incompatibility, never a name guess."""

    if not isinstance(revision, str) or not runtime_version:
        return ""
    key = (
        runtime_version.strip().lstrip("v"),
        spec,
        revision.strip().lower(),
        quantization.strip().lower(),
    )
    return _KNOWN_VLLM_QUANTIZATION_FAILURES.get(key, "")


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


def _cpu_model() -> str | None:
    """Best available human-readable CPU model without a network probe."""

    if platform.system() == "Linux":
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            cpuinfo = ""
        for key in ("model name", "hardware", "processor"):
            for line in cpuinfo.splitlines():
                name, separator, value = line.partition(":")
                if separator and name.strip().lower() == key and value.strip():
                    return value.strip()
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=3, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return (
        platform.processor().strip()
        or os.environ.get("PROCESSOR_IDENTIFIER", "").strip()
        or platform.machine().strip()
        or None
    )


def _physical_cpu_count() -> int | None:
    """Physical cores when the cross-platform system probe is available."""

    try:
        import psutil  # noqa: PLC0415 - optional defensive fallback

        count = psutil.cpu_count(logical=False)
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            return count
    except (ImportError, OSError, RuntimeError):
        pass
    return None


def _total_ram_bytes() -> int | None:
    """Installed system RAM from psutil, then the POSIX stdlib fallback."""

    try:
        import psutil  # noqa: PLC0415 - optional defensive fallback

        total = psutil.virtual_memory().total
        if isinstance(total, int) and not isinstance(total, bool) and total > 0:
            return total
    except (ImportError, OSError, RuntimeError):
        pass
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        page_count = int(os.sysconf("SC_PHYS_PAGES"))
        total = page_size * page_count
        if total > 0:
            return total
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return None


def detect_system_hardware() -> dict[str, object]:
    """Best-effort CPU/core/RAM inventory with JSON-safe null fallbacks."""

    def safely(probe: Callable[[], object]) -> object | None:
        try:
            return probe()
        except Exception:  # noqa: BLE001 - hardware discovery must not block startup
            return None

    cpu_model = safely(_cpu_model)
    platform_name = safely(platform.platform)
    logical_count = safely(os.cpu_count)
    physical_count = safely(_physical_cpu_count)
    total_bytes = safely(_total_ram_bytes)
    logical_count = (
        logical_count
        if isinstance(logical_count, int) and not isinstance(logical_count, bool)
        and logical_count > 0 else None
    )
    physical_count = (
        physical_count
        if isinstance(physical_count, int) and not isinstance(physical_count, bool)
        and physical_count > 0 else None
    )
    total_bytes = (
        total_bytes
        if isinstance(total_bytes, int) and not isinstance(total_bytes, bool)
        and total_bytes > 0 else None
    )
    model = cpu_model.strip() if isinstance(cpu_model, str) else ""
    platform_text = platform_name.strip() if isinstance(platform_name, str) else ""
    return {
        "available": bool(model or logical_count or physical_count or total_bytes),
        "platform": platform_text or "unknown",
        "cpu_model": model or "unknown",
        "logical_cpu_count": logical_count,
        "physical_cpu_count": physical_count,
        "total_ram_bytes": total_bytes,
        "total_ram_gib": round(total_bytes / (1024 ** 3), 2) if total_bytes else None,
    }


@lru_cache(maxsize=1)
def _cached_startup_system_hardware() -> dict[str, object]:
    return detect_system_hardware()


def startup_system_hardware() -> dict[str, object]:
    """One system probe per process, returned as an isolated copy."""

    return json.loads(json.dumps(_cached_startup_system_hardware()))


def infer_parameter_count_b(spec: str) -> float | None:
    """Infer a basic parameter count from conventional ``7B``/``350M`` ids."""

    # A single expert/active size is not the total set of weights loaded by a
    # mixture-of-experts checkpoint. Treat ambiguous names as unknown instead
    # of turning Mixtral-8x7B into 7B or Llama-4-17B-128E into 17B. Operators
    # can supply an exact total through ``parameter_count_b`` in the roster.
    if (
        re.search(
            r"(?<![a-z0-9])\d+(?:\.\d+)?\s*x\s*\d+(?:\.\d+)?\s*[bm]"
            r"(?=$|[-_./])",
            spec,
            flags=re.IGNORECASE,
        )
        or re.search(
            r"(?<![a-z0-9])\d+\s*e(?=$|[-_./])",
            spec,
            flags=re.IGNORECASE,
        )
        or re.search(
            r"(?<![a-z0-9])moe(?=$|[-_./])", spec, flags=re.IGNORECASE
        )
    ):
        return None

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


def tensor_parallel_capacity_gib(
    hardware: dict[str, object], utilization: float, tensor_parallel_size: int,
) -> float | None:
    """Usable equal-shard capacity for the strongest requested GPU subset."""

    cards: list[float] = []
    for gpu in hardware.get("gpus", []):
        if not isinstance(gpu, dict):
            continue
        try:
            memory_gib = float(gpu["memory_total_mib"]) / 1024
        except (KeyError, TypeError, ValueError):
            continue
        if memory_gib > 0:
            cards.append(memory_gib)
    cards.sort(reverse=True)
    if tensor_parallel_size < 1 or len(cards) < tensor_parallel_size:
        return None
    # Tensor-parallel weight shards are equal, so the smallest selected card
    # limits every shard. Larger cards cannot donate their unused remainder.
    return cards[tensor_parallel_size - 1] * tensor_parallel_size * utilization


def model_hardware_profile(
    spec: str,
    entry: dict[str, object] | None,
    hardware: dict[str, object],
    *,
    default_quantization: str = "",
    runtime_version: str | None = None,
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
    utilization = config.get("gpu_memory_utilization", 0.90)
    utilization = (
        float(utilization)
        if isinstance(utilization, (int, float)) and not isinstance(utilization, bool)
        else 0.90
    )
    gpu_count = int(hardware.get("gpu_count", 0) or 0)
    tp_limit = gpu_count if multi_gpu_compatible else min(gpu_count, 1)
    capacities = {
        tp: capacity
        for tp in range(1, tp_limit + 1)
        if (capacity := tensor_parallel_capacity_gib(
            hardware, utilization, tp
        )) is not None
    }
    available = max(capacities.values(), default=0.0)
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
    minimum_capability = (
        min(capabilities) if capabilities and capability_complete else None
    )
    # These thresholds are the quantizer gates in the pinned vLLM runtime:
    # Fp8Config requires SM 7.5 and BitsAndBytesConfig requires SM 7.0.
    fp8_supported: bool | None = (
        minimum_capability >= 7.5 if minimum_capability is not None else None
    )
    bnb_supported: bool | None = (
        minimum_capability >= 7.0 if minimum_capability is not None else None
    )
    compatibility_note = ""
    revision = config.get("revision")

    def known_issue(candidate: str) -> str:
        return known_vllm_quantization_issue(
            spec, revision, candidate, runtime_version
        )

    explicit = config.get("quantization")
    if isinstance(explicit, str) and explicit.strip():
        quantization = explicit.strip().lower()
        source = "model_override"
    elif default_quantization.strip():
        quantization = default_quantization.strip().lower()
        source = "command_override"
    elif params is not None and available > 0:
        full_precision = params * _VRAM_GIB_PER_BILLION["none"]
        fp8_precision = params * _VRAM_GIB_PER_BILLION["fp8"]
        if full_precision <= available:
            quantization = "none"
            source = "hardware_auto"
        elif (
            fp8_supported is True
            and fp8_precision <= available
            and not known_issue("fp8")
        ):
            # Prefer the highest precision that fits: 16-bit, then FP8,
            # then in-flight BitsAndBytes 4-bit.
            quantization = "fp8"
            source = "hardware_auto"
        elif bnb_supported is True and not known_issue("bitsandbytes"):
            quantization = "bitsandbytes"
            source = "hardware_auto"
        elif fp8_supported is True and not known_issue("fp8"):
            # The model remains visibly incompatible, but FP8 is the smallest
            # supported automatic fallback available on this hardware.
            quantization = "fp8"
            source = "hardware_auto"
        else:
            quantization = "none"
            source = "hardware_auto_unavailable"
            compatibility_note = (
                known_issue("fp8")
                or known_issue("bitsandbytes")
                or (
                    "automatic FP8/4-bit fallback requires NVIDIA compute "
                    "capability 7.0+"
                    if bnb_supported is False else
                    "automatic FP8/4-bit fallback requires a known NVIDIA "
                    "compute capability 7.0+"
                )
            )
    else:
        quantization = "none"
        source = "safe_fallback"
    if quantization not in _QUANTIZATIONS:
        raise ValueError(f"unsupported quantization {quantization!r} for {spec!r}")
    quantization_available: bool | None = None
    selected_known_issue = known_issue(quantization)
    if quantization == "bitsandbytes":
        quantization_available = bnb_supported
        if bnb_supported is not True and not compatibility_note:
            compatibility_note = (
                "bitsandbytes requires a known NVIDIA compute capability 7.0+"
            )
    elif quantization == "fp8":
        quantization_available = fp8_supported
        if fp8_supported is not True and not compatibility_note:
            compatibility_note = (
                "FP8 requires a known NVIDIA compute capability 7.5+"
            )
    if selected_known_issue:
        quantization_available = False
        compatibility_note = selected_known_issue
    estimated = (
        round(params * _VRAM_GIB_PER_BILLION[quantization], 2)
        if params is not None else None
    )
    fitting_tp = [tp for tp, capacity in capacities.items()
                  if estimated is not None and estimated <= capacity]
    fits = bool(fitting_tp) if estimated is not None and capacities else None
    if (
        (quantization == "bitsandbytes" and bnb_supported is not True)
        or (quantization == "fp8" and fp8_supported is not True)
        or bool(selected_known_issue)
    ):
        fits = False
    tensor_parallel_size = min(fitting_tp) if fitting_tp else 1
    full_precision_estimated = (
        round(params * _VRAM_GIB_PER_BILLION["none"], 2)
        if params is not None else None
    )
    full_precision_fits = (
        any(full_precision_estimated <= capacity for capacity in capacities.values())
        if full_precision_estimated is not None and capacities else None
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
        "recommended_precision_bits": _QUANTIZATION_BITS[quantization],
        "quantization_source": source,
        "quantization_available": quantization_available,
        "quantization_required_by_hardware": bool(
            quantization != "none" and fits is True and full_precision_fits is False
        ),
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
            data = strict_json_loads(path.read_text(encoding="utf-8"))
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
