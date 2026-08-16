from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from experiments import local_targets, run_matrix
from experiments.rig_web import RigWebApp
from ura.targets.local import VLLMTarget


def _rig_hardware(capability: str = "8.9") -> dict[str, object]:
    return {
        "available": True,
        "source": "test",
        "gpu_count": 2,
        "aggregate_vram_gib": 49128 / 1024,
        "max_gpu_vram_gib": 24564 / 1024,
        "gpus": [
            {"index": 0, "compute_capability": capability,
             "memory_total_mib": 24564},
            {"index": 1, "compute_capability": capability,
             "memory_total_mib": 24564},
        ],
    }


def test_nvidia_smi_inventory_and_no_gpu_fallback() -> None:
    def success(argv, **_kwargs):  # noqa: ANN001
        assert "index,name,pci.bus_id,memory.total,compute_cap,driver_version" in argv[1]
        return subprocess.CompletedProcess(
            argv, 0,
            "0, NVIDIA GeForce RTX 4090, 0000:01:00.0, 24564, 8.9, 610.57.04\n"
            "1, NVIDIA GeForce RTX 4090, 0000:02:00.0, 24564, 8.9, 610.57.04\n",
            "",
        )

    detected = local_targets.detect_gpu_hardware(success)
    assert detected["gpu_count"] == 2
    assert detected["aggregate_vram_gib"] == round(49128 / 1024, 2)
    assert detected["gpus"][1]["index"] == 1
    assert detected["gpus"][0]["compute_capability"] == "8.9"

    def missing(*_args, **_kwargs):
        raise FileNotFoundError

    assert local_targets.detect_gpu_hardware(missing)["available"] is False


def test_system_hardware_inventory_is_simple_and_json_safe(monkeypatch) -> None:
    monkeypatch.setattr(local_targets, "_cpu_model", lambda: "Example 32-Core CPU")
    monkeypatch.setattr(local_targets, "_physical_cpu_count", lambda: 32)
    monkeypatch.setattr(local_targets, "_total_ram_bytes", lambda: 128 * 1024 ** 3)
    monkeypatch.setattr(local_targets.os, "cpu_count", lambda: 64)
    monkeypatch.setattr(
        local_targets.platform, "platform", lambda: "Linux-6.8.0-x86_64"
    )

    detected = local_targets.detect_system_hardware()

    assert detected == {
        "available": True,
        "platform": "Linux-6.8.0-x86_64",
        "cpu_model": "Example 32-Core CPU",
        "logical_cpu_count": 64,
        "physical_cpu_count": 32,
        "total_ram_bytes": 128 * 1024 ** 3,
        "total_ram_gib": 128.0,
    }
    assert json.loads(json.dumps(detected)) == detected


def test_system_hardware_probe_fails_gracefully(monkeypatch) -> None:
    def unavailable():
        raise OSError("not available")

    monkeypatch.setattr(local_targets, "_cpu_model", unavailable)
    monkeypatch.setattr(local_targets, "_physical_cpu_count", unavailable)
    monkeypatch.setattr(local_targets, "_total_ram_bytes", unavailable)
    monkeypatch.setattr(local_targets.os, "cpu_count", unavailable)
    monkeypatch.setattr(local_targets.platform, "platform", unavailable)

    assert local_targets.detect_system_hardware() == {
        "available": False,
        "platform": "unknown",
        "cpu_model": "unknown",
        "logical_cpu_count": None,
        "physical_cpu_count": None,
        "total_ram_bytes": None,
        "total_ram_gib": None,
    }


def test_70b_auto_fit_resolves_bitsandbytes_and_tp2() -> None:
    profile = local_targets.model_hardware_profile(
        "vllm:org/model-70B", {"gpu_memory_utilization": 0.85}, _rig_hardware()
    )
    assert profile["recommended_quantization"] == "bitsandbytes"
    assert profile["recommended_precision_bits"] == 4
    assert profile["recommended_tensor_parallel_size"] == 2
    assert profile["quantization_required_by_hardware"] is True
    assert profile["fits"] is True
    assert profile["multi_gpu_support_basis"] == "assumed"


def test_auto_fit_prefers_16_then_8_then_4_bit_precision() -> None:
    full_precision = local_targets.model_hardware_profile(
        "vllm:org/model-13B", {"gpu_memory_utilization": 0.85}, _rig_hardware()
    )
    assert full_precision["recommended_quantization"] == "none"
    assert full_precision["recommended_precision_bits"] == 16
    assert full_precision["recommended_tensor_parallel_size"] == 2

    fp8 = local_targets.model_hardware_profile(
        "vllm:org/model-34B", {"gpu_memory_utilization": 0.85}, _rig_hardware()
    )
    assert fp8["recommended_quantization"] == "fp8"
    assert fp8["recommended_precision_bits"] == 8
    assert fp8["recommended_tensor_parallel_size"] == 2
    assert fp8["quantization_required_by_hardware"] is True

    four_bit = local_targets.model_hardware_profile(
        "vllm:org/model-70B", {"gpu_memory_utilization": 0.85}, _rig_hardware()
    )
    assert four_bit["recommended_quantization"] == "bitsandbytes"
    assert four_bit["recommended_precision_bits"] == 4


def test_mixed_vram_does_not_overstate_equal_shard_capacity() -> None:
    hardware = _rig_hardware()
    hardware["aggregate_vram_gib"] = 32.0
    hardware["gpus"][1]["memory_total_mib"] = 8192
    profile = local_targets.model_hardware_profile(
        "vllm:org/model-40B", {"gpu_memory_utilization": 0.85}, hardware
    )
    assert profile["recommended_quantization"] == "bitsandbytes"
    assert profile["estimated_vram_gib"] == 22.8
    assert profile["available_vram_gib"] == pytest.approx(20.39, abs=0.01)
    assert profile["fits"] is False


def test_override_wins_and_old_gpu_blocks_automatic_bitsandbytes() -> None:
    explicit = local_targets.model_hardware_profile(
        "vllm:org/model-70B", {"quantization": "awq"}, _rig_hardware()
    )
    assert explicit["recommended_quantization"] == "awq"
    assert explicit["quantization_source"] == "model_override"
    assert explicit["quantization_required_by_hardware"] is True

    old = local_targets.model_hardware_profile(
        "vllm:org/model-70B", {}, _rig_hardware("6.1")
    )
    assert old["fits"] is False
    assert old["quantization_source"] == "hardware_auto_unavailable"
    assert "7.0+" in old["compatibility_note"]


def test_parameter_count_basis_does_not_treat_active_count_as_total() -> None:
    assert local_targets.infer_parameter_count_b("vllm:org/Hunyuan-A13B") is None
    assert local_targets.infer_parameter_count_b("vllm:org/model-30B-A3B") == 30.0
    profile = local_targets.model_hardware_profile(
        "vllm:org/Hunyuan-A13B", {}, _rig_hardware()
    )
    assert profile["parameter_count_basis"] == "unknown"
    assert profile["fits"] is None


def test_moe_names_never_masquerade_as_dense_parameter_totals() -> None:
    ambiguous = (
        "vllm:mistralai/Mixtral-8x7B-Instruct-v0.1",
        "vllm:meta-llama/Llama-4-Maverick-17B-128E-Instruct",
        "vllm:org/Example-MoE-7B",
    )
    for spec in ambiguous:
        assert local_targets.infer_parameter_count_b(spec) is None
        profile = local_targets.model_hardware_profile(spec, {}, _rig_hardware())
        assert profile["parameter_count_basis"] == "unknown"
        assert profile["fits"] is None

    declared = local_targets.model_hardware_profile(
        ambiguous[0], {"parameter_count_b": 46.7}, _rig_hardware()
    )
    assert declared["parameter_count_basis"] == "declared"
    assert declared["parameter_count_b"] == 46.7


def test_cli_local_config_auto_records_exact_quantization_and_tp(tmp_path: Path) -> None:
    spec = "vllm:org/model-70B"
    path = tmp_path / "local.json"
    path.write_text(json.dumps({spec: {
        "revision": "a" * 40,
        "modalities": ["text"],
        "tensor_parallel_size": "auto",
        "gpu_memory_utilization": 0.85,
    }}), encoding="utf-8")

    loaded, artifact = run_matrix._load_local_config(
        str(path), [spec], hardware=_rig_hardware()
    )

    assert artifact is not None
    assert loaded[spec]["quantization"] == "bitsandbytes"
    assert loaded[spec]["tensor_parallel_size"] == 2


def test_cli_rejects_tp2_when_multi_gpu_is_declared_false(tmp_path: Path) -> None:
    spec = "vllm:org/model-7B"
    path = tmp_path / "local.json"
    path.write_text(json.dumps({spec: {
        "revision": "a" * 40, "modalities": ["text"],
        "tensor_parallel_size": 2, "parameter_count_b": 7,
        "multi_gpu_compatible": False,
    }}), encoding="utf-8")
    with pytest.raises(ValueError, match="multi_gpu_compatible false"):
        run_matrix._load_local_config(str(path), [spec], hardware=_rig_hardware())


def test_cli_rejects_tp_above_detected_gpu_count(tmp_path: Path) -> None:
    spec = "vllm:org/model-7B"
    path = tmp_path / "local.json"
    path.write_text(json.dumps({spec: {
        "revision": "a" * 40, "modalities": ["text"],
        "tensor_parallel_size": 2, "parameter_count_b": 7,
    }}), encoding="utf-8")
    one_gpu = _rig_hardware()
    one_gpu["gpu_count"] = 1
    one_gpu["aggregate_vram_gib"] = one_gpu["max_gpu_vram_gib"]
    one_gpu["gpus"] = [one_gpu["gpus"][0]]
    with pytest.raises(ValueError, match=r"only 1 GPU\(s\) were detected"):
        run_matrix._load_local_config(str(path), [spec], hardware=one_gpu)


def test_real_vllm_target_fails_closed_without_detected_gpu() -> None:
    spec = "vllm:org/model-7B"
    config = {
        "revision": "a" * 40, "modalities": ["text"],
        "tensor_parallel_size": 1, "parameter_count_b": 7.0,
        "quantization": "none",
    }
    target = VLLMTarget(
        "org/model-7B", revision="a" * 40, modality_support=("text",),
        tensor_parallel_size=1,
    )
    no_gpu = {
        "available": False, "gpu_count": 0, "aggregate_vram_gib": 0.0,
        "max_gpu_vram_gib": 0.0, "gpus": [],
    }
    with pytest.raises(ValueError, match="requires a detected NVIDIA GPU"):
        run_matrix._require_local_hardware_fit(target, spec, config, no_gpu)


def test_web_materializes_clean_roster_selection_with_exact_values(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True)
    spec = "vllm:org/model-70B"
    (repo / "experiments" / "rig" / "vllm-roster.example.json").write_text(
        json.dumps({"models": {spec: {
            "revision": "b" * 40,
            "modalities": ["text"],
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.85,
        }}}), encoding="utf-8",
    )
    app = RigWebApp(
        results_root=tmp_path / "results",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    try:
        path = app._materialize_selected_local_config([spec])
        selected = json.loads(path.read_text(encoding="utf-8"))[spec]
        assert selected["quantization"] == "bitsandbytes"
        assert selected["tensor_parallel_size"] == 2
        assert "multi_gpu_compatible" not in selected
        normalized, _ = run_matrix._load_local_config(
            str(path), [spec], hardware=_rig_hardware()
        )
        assert normalized[spec]["multi_gpu_compatible"] is True
        assert normalized[spec]["multi_gpu_support_basis"] == "assumed"
        assert str(path).startswith(str(app.state_dir))
        override_path = app._materialize_selected_local_config(
            [spec], quantization_overrides={spec: "awq"}
        )
        overridden = json.loads(override_path.read_text(encoding="utf-8"))[spec]
        assert overridden["quantization"] == "awq"
        assert overridden["tensor_parallel_size"] == 2

        rerendered = app._build_page(
            prefill={"local": spec, f"quantization::{spec}": "awq"},
            errors={"limit": "test validation error"},
        ).decode("utf-8")
        assert "<option value='awq' selected>4-bit AWQ</option>" in rerendered
    finally:
        app.close()
