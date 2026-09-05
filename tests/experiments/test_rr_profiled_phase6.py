from __future__ import annotations

import json

import pytest

from experiments.local_campaign import rr_profiled_phase6 as mod


@pytest.mark.parametrize("mutation", [None, "model", "seed", "limit", "revision"])
def test_rr_uses_all_four_retained_selections_and_the_admitted_profile(tmp_path, monkeypatch, mutation):
    source = tmp_path / "specs"
    source.mkdir()
    control = tmp_path / "campaign"
    (control / "configs").mkdir(parents=True)
    registry = tmp_path / "profiles.json"
    registry.write_text("{}", encoding="utf-8")
    config = tmp_path / "old-config.json"
    config.write_text(json.dumps({mod.RR_SPEC: {"revision": mod.RR_REVISION}}), encoding="utf-8")
    config_desc = mod._descriptor(config, label="fixture")
    originals = []
    for index, (lane, count) in enumerate(mod.LAYOUT, 1):
        argv = ["--local", mod.RR_SPEC, "--local-config", str(config),
                "--local-config-sha256", config_desc["sha256"], "--limit", "100",
                "--sample-seed", "0", "--seeds", "0", "--attackers", "replay",
                "--corpora", f"corpus-{index}"]
        value = {"lane_id": lane, "base_argv": argv, "local_config": config_desc,
                 "target": {"revision": mod.RR_REVISION}, "approved_caps": {"target_calls": count}}
        originals.append(list(argv))
        if index == 1:
            if mutation == "model":
                argv[argv.index("--local") + 1] = "vllm:base"
            elif mutation == "seed":
                argv[argv.index("--sample-seed") + 1] = "1"
            elif mutation == "limit":
                argv[argv.index("--limit") + 1] = "50"
            elif mutation == "revision":
                value["target"]["revision"] = "f" * 40
        (source / f"{index:02d}-{lane}.json").write_text(json.dumps(value), encoding="utf-8")
    calls = []

    def profile(config, *, spec, profile_registry):
        assert spec == mod.RR_SPEC and profile_registry == registry
        calls.append(spec)
        return {spec: {**config[spec], "max_tokens": 4096, "max_model_len": -1,
                       "timeout": 120, "tensor_parallel_size": 1}}, {"verified": True}

    monkeypatch.setattr(mod, "profiled_bounded_local_config", profile)
    if mutation:
        with pytest.raises(ValueError, match="retained selection"):
            mod.configure_units(source, control, registry)
        assert not calls
        return
    units, evidence = mod.configure_units(source, control, registry)
    assert sum(unit.selected_records for unit in units) == 7606
    assert [unit.unit_id for unit in units] == [lane for lane, _count in mod.LAYOUT]
    assert len(calls) == 4
    for unit, original in zip(units, originals, strict=True):
        assert unit.recovery is None
        rewritten = unit.spec["base_argv"]
        for flag in ("--local", "--limit", "--sample-seed", "--seeds", "--corpora", "--attackers"):
            assert mod._option(rewritten, flag) == mod._option(original, flag)
        current = json.loads((control / "configs" / f"{unit.unit_id}.json").read_text())
        assert current[mod.RR_SPEC]["max_tokens"] == 4096
        assert evidence[unit.unit_id]["execution_profile"] == {"verified": True}
