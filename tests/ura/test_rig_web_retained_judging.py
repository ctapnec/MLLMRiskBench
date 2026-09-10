"""UI/CLI parity for the existing retained-output judging workflow."""
import hashlib
import json

import pytest

from experiments.rig_web import build_argv
from test_rig_web_model_acquisition import _app


@pytest.mark.parametrize("custom", [False, True])
def test_retained_judging_child_receives_only_selected_provider_key(tmp_path, monkeypatch, custom):
    app = _app(tmp_path)
    model = "anthropic:claude-haiku-4-5-20251001"
    key = "TEST_HAIKU_KEY" if custom else "ANTHROPIC_API_KEY"
    monkeypatch.setenv(key, "test-judge-key")
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-provider-key")
    monkeypatch.setenv("HF_TOKEN", "unrelated-download-token")
    config = tmp_path / "api.json"
    config.write_text(json.dumps({model: {"modalities": ["text"], "max_tokens": 512,
                                        **({"key_env": key} if custom else {})}}))
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"judge_condition": {"model": model,
        "api_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}}))
    try:
        child = app._generic_child_environment("retained_response_judge_pair_execute",
            {"--plan": str(plan), "--api-config": str(config)})
        assert child[key] == "test-judge-key"
        assert "OPENAI_API_KEY" not in child and "HF_TOKEN" not in child
        ordinary = app._generic_child_environment("webui_selftest", {})
        assert key not in ordinary
    finally:
        app.close()


def test_retained_judging_ui_can_keep_invalid_verdicts(tmp_path):
    from experiments.retained_response_judge_pair_execute import main

    values = {flag: str(tmp_path / flag[2:]) for flag in (
        "--plan", "--local-runner-view", "--hosted-runner-view", "--source-receipt",
        "--api-config", "--pricing-config", "--out")}
    values.update({"--ack-paid-execution": "on", "--retain-invalid-verdicts": "on",
                   "--verify-artifact-sha256": "on"})
    argv = build_argv("retained_response_judge_pair_execute", values)
    assert "--retain-invalid-verdicts" in argv
    assert "--verify-artifact-sha256" in argv
    # Parser accepts the UI option and stops on the missing plan, not an unknown flag.
    with pytest.raises((OSError, ValueError)):
        main(argv[argv.index("experiments.retained_response_judge_pair_execute") + 1:])
