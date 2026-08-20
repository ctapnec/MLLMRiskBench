from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest


def test_framework_packages_are_not_main_environment_extras() -> None:
    project_root = Path(__file__).resolve().parents[2]
    document = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    extras = document["project"]["optional-dependencies"]
    lock = json.loads(
        (project_root / "experiments" / "framework_runtime_lock.json").read_text(
            encoding="utf-8"
        )
    )
    frameworks = {entry["name"]: entry for entry in lock["frameworks"]}

    assert "harmbench" not in extras
    assert "giskard-v2" not in extras
    assert frameworks["harmbench"]["env_slug"] == "harmbench-8e1604d-py312"
    assert "vllm==0.27.1" in frameworks["harmbench"]["install"]["constraints"]
    assert frameworks["giskard"]["version"] == "2.19.2+86512399daf0"


def test_operator_docs_and_requirements_share_the_global_runtime_entrypoint() -> None:
    project_root = Path(__file__).resolve().parents[2]
    documents = {
        name: (project_root / name).read_text(encoding="utf-8")
        for name in ("README.md", "experiments/RUN_AND_RETURN.md", "requirements.txt")
    }
    for text in documents.values():
        assert "experiments/framework_runtime_lock.json" in text
        assert "experiments.framework_runtime_installer" in text
        assert "local-vllm,harmbench" not in text
    runbook = documents["experiments/RUN_AND_RETURN.md"]
    assert 'python3.12 -m venv "$URA_FRAMEWORK_ENVS' not in runbook
    assert "URA_NATIVE_ENVS" not in runbook
    assert "tmux -L" in runbook
    assert "--kill-after=60s 168h" in runbook
    assert "URA_NATIVE_TARGET_CALL_CAP" in runbook
    assert 'ENGINEERING_ONLY.json"' in runbook
    assert "ura_abort_native_session 124" in runbook
    assert "ura_native_support_run petri-convert" in runbook
    assert 'ura_wait_session "$URA_FRAMEWORK_SESSION_JSON" || exit $?' in runbook
    # The native wrappers resolve the URA interpreter through URA_PY (section 2),
    # never through a path under the data root URA_WORK (P2-02).
    assert 'export URA_REPO="$HOME/MLLMRiskBench"' in runbook
    assert 'export URA_PY="$URA_REPO/.venv/bin/python"' in runbook
    assert 'logger_python="${URA_PY:-}"' in runbook
    assert "$URA_WORK/MLLMRiskBench" not in runbook
    assert '"$URA_PY" - <<\'PY\'' in runbook
    # pytest-asyncio is not a dev extra, so its ini option must not be declared
    # (it warns on the CI install where the plugin is absent) (P5-05).
    pyproject = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    assert "asyncio_default_fixture_loop_scope" not in pyproject
    # requirements.txt mirrors the pyproject extras it names (P5-06).
    requirements = documents["requirements.txt"]
    for pin in ("PyYAML>=6,<7", "vllm==0.27.1", "bitsandbytes==0.49.2"):
        assert pin in requirements, pin
    assert "haversine" not in requirements


@pytest.mark.skipif(os.name == "nt", reason="named native sessions target Linux")
def test_runbook_native_wrapper_is_bounded_and_campaign_visible(tmp_path: Path) -> None:
    if shutil.which("timeout") is None or not (shutil.which("tmux") or shutil.which("screen")):
        pytest.skip("timeout and tmux/screen are required")
    project_root = Path(__file__).resolve().parents[2]
    runbook = (project_root / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    start = runbook.index("ura_native_session() {")
    end = runbook.index("# FuzzyAI:", start)
    helper = runbook[start:end]
    work = tmp_path / "work"
    repo = tmp_path / "MLLMRiskBench"
    interpreter = repo / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path(sys.executable))
    command = (
        "set -u\n"
        f"export URA_WORK={shlex.quote(str(work))}\n"
        f"export URA_REPO={shlex.quote(str(repo))}\n"
        'export URA_PY="$URA_REPO/.venv/bin/python"\n'
        f"{helper}\n"
        "DEMO_PROVIDER_SENTINEL=current URA_NATIVE_TARGET_CALL_CAP=1 "
        "ura_native_run demo /usr/bin/env\n"
        "ura_native_support_run support-demo /bin/true\n"
    )
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    attempts = list((work / "runs" / "engineering").glob("ura-native-demo-*"))
    support_attempts = list(
        (work / "runs" / "engineering").glob("ura-native-support-demo-*")
    )
    assert len(attempts) == 1 and len(support_attempts) == 1
    attempt = attempts[0]
    marker = json.loads((attempt / "ENGINEERING_ONLY.json").read_text(encoding="utf-8"))
    assert marker["schema"] == "ura-engineering-campaign/1"
    assert marker["thesis_empirical_evidence"] is False
    assert marker["hosted_calls_allowed"] is True
    assert marker["hard_stop_hours"] == 168
    assert marker["target_call_cap"] == 1
    events = [json.loads(line) for line in (attempt / "task-log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(row["event"], row["status"]) for row in events] == [
        ("campaign_start", "running"),
        ("task_start", "running"),
        ("task_end", "passed"),
        ("campaign_end", "complete"),
    ]
    assert next(attempt.glob("*.exit")).read_text(encoding="utf-8").strip() == "0"
    transcript = next(attempt.glob("*.log")).read_text(encoding="utf-8")
    assert "DEMO_PROVIDER_SENTINEL=current" in transcript
    assert len(transcript.encode()) <= 16 * 1024 * 1024
    support_marker = json.loads(
        (support_attempts[0] / "ENGINEERING_ONLY.json").read_text(encoding="utf-8")
    )
    assert support_marker["hosted_calls_allowed"] is False
    assert support_marker["model_tasks"] == []
    assert support_marker["target_call_cap"] == 0
    if shutil.which("tmux"):
        assert "attach=tmux -L ura-native-demo-" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="named native sessions target Linux")
def test_runbook_native_wrapper_fails_loudly_without_ura_py(tmp_path: Path) -> None:
    # Regression for P2-02: the wrapper used to hard-code
    # $URA_WORK/MLLMRiskBench/.venv/bin/python and silently `return 1` when that
    # path did not exist (the rig keeps the checkout under $HOME, not the data
    # root). It must now resolve $URA_PY and name the problem on stderr.
    if shutil.which("bash") is None or shutil.which("timeout") is None:
        pytest.skip("bash and GNU timeout are required")
    project_root = Path(__file__).resolve().parents[2]
    runbook = (project_root / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    start = runbook.index("ura_native_session() {")
    end = runbook.index("# FuzzyAI:", start)
    helper = runbook[start:end]
    work = tmp_path / "work"
    (work / "MLLMRiskBench" / ".venv" / "bin").mkdir(parents=True)
    for exported in ("", f"export URA_PY={shlex.quote(str(tmp_path / 'missing-python'))}\n"):
        command = (
            "set -u\n"
            f"export URA_WORK={shlex.quote(str(work))}\n"
            f"{exported}"
            f"{helper}\n"
            "URA_NATIVE_TARGET_CALL_CAP=1 ura_native_run demo /usr/bin/env\n"
        )
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 1, (result.returncode, result.stderr)
        assert "ura_native_session: URA_PY=" in result.stderr
        assert "export URA_REPO and URA_PY as in section 2" in result.stderr
        # The check runs before any attempt directory is created, so a
        # misconfigured shell leaves no empty engineering-campaign entry.
        assert not (work / "runs" / "engineering").exists()
