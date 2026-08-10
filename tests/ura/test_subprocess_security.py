"""Security regressions for external-engine subprocess isolation."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ura.adapters._engine_common import ExternalEngineError, run_engine_command


def _visible_environment(names: list[str], *, allow: tuple[str, ...] = ()) -> dict:
    program = (
        "import json, os; "
        f"names={names!r}; "
        "print(json.dumps({name: name in os.environ for name in names}))"
    )
    result = run_engine_command(
        [sys.executable, "-c", program],
        feature="environment-isolation test",
        allow_credentials=allow,
        timeout_seconds=10,
    )
    return json.loads(result.stdout)


def test_credentials_cookies_tokens_and_database_urls_are_not_inherited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = {
        "OPENAI_API_KEY": "api-secret",
        "URA_BROWSER_COOKIES": "cookie-secret",
        "GITHUB_TOKEN": "token-secret",
        "DATABASE_URL": "postgresql://user:password@example.invalid/db",
    }
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)

    visible = _visible_environment(list(secrets))

    assert visible == {name: False for name in secrets}


def test_exact_credential_allowlist_forwards_only_the_named_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "deliberately-forwarded")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-stay-private")

    visible = _visible_environment(
        ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
        allow=("OPENAI_API_KEY",),
    )

    assert visible == {
        "OPENAI_API_KEY": True,
        "ANTHROPIC_API_KEY": False,
    }


def test_timeout_terminates_a_stalled_engine() -> None:
    with pytest.raises(ExternalEngineError, match=r"timed out after 0\.05s"):
        run_engine_command(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            feature="stalled test engine",
            timeout_seconds=0.05,
        )


def test_configured_timeout_and_shell_false_are_always_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict = {}

    def fake_run(args, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0)

    monkeypatch.setenv("URA_ENGINE_TIMEOUT_SECONDS", "12.5")
    monkeypatch.setattr(subprocess, "run", fake_run)

    run_engine_command(["engine", "--plan"], feature="mock engine")

    assert observed["timeout"] == 12.5
    assert observed["shell"] is False
    assert "capture_output" not in observed
    assert observed["stdout"] is not subprocess.PIPE
    assert observed["stderr"] is not subprocess.PIPE


def test_failure_diagnostics_are_bounded_and_forwarded_secrets_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "forwarded-secret-value"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    program = (
        "import os, sys; "
        "sys.stdout.write(os.environ['OPENAI_API_KEY'] + 'x' * 4096); "
        "sys.stderr.write('y' * 4096); "
        "sys.exit(7)"
    )

    with pytest.raises(ExternalEngineError) as raised:
        run_engine_command(
            [sys.executable, "-c", program],
            feature="noisy test engine",
            allow_credentials=("OPENAI_API_KEY",),
            timeout_seconds=10,
            diagnostic_limit_bytes=128,
        )

    message = str(raised.value)
    assert secret not in message
    assert "diagnostic truncated" in message
    assert len(message) < 1_000


def test_wildcard_credential_forwarding_is_rejected() -> None:
    with pytest.raises(ValueError, match="explicit variable names only"):
        run_engine_command(
            ["engine"],
            feature="invalid allowlist test",
            allow_credentials=("*TOKEN*",),
        )


def test_adapters_have_no_unmediated_subprocess_calls() -> None:
    adapters = Path(__file__).parents[2] / "src" / "ura" / "adapters"
    offenders: list[str] = []
    for source in adapters.glob("*.py"):
        if source.name == "_engine_common.py":
            continue
        text = source.read_text(encoding="utf-8")
        if "subprocess.run(" in text or "subprocess.Popen(" in text:
            offenders.append(source.name)
    assert offenders == []
