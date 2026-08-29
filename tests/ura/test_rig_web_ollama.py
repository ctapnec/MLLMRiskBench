from __future__ import annotations

import io
import json
import os
import signal
import sqlite3
import stat
import subprocess
import urllib.error
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from experiments import ollama_pull
from experiments.rig_web_app.app import RigWebApp
from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.builder_models import BuilderModelsMixin
from experiments.rig_web_app.catalog import COMMAND_GROUPS, COMMANDS
from experiments.rig_web_app.ollama_service import (
    DEFAULT_OLLAMA_URL,
    OllamaAPI,
    OllamaError,
    OllamaProtocolError,
    OllamaService,
    OllamaUnavailable,
    normalize_ollama_digest,
    validate_ollama_base_url,
    validate_ollama_pull_storage,
    validate_ollama_tag,
)
from experiments.rig_web_app.storage import ConsoleDB


class _LabelInputCounter(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._active: list[int] = []
        self.counts: list[int] = []

    def handle_starttag(
        self, tag: str, _attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag == "label":
            self._active.append(0)
        elif tag == "input" and self._active:
            self._active[-1] += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "label" and self._active:
            self.counts.append(self._active.pop())


def _tags(*rows: dict[str, object]) -> dict[str, object]:
    return {"models": list(rows)}


def _tag(
    name: str,
    digest: str,
    *,
    family: str = "fixture",
    families: list[str] | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "model": name,
        "digest": digest,
        "details": {
            "family": family,
            "families": families or [family],
            "format": "gguf",
            "parameter_size": "7B",
            "quantization_level": "Q4_K_M",
        },
    }


class _Response:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.stream = io.BytesIO(raw)

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        return self.stream.read(amount)

    def readline(self, amount: int = -1) -> bytes:
        return self.stream.readline(amount)


class _FakeAPI:
    timeout = 1.0
    base_url = DEFAULT_OLLAMA_URL

    def __init__(
        self,
        tag_documents: list[dict[str, object]],
        *,
        shown: dict[str, dict[str, object]] | None = None,
        loaded: dict[str, object] | None = None,
    ) -> None:
        self.tag_documents = list(tag_documents)
        self.shown = shown or {}
        self.loaded = loaded or {"models": []}
        self.show_calls: list[tuple[str, float | None]] = []
        self.timeouts: list[float | None] = []

    def tags(self, *, timeout: float | None = None) -> dict[str, object]:
        self.timeouts.append(timeout)
        if not self.tag_documents:
            raise AssertionError("unexpected tags request")
        return self.tag_documents.pop(0)

    def ps(self, *, timeout: float | None = None) -> dict[str, object]:
        self.timeouts.append(timeout)
        return self.loaded

    def show(self, model: str, *, timeout: float | None = None) -> dict[str, object]:
        self.timeouts.append(timeout)
        self.show_calls.append((model, timeout))
        return self.shown[model]


class _FakeProcess:
    def __init__(self, pid: int = 4242, code: int | None = None) -> None:
        self.pid = pid
        self.code = code
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.code

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.code is None:
            raise subprocess.TimeoutExpired("ollama", 0)
        return self.code

    def terminate(self) -> None:
        self.terminated = True
        self.code = -signal.SIGTERM

    def kill(self) -> None:
        self.killed = True
        self.code = -signal.SIGKILL


def test_loopback_url_tag_and_digest_validation() -> None:
    assert validate_ollama_base_url("http://localhost:11434/") == DEFAULT_OLLAMA_URL
    assert validate_ollama_base_url("http://[::1]:11434") == "http://[::1]:11434"
    for unsafe in (
        "https://127.0.0.1:11434",
        "http://192.168.1.5:11434",
        "http://example.com:11434",
        "http://user:pass@127.0.0.1:11434",
        "http://127.0.0.1:11434/api/tags",
        "http://127.0.0.1:11434?next=http://example.com",
    ):
        with pytest.raises(ValueError):
            validate_ollama_base_url(unsafe)
    assert validate_ollama_tag("registry.example/model-name:Q4_K_M")
    for unsafe_tag in ("", "../model", " model tag ", "-flag", "a//b", "a/../b"):
        with pytest.raises(ValueError):
            validate_ollama_tag(unsafe_tag)
    assert normalize_ollama_digest("SHA256:" + "A" * 64) == "a" * 64


def test_api_uses_fixed_methods_bounded_bodies_and_no_redirect() -> None:
    seen: list[tuple[str, str, bytes | None, float]] = []

    def opener(request, *, timeout):
        seen.append((request.full_url, request.method, request.data, timeout))
        if request.full_url.endswith("/api/show"):
            return _Response(b'{"capabilities":["completion"]}')
        return _Response(b'{"models":[]}')

    api = OllamaAPI(open_request=opener, timeout=0.5)
    assert api.tags() == {"models": []}
    assert api.ps() == {"models": []}
    assert api.show("fixture:latest")["capabilities"] == ["completion"]
    assert [(row[1], row[0].rsplit("/", 2)[-1]) for row in seen] == [
        ("GET", "tags"),
        ("GET", "ps"),
        ("POST", "show"),
    ]
    assert json.loads(seen[-1][2] or b"null") == {"model": "fixture:latest"}
    with pytest.raises(OllamaProtocolError, match="byte limit"):
        OllamaAPI(
            open_request=lambda *_args, **_kwargs: _Response(
                b"{" + b" " * (4 * 1024 * 1024) + b"}"
            )
        ).tags()

    def redirect(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            DEFAULT_OLLAMA_URL + "/api/tags",
            302,
            "redirect",
            {"Location": "http://example.com"},
            None,
        )

    with pytest.raises(OllamaUnavailable):
        OllamaAPI(open_request=redirect).tags()


def test_live_roster_materializes_all_exact_capabilities_despite_vllm_overlap(
    tmp_path: Path,
) -> None:
    unique = _tag("granite-code:latest", "A" * 64, family="granite")
    overlap = _tag("llama3:latest", "b" * 64, family="llama")
    snapshot = _tags(unique, overlap)
    api = _FakeAPI(
        [snapshot, snapshot],
        shown={
            "granite-code:latest": {
                "capabilities": ["completion", "vision", "tools"],
                "details": unique["details"],
            },
            "llama3:latest": {
                "capabilities": ["completion"],
                "details": overlap["details"],
            },
        },
        loaded={"models": [unique]},
    )
    service = OllamaService(tmp_path, api=api, platform="posix")
    roster = service.roster(
        {
            "vllm:meta-llama/Llama-3-8B-Instruct": {
                "modalities": ["text"]
            }
        },
        force=True,
    )
    assert roster["available"] is True
    assert roster["models"] == [
        {
            "capabilities": ["completion", "tools", "vision"],
            "details": unique["details"],
            "digest": "a" * 64,
            "loaded": True,
            "modalities": ["text", "image"],
            "model": "granite-code:latest",
            "name": "granite-code:latest",
            "overlap_with": [],
            "spec": "ollama:granite-code:latest",
            "tag": "granite-code:latest",
        },
        {
            "capabilities": ["completion"],
            "details": overlap["details"],
            "digest": "b" * 64,
            "loaded": False,
            "modalities": ["text"],
            "model": "llama3:latest",
            "name": "llama3:latest",
            "overlap_with": [],
            "spec": "ollama:llama3:latest",
            "tag": "llama3:latest",
        },
    ]
    assert roster["excluded"] == []


def test_roster_keeps_opaque_alias_despite_vllm_family_architecture(
    tmp_path: Path,
) -> None:
    opaque = _tag("private-alias:latest", "c" * 64)
    opaque["details"] = {}
    snapshot = _tags(opaque)
    api = _FakeAPI(
        [snapshot, snapshot],
        shown={
            "private-alias:latest": {
                "capabilities": ["completion"],
                "details": {},
                "model_info": {"general.architecture": "llama"},
            }
        },
    )
    result = OllamaService(tmp_path, api=api, platform="posix").roster(
        {"vllm:meta-llama/Llama-3-8B-Instruct": {}}, force=True
    )
    assert result["available"] is True
    assert result["models"] == [
        {
            "architecture": "llama",
            "capabilities": ["completion"],
            "details": {},
            "digest": "c" * 64,
            "loaded": False,
            "modalities": ["text"],
            "model": "private-alias:latest",
            "name": "private-alias:latest",
            "overlap_with": [],
            "spec": "ollama:private-alias:latest",
            "tag": "private-alias:latest",
        }
    ]
    assert result["excluded"] == []


@pytest.mark.parametrize(
    ("tag_details", "show_details", "model_info", "message"),
    [
        ({}, {}, {}, "no credible upstream family identity evidence"),
        (
            {"family": "granite"},
            {"family": "granite"},
            {"general.architecture": "llama"},
            "model-family identity mismatch",
        ),
        (
            {},
            {},
            {"general.architecture": "x" * 129},
            "general.architecture must be bounded",
        ),
    ],
)
def test_roster_fails_closed_on_missing_ambiguous_or_unbounded_identity(
    tmp_path: Path,
    tag_details: dict[str, object],
    show_details: dict[str, object],
    model_info: dict[str, object],
    message: str,
) -> None:
    row = _tag("opaque:latest", "f" * 64)
    row["details"] = tag_details
    snapshot = _tags(row)
    result = OllamaService(
        tmp_path,
        api=_FakeAPI(
            [snapshot, snapshot],
            shown={
                "opaque:latest": {
                    "capabilities": ["completion"],
                    "details": show_details,
                    "model_info": model_info,
                }
            },
        ),
        platform="posix",
    ).roster({}, force=True)
    assert result["available"] is True
    assert result["models"] == [] and result["excluded"] == []
    assert message in " ".join(result["issues"])


def test_roster_never_fabricates_missing_capability_or_malformed_rows(
    tmp_path: Path,
) -> None:
    invalid_digest = _tag("bad:latest", "x" * 64)
    no_capabilities = _tag("embedding:latest", "c" * 64)
    snapshot = _tags(invalid_digest, no_capabilities)
    api = _FakeAPI(
        [snapshot, snapshot],
        shown={"embedding:latest": {"capabilities": ["embedding"]}},
    )
    result = OllamaService(tmp_path, api=api, platform="posix").roster({}, force=True)
    assert result["available"] is True
    assert result["models"] == [] and result["excluded"] == []
    issues = " ".join(result["issues"])
    assert "digest" in issues and "no completion capability" in issues


def test_roster_requires_real_details_and_does_not_match_generic_name_tokens(
    tmp_path: Path,
) -> None:
    malformed = _tag("missing-details:latest", "d" * 64)
    malformed.pop("details")
    code_model = _tag("granite-code:latest", "e" * 64, family="granite")
    snapshot = _tags(malformed, code_model)
    api = _FakeAPI(
        [snapshot, snapshot],
        shown={
            "granite-code:latest": {
                "capabilities": ["completion"],
                "details": code_model["details"],
            }
        },
    )
    result = OllamaService(tmp_path, api=api, platform="posix").roster(
        {"vllm:Example/Unrelated-Code-7B-Instruct": {}}, force=True
    )
    assert [row["spec"] for row in result["models"]] == [
        "ollama:granite-code:latest"
    ]
    assert result["excluded"] == []
    assert "details must be an object" in " ".join(result["issues"])


def test_roster_fails_closed_when_mutable_tag_changes_mid_discovery(tmp_path: Path) -> None:
    before = _tags(_tag("fixture:latest", "a" * 64))
    after = _tags(_tag("fixture:latest", "b" * 64))
    api = _FakeAPI(
        [before, after],
        shown={"fixture:latest": {"capabilities": ["completion"]}},
    )
    result = OllamaService(tmp_path, api=api, platform="posix").roster({}, force=True)
    assert result["available"] is False and result["models"] == []
    assert "changed during capability discovery" in str(result["error"])


def test_roster_has_strict_model_count_and_aggregate_time_bounds(tmp_path: Path) -> None:
    rows = [_tag(f"model-{index}:latest", f"{index:064x}") for index in range(65)]
    count_api = _FakeAPI([_tags(*rows)])
    count_result = OllamaService(
        tmp_path / "count", api=count_api, platform="posix"
    ).roster({}, force=True)
    assert count_result["available"] is False
    assert "64-model" in str(count_result["error"])
    assert count_api.show_calls == []

    clock = [0.0]
    small_rows = [_tag(f"slow-{index}:latest", f"{index + 100:064x}") for index in range(4)]

    class SlowAPI(_FakeAPI):
        def tags(self, *, timeout=None):
            clock[0] += 0.15
            return super().tags(timeout=timeout)

        def ps(self, *, timeout=None):
            clock[0] += 0.15
            return super().ps(timeout=timeout)

        def show(self, model: str, *, timeout=None):
            clock[0] += 0.25
            return super().show(model, timeout=timeout)

    snapshot = _tags(*small_rows)
    slow = SlowAPI(
        [snapshot, snapshot],
        shown={row["name"]: {"capabilities": ["completion"]} for row in small_rows},
    )
    timed = OllamaService(
        tmp_path / "timed",
        api=slow,
        platform="posix",
        monotonic=lambda: clock[0],
        discovery_timeout=0.5,
    ).roster({}, force=True)
    assert timed["available"] is False
    assert "aggregate timeout" in str(timed["error"])
    assert len(slow.show_calls) <= 1
    assert all(value is None or 0.05 <= value <= 0.5 for value in slow.timeouts)


class _SwitchingAPI:
    timeout = 0.05
    base_url = DEFAULT_OLLAMA_URL

    def __init__(self) -> None:
        self.running = False

    def tags(self, *, timeout=None):
        del timeout
        if not self.running:
            raise OllamaUnavailable("not running")
        return {"models": []}

    def ps(self, *, timeout=None):
        del timeout
        if not self.running:
            raise OllamaUnavailable("not running")
        return {"models": []}


def _executable(tmp_path: Path) -> Path:
    executable = tmp_path / "ollama"
    executable.write_text("fixture", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_lifecycle_starts_fixed_argv_and_stops_only_owned_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    retained = {
        "PATH": "fixture-runtime-path",
        "HOME": "fixture-home",
        "CUDA_VISIBLE_DEVICES": "1,3",
        "LD_LIBRARY_PATH": "fixture-cuda-libraries",
        "OLLAMA_MODELS": str((tmp_path / "fixture-model-cache").resolve()),
        "HTTPS_PROXY": "http://proxy.fixture:8080",
        "NO_PROXY": "127.0.0.1,localhost",
    }
    secrets = {
        "OPENAI_API_KEY": "sentinel-openai-secret",
        "ANTHROPIC_AUTH_TOKEN": "sentinel-anthropic-secret",
        "HF_TOKEN": "sentinel-hf-secret",
        "AWS_ACCESS_KEY_ID": "sentinel-aws-credential",
        "GOOGLE_APPLICATION_CREDENTIALS": "sentinel-google-credentials",
        "FIXTURE_PROVIDER_CLIENT_SECRET": "sentinel-client-secret",
        "FIXTURE_PASSWORD": "sentinel-password",
        "UNRELATED_RUNTIME_VALUE": "sentinel-unrelated",
        "CUSTOM_API_TOKEN": "sentinel-custom-token",
        "HTTP_PROXY": "http://proxy-user:proxy-password@proxy.fixture:8080",
        "ALL_PROXY": "socks5://proxy-token@proxy.fixture:1080",
        "ollama_host": "0.0.0.0:11434",
    }
    for name, value in retained.items() | secrets.items():
        monkeypatch.setenv(name, value)
    api = _SwitchingAPI()
    process = _FakeProcess()
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        api.running = True
        return process

    signals: list[int] = []

    group_alive = True

    def killpg(pgid: int, sent: int) -> None:
        nonlocal group_alive
        assert pgid == process.pid
        if sent == 0:
            if not group_alive:
                raise ProcessLookupError
            return
        signals.append(sent)
        if sent == getattr(signal, "SIGTERM", 15):
            process.code = -sent
            api.running = False
            group_alive = False

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    executable = _executable(tmp_path)
    service = OllamaService(
        tmp_path / "state",
        api=api,
        platform="posix",
        popen_factory=popen,
        which=lambda _name: str(executable),
        sleep=lambda _delay: None,
        start_timeout=0.5,
        listener_owner=lambda *_args: True,
        process_identity=lambda pid: f"linux-proc-v1:{pid}:1",
    )
    started = service.start()
    assert started["state"] == "owned" and started["can_stop"] is True
    argv, kwargs = calls[0]
    assert argv == [str(executable.resolve()), "serve"]
    assert kwargs["shell"] is False and kwargs["start_new_session"] is True
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    child_env = kwargs["env"]
    assert child_env["OLLAMA_HOST"] == "127.0.0.1:11434"
    assert all(child_env[name] == value for name, value in retained.items())
    assert all(value not in child_env.values() for value in secrets.values())
    assert sum(name.upper() == "OLLAMA_HOST" for name in child_env) == 1
    storage = service.validate_pull_storage()
    assert storage["models_path"] == retained["OLLAMA_MODELS"]
    assert storage["owned_pid"] == process.pid
    assert storage["owned_process_identity"] == f"linux-proc-v1:{process.pid}:1"
    stopped = service.stop()
    assert stopped["state"] == "stopped"
    assert signals == [getattr(signal, "SIGTERM", 15)]


def test_external_and_restarted_daemons_are_never_stopped(tmp_path: Path) -> None:
    api = _SwitchingAPI()
    api.running = True
    first = OllamaService(tmp_path / "first", api=api, platform="posix")
    assert first.status()["state"] == "external"
    with pytest.raises(OllamaError, match="external"):
        first.stop()
    # A fresh console has no inherited Popen handle: even if the prior console
    # created this endpoint, the restarted process treats it as external.
    restarted = OllamaService(tmp_path / "second", api=api, platform="posix")
    assert restarted.status()["owned_by_console"] is False
    with pytest.raises(OllamaError, match="external"):
        restarted.stop()
    restarted.close()  # also must not attempt a stop


def test_absent_daemon_status_is_stopped_and_unowned(tmp_path: Path) -> None:
    status = OllamaService(
        tmp_path, api=_SwitchingAPI(), platform="posix"
    ).status()
    assert status["state"] == "stopped"
    assert status["api_reachable"] is False
    assert status["owned_by_console"] is False
    assert status["can_stop"] is False


def test_status_skips_optional_ps_when_shared_deadline_is_below_api_floor(
    tmp_path: Path,
) -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    class DeadlineAPI(_FakeAPI):
        def tags(self, *, timeout: float | None = None) -> dict[str, object]:
            document = super().tags(timeout=timeout)
            clock.now = 0.19
            return document

        def ps(self, *, timeout: float | None = None) -> dict[str, object]:
            raise AssertionError("expired status budget must not reach /api/ps")

    clock = Clock()
    service = OllamaService(
        tmp_path,
        api=DeadlineAPI([_tags()]),
        platform="posix",
        monotonic=clock,
    )

    reachable, loaded, warning = service._api_state(deadline=0.20)

    assert reachable is True
    assert loaded == ()
    assert warning == "Ollama status request budget is exhausted"


def test_unexpected_owned_parent_exit_retains_group_without_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _SwitchingAPI()
    process = _FakeProcess(code=1)
    service = OllamaService(tmp_path, api=api, platform="posix")
    service._owned_process = process
    service._owned_pgid = process.pid
    killed: list[tuple[int, int]] = []
    group_alive = True

    def killpg(pgid: int, sent: int) -> None:
        nonlocal group_alive
        if sent == 0:
            if not group_alive:
                raise ProcessLookupError
            return
        killed.append((pgid, sent))
        group_alive = False

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    status = service.status()
    assert status["state"] == "error" and status["owned_by_console"] is True
    assert status["can_stop"] is True
    assert "leader identity" in str(status["last_error"])
    assert killed == []


def test_start_bind_race_reaps_own_group_and_classifies_external(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _SwitchingAPI()
    process = _FakeProcess(code=1)
    executable = _executable(tmp_path)
    killed: list[int] = []

    def popen(_argv, **_kwargs):
        api.running = True  # another daemon won the endpoint
        return process

    def killpg(_pgid: int, sent: int) -> None:
        if sent == 0:
            raise ProcessLookupError
        killed.append(sent)

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    service = OllamaService(
        tmp_path / "state",
        api=api,
        platform="posix",
        popen_factory=popen,
        which=lambda _name: str(executable),
        sleep=lambda _delay: None,
        start_timeout=0.5,
    )
    result = service.start()
    assert result["state"] == "external" and result["owned_by_console"] is False
    assert killed == []
    with pytest.raises(OllamaError, match="external"):
        service.stop()


def test_pull_stream_emits_bounded_normalized_progress(capsys) -> None:
    rows = b"\n".join(
        json.dumps(row).encode("utf-8")
        for row in (
            {"status": "pulling manifest"},
            {"status": "downloading", "completed": 5, "total": 10},
            {"status": "success"},
        )
    ) + b"\n"
    seen: dict[str, object] = {}

    def opener(request, *, timeout):
        seen.update(url=request.full_url, method=request.method, body=request.data, timeout=timeout)
        return _Response(rows)

    assert ollama_pull.pull(
        "fixture:latest",
        models_path=str(Path.cwd().resolve()),
        owned_pid=4242,
        owned_process_identity="linux-proc-v1:4242:1",
        open_request=opener,
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:1",
        listener_owner=lambda *_args: True,
    ) == 0
    emitted = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert seen["url"] == DEFAULT_OLLAMA_URL + "/api/pull"
    assert seen["method"] == "POST"
    assert json.loads(seen["body"]) == {"model": "fixture:latest", "stream": True}
    assert [row["activity"] for row in emitted] == ["model_download"] * 3
    assert emitted[1]["percent"] == 50.0


def test_pull_coalesces_more_than_ten_thousand_normal_1_3gb_frames(
    capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    total = 1_336_082_784
    frame_count = 12_500
    # Storage admission and reported-remaining checks have dedicated tests;
    # keep this high-frame integration regression focused and fast.
    monkeypatch.setattr(
        ollama_pull,
        "validate_ollama_pull_storage",
        lambda *_args, **_kwargs: {"models_path": str(Path.cwd().resolve())},
    )
    rows = [json.dumps({"status": "pulling manifest"}).encode("utf-8")]
    rows.extend(
        json.dumps({
            "status": "pulling 751872507196",
            "digest": "sha256:" + "7" * 64,
            "completed": total * index // frame_count,
            "total": total,
        }).encode("utf-8")
        for index in range(1, frame_count + 1)
    )
    rows.append(json.dumps({"status": "success"}).encode("utf-8"))

    assert ollama_pull.pull(
        "fixture:latest",
        models_path=str(Path.cwd().resolve()),
        owned_pid=4242,
        owned_process_identity="linux-proc-v1:4242:1",
        open_request=lambda *_args, **_kwargs: _Response(b"\n".join(rows) + b"\n"),
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:1",
        listener_owner=lambda *_args: True,
    ) == 0
    emitted = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert frame_count > 10_000
    assert len(emitted) < 500
    assert emitted[0]["status"] == "pulling manifest"
    assert emitted[-1]["status"] == "success"
    assert max(
        int(row.get("completed", 0)) for row in emitted
    ) == total


def test_pull_caps_malicious_tiny_zero_progress_frames(
    capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ollama_pull, "_MAX_STALLED_RAW_EVENTS", 32)
    raw = b'{"status":"downloading"}\n' * 64
    assert ollama_pull.pull(
        "fixture:latest",
        models_path=str(Path.cwd().resolve()),
        owned_pid=4242,
        owned_process_identity="linux-proc-v1:4242:1",
        open_request=lambda *_args, **_kwargs: _Response(raw),
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:1",
        listener_owner=lambda *_args: True,
    ) == 1
    captured = capsys.readouterr()
    emitted = [json.loads(line) for line in captured.out.splitlines()]
    assert [row["status"] for row in emitted] == ["downloading", "error"]
    assert "stalled across too many raw frames" in captured.err


def test_pull_raw_frame_ceiling_is_derived_and_independently_enforced(
    capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert ollama_pull._MAX_RAW_EVENTS == (
        ollama_pull._MAX_NORMAL_MODEL_BYTES
        // ollama_pull._NORMAL_PROGRESS_FRAME_BYTES
        + ollama_pull._RAW_EVENT_OVERHEAD
    )
    monkeypatch.setattr(ollama_pull, "_MAX_RAW_EVENTS", 32)
    monkeypatch.setattr(ollama_pull, "_MAX_STALLED_RAW_EVENTS", 128)
    raw = b"".join(
        b'{"status":"phase-a"}\n' if index % 2 else b'{"status":"phase-b"}\n'
        for index in range(64)
    )
    assert ollama_pull.pull(
        "fixture:latest",
        models_path=str(Path.cwd().resolve()),
        owned_pid=4242,
        owned_process_identity="linux-proc-v1:4242:1",
        open_request=lambda *_args, **_kwargs: _Response(raw),
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:1",
        listener_owner=lambda *_args: True,
    ) == 1
    captured = capsys.readouterr()
    assert "raw progress frame limit" in captured.err
    assert len(captured.out.splitlines()) <= 33


def test_progress_emitter_heartbeats_and_reserves_terminal_capacity(
    capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ollama_pull, "_MAX_EMITTED_EVENTS", 3)
    state = ollama_pull._EmissionState()
    progress = {
        "activity": "model_download",
        "event": "ollama_pull_progress",
        "model": "fixture:latest",
        "status": "downloading",
    }
    assert ollama_pull._emit_progress(progress, state, now=0.0) is True
    assert ollama_pull._emit_progress(progress, state, now=14.9) is False
    assert ollama_pull._emit_progress(progress, state, now=15.0) is True
    assert ollama_pull._emit_progress(
        {**progress, "status": "another phase"}, state, now=16.0
    ) is False
    assert ollama_pull._emit_progress(
        {**progress, "status": "success"}, state, now=17.0, terminal=True
    ) is True
    assert [
        json.loads(line)["status"] for line in capsys.readouterr().out.splitlines()
    ] == ["downloading", "downloading", "success"]


def test_pull_rejects_deep_oversized_and_nonterminal_streams(capsys) -> None:
    deep: object = "leaf"
    for _index in range(70):
        deep = {"nested": deep}
    cases = (
        json.dumps({"status": "downloading", "extra": deep}).encode() + b"\n",
        b'{"status":"' + b"x" * (64 * 1024) + b'"}\n',
        b'{"status":"downloading"}\n',
    )
    for raw in cases:
        assert ollama_pull.pull(
            "fixture:latest",
            models_path=str(Path.cwd().resolve()),
            owned_pid=4242,
            owned_process_identity="linux-proc-v1:4242:1",
            open_request=lambda *_args, _raw=raw, **_kwargs: _Response(_raw),
            disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
            process_identity=lambda _pid: "linux-proc-v1:4242:1",
            listener_owner=lambda *_args: True,
        ) == 1
    assert "failed" in capsys.readouterr().err


def test_pull_disk_guard_runs_before_request_and_tracks_reported_remaining(
    tmp_path: Path, capsys
) -> None:
    opened = False

    def opener(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("low-space pull must not reach the daemon")

    assert ollama_pull.pull(
        "fixture:latest",
        models_path=str(tmp_path.resolve()),
        owned_pid=4242,
        owned_process_identity="linux-proc-v1:4242:1",
        open_request=opener,
        disk_usage=lambda _path: SimpleNamespace(free=4 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:1",
        listener_owner=lambda *_args: True,
    ) == 1
    assert opened is False and "five GiB" in capsys.readouterr().err

    with pytest.raises(OllamaUnavailable, match="reported remaining"):
        validate_ollama_pull_storage(
            {"OLLAMA_MODELS": str(tmp_path)},
            required_bytes=2 * 1024**3,
            disk_usage=lambda _path: SimpleNamespace(free=6 * 1024**3),
        )


class _ControlService:
    def __init__(self) -> None:
        self.started = 0
        self.stopped = 0
        self.invalidated = 0
        self.closed = 0
        self.storage_checks = 0

    def status(self) -> dict[str, object]:
        return {
            "api_reachable": True,
            "base_url": DEFAULT_OLLAMA_URL,
            "can_stop": False,
            "can_pull": False,
            "last_error": "",
            "loaded_models": [],
            "owned_by_console": False,
            "pid": None,
            "state": "external",
            "warning": "",
        }

    def start(self) -> dict[str, object]:
        self.started += 1
        return self.status()

    def stop(self) -> dict[str, object]:
        self.stopped += 1
        return self.status()

    def invalidate_roster(self) -> None:
        self.invalidated += 1

    def validate_pull_storage(self) -> dict[str, object]:
        self.storage_checks += 1
        return {
            "free_bytes": 10 * 1024**3,
            "minimum_free_bytes": 5 * 1024**3,
            "models_path": str(Path.cwd().resolve()),
            "base_url": DEFAULT_OLLAMA_URL,
            "owned_pid": 4242,
            "owned_process_identity": "linux-proc-v1:4242:1",
        }

    def close(self) -> None:
        self.closed += 1

    def roster(self, _entries, *, force=False):
        del force
        return {"available": True, "models": [], "excluded": [], "issues": []}


def _app(tmp_path: Path, service: _ControlService) -> RigWebApp:
    return RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=Path(__file__).resolve().parents[2],
        gpu_hardware={"available": False, "gpu_count": 0, "gpus": []},
        system_hardware={"available": False},
        ollama_service=service,
    )


def test_ollama_service_has_no_process_lifetime_action_token(tmp_path: Path) -> None:
    service = OllamaService(tmp_path)

    assert not hasattr(OllamaService, "validate_action")
    assert not hasattr(service, "action_token")


def test_routes_dispatch_without_action_token_and_pull_sets_explicit_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _ControlService()
    app = _app(tmp_path, service)
    captured: dict[str, object] = {}

    def start_job(command, values, **kwargs):
        captured.update(command=command, values=values, kwargs=kwargs)
        return SimpleNamespace(job_id="pull-job")

    monkeypatch.setattr(app, "start_job", start_job)
    try:
        status, content_type, body = app.handle("GET", "/ollama/status")
        assert status == 200 and content_type.startswith("application/json")
        assert "action_token" not in body.decode("utf-8")
        started = app.handle("POST", "/ollama/start", {})
        assert started[:2] == (303, "/build?ollama_state=external")
        assert service.started == 1
        stopped = app.handle("POST", "/ollama/stop", {})
        assert stopped[:2] == (303, "/build?ollama_state=external")
        assert service.stopped == 1
        pulled = app.handle(
            "POST",
            "/ollama/pull",
            {"model": "fixture:latest"},
        )
        assert pulled[:2] == (303, "/jobs/pull-job")
        assert service.storage_checks == 1
        assert captured == {
            "command": "ollama_pull",
            "values": {
                "--model": "fixture:latest",
                "--base-url": DEFAULT_OLLAMA_URL,
                "--models-path": str(Path.cwd().resolve()),
                "--owned-pid": "4242",
                "--owned-process-identity": "linux-proc-v1:4242:1",
                "--timeout-seconds": "120",
            },
            "kwargs": {
                "activity": "model_download",
                "builder_params": {"ollama_model": "fixture:latest"},
            },
        }
        generic = app.handle(
            "POST", "/jobs", {"command": "ollama_pull", "--model": "fixture"}
        )
        assert generic[0] == 400
    finally:
        app.close()


def test_pull_is_typed_but_never_advertised_as_a_generic_command(
    tmp_path: Path,
) -> None:
    grouped = {name for _title, _icon, _ref, names in COMMAND_GROUPS for name in names}
    assert "ollama_pull" in COMMANDS
    assert "ollama_pull" not in grouped
    app = _app(tmp_path, _ControlService())
    try:
        page = app._commands_page().decode("utf-8")
        assert "data-name='ollama_pull'" not in page
        assert "name='command' value='ollama_pull'" not in page
    finally:
        app.close()


def test_build_renders_owned_boundaries_and_pull_controls_without_nested_forms(
    tmp_path: Path,
) -> None:
    class LiveControl(_ControlService):
        def status(self) -> dict[str, object]:
            value = super().status()
            value["loaded_models"] = ["granite:latest"]
            return value

        def roster(self, _entries, *, force=False):
            del force
            return {
                "available": True,
                "models": [
                    {
                        "spec": "ollama:granite:latest",
                        "digest": "d" * 64,
                        "modalities": ["text"],
                    }
                ],
                "excluded": [
                    {
                        "spec": "ollama:llava:latest",
                        "digest": "e" * 64,
                        "modalities": ["text", "image"],
                        "overlap_with": [
                            "vllm:llava-hf/llava-v1.6-mistral-7b-hf"
                        ],
                    }
                ],
                "issues": ["one bounded fixture warning"],
            }

    app = _app(tmp_path, LiveControl())
    try:
        page = app.handle(
            "GET", "/build?ollama_error=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        )[2].decode("utf-8")
        assert "Local Ollama service" in page
        assert "<span class='badge blue'>external</span>" in page
        assert "discovery is read-only and pulls are disabled" in page
        assert "granite:latest" in page and "Loaded now" in page
        assert "ollama:llava:latest" not in page
        assert "Excluded vLLM overlaps" not in page
        assert "vLLM availability never excludes an installed Ollama tag" in page
        assert "one bounded fixture warning" in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        assert "<script>alert(1)</script>" not in page
        assert "action='/ollama/start'" in page
        assert "action='/ollama/stop'" in page
        assert "action='/ollama/pull'" in page
        assert page.index("action='/ollama/start'") < page.index("id='builder'")
        assert "name='action_token'" not in page
        assert page.count("<div class='modelrow'") == page.count(
            "class='modelbox'"
        )
        assert "judge-modelbox" not in page
        parser = _LabelInputCounter()
        parser.feed(page)
        assert parser.counts and max(parser.counts) <= 1
        start = page[page.index("action='/ollama/start'"):]
        start = start[: start.index("</form>")]
        stop = page[page.index("action='/ollama/stop'"):]
        stop = stop[: stop.index("</form>")]
        pull = page[page.index("action='/ollama/pull'"):]
        pull = pull[: pull.index("</form>")]
        assert "name='confirm'" not in start
        assert "name='confirm'" not in stop
        assert "name='confirm'" not in pull
        assert "<button type='submit' disabled>Start</button>" in start
        assert "type='submit' disabled>Stop</button>" in stop
        assert "type='submit' disabled>Pull model</button>" in pull
    finally:
        app.close()


def test_job_activity_validation_precedes_filesystem_or_spawn(tmp_path: Path) -> None:
    service = _ControlService()
    app = _app(tmp_path, service)
    try:
        before = set((tmp_path / "state").iterdir())
        with pytest.raises(ValueError, match="unsupported job activity"):
            app.start_job(
                "webui_selftest",
                {"--selftest-sleep": "0"},
                activity="guessed_download",
            )
        with pytest.raises(ValueError, match="reserved for ollama_pull"):
            app.start_job(
                "webui_selftest",
                {"--selftest-sleep": "0"},
                activity="model_download",
            )
        assert set((tmp_path / "state").iterdir()) == before
    finally:
        app.close()


def test_job_activity_schema_migrates_persists_and_restores(tmp_path: Path) -> None:
    path = tmp_path / "console.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE jobs (job_id TEXT PRIMARY KEY, command TEXT, argv TEXT, "
        "directory TEXT, state TEXT, exit_code INTEGER, started_at REAL, "
        "ended_at REAL, updated_at REAL, builder_params TEXT, run_kind TEXT, "
        "out_dir TEXT, pin TEXT, failure TEXT)"
    )
    connection.commit()
    connection.close()
    db = ConsoleDB(path)
    try:
        columns = {
            str(row[1])
            for row in db._conn.execute("PRAGMA table_info(jobs)")  # type: ignore[union-attr]
        }
        assert "activity" in columns and db.SCHEMA_VERSION == 4
        job = Job(
            "download-job",
            "ollama_pull",
            ["python", "-m", "experiments.ollama_pull", "--model", "fixture"],
            tmp_path / "job",
            process=None,
            restored_state="running",
            activity="model_download",
        )
        assert db.upsert_job(job)
        row = db.load_jobs()[0]
        assert row["activity"] == "model_download"
    finally:
        db.close()


def test_terminal_pull_clears_activity_and_invalidates_roster(tmp_path: Path) -> None:
    service = _ControlService()
    app = _app(tmp_path, service)
    job = Job(
        "terminal-download",
        "ollama_pull",
        ["python", "-m", "experiments.ollama_pull", "--model", "fixture"],
        tmp_path / "state" / "jobs" / "terminal-download",
        process=_FakeProcess(code=0),
        activity="model_download",
    )
    app.jobs[job.job_id] = job
    try:
        app._reconcile()
        assert job.activity is None
        assert service.invalidated == 1
        assert app.db.load_jobs()[0]["activity"] is None
    finally:
        app.close()


class _Builder(BuilderModelsMixin):
    def __init__(self, root: Path, state: Path, service) -> None:
        self.repo_root = root
        self.state_dir = state
        self.ollama = service
        self.gpu_hardware = {"available": False, "gpu_count": 0, "gpus": []}


class _RosterService:
    def __init__(self, roster: dict[str, object]) -> None:
        self.value = roster
        self.entries: list[dict[str, object]] = []

    def roster(self, entries, *, force=False):
        del force
        self.entries.append(json.loads(json.dumps(entries)))
        return json.loads(json.dumps(self.value))


def _builder_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    rig = root / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "vllm-roster.example.json").write_text(
        json.dumps(
            {
                "models": {
                    "vllm:llava-hf/llava-v1.6-mistral-7b-hf": {
                        "modalities": ["text", "image"],
                        "revision": "a" * 40,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (rig / "local-targets.example.json").write_text("{}\n", encoding="utf-8")
    (rig / "api-targets.example.json").write_text("{}\n", encoding="utf-8")
    return root


def test_builder_uses_only_exact_live_rows_and_ignores_catalog_only_overlap(
    tmp_path: Path,
) -> None:
    root = _builder_repo(tmp_path)
    live = {
        "available": True,
        "excluded": [],
        "issues": [],
        "models": [
            {
                "spec": "ollama:granite:latest",
                "digest": "B" * 64,
                "modalities": ["text", "image"],
            }
        ],
    }
    service = _RosterService(live)
    builder = _Builder(root, tmp_path / "state", service)
    catalog, explicit = builder._local_entry_catalog()
    assert service.entries == [{}]
    assert explicit == set()
    assert catalog["ollama:granite:latest"] == {
        "digest": "B" * 64,
        "modalities": ["text", "image"],
    }
    generated = builder._materialize_selected_local_config(
        ["ollama:granite:latest"], require_live_ollama=True
    )
    assert json.loads(generated.read_text(encoding="utf-8")) == {
        "ollama:granite:latest": {
            "digest": "b" * 64,
            "modalities": ["text", "image"],
        }
    }

    manual_path = root / "experiments" / "local-targets.json"
    manual_spec = "ollama:opaque-build:latest"
    manual = {
        manual_spec: {
            "digest": "c" * 64,
            "modalities": ["text", "image"],
        }
    }
    manual_path.write_text(json.dumps(manual), encoding="utf-8")
    live["models"].append(
        {
            "spec": manual_spec,
            "digest": "c" * 64,
            "modalities": ["text", "image"],
            "details": {"family": "llava"},
            "overlap_with": [
                "vllm:llava-hf/llava-v1.6-mistral-7b-hf"
            ],
        }
    )
    generated = builder._materialize_selected_local_config(
        [manual_spec], require_live_ollama=True
    )
    assert manual_spec in json.loads(generated.read_text(encoding="utf-8"))
    paired = builder._materialize_selected_local_config(
        ["vllm:llava-hf/llava-v1.6-mistral-7b-hf", manual_spec],
        require_live_ollama=True,
    )
    assert set(json.loads(paired.read_text(encoding="utf-8"))) == {
        "vllm:llava-hf/llava-v1.6-mistral-7b-hf",
        manual_spec,
    }
    manual[manual_spec]["allow_vllm_overlap"] = True
    manual_path.write_text(json.dumps(manual), encoding="utf-8")
    generated = builder._materialize_selected_local_config(
        [manual_spec], require_live_ollama=True
    )
    assert "allow_vllm_overlap" not in json.loads(
        generated.read_text(encoding="utf-8")
    )[manual_spec]


def test_builder_keeps_downloaded_ollama_models_when_only_catalog_families_overlap(
    tmp_path: Path,
) -> None:
    root = _builder_repo(tmp_path)
    roster_path = root / "experiments" / "rig" / "vllm-roster.example.json"
    roster_path.write_text(
        json.dumps(
            {
                "models": {
                    "vllm:google/gemma-4-12B-it": {"modalities": ["text"]},
                    "vllm:mistralai/Ministral-3-3B-Instruct-2512": {
                        "modalities": ["text"]
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    live = {
        "available": True,
        "excluded": [],
        "issues": [],
        "models": [
            {
                "spec": "ollama:gemma4:12b-it-q4_K_M",
                "digest": "a" * 64,
                "modalities": ["text", "image"],
            },
            {
                "spec": "ollama:ministral-3:14b-instruct-2512-q4_K_M",
                "digest": "b" * 64,
                "modalities": ["text", "image"],
            },
        ],
    }
    service = _RosterService(live)
    builder = _Builder(root, tmp_path / "state", service)

    snapshot = builder._ollama_roster_snapshot(force=True)

    assert service.entries == [{}]
    assert [row["spec"] for row in snapshot["models"]] == [
        "ollama:gemma4:12b-it-q4_K_M",
        "ollama:ministral-3:14b-instruct-2512-q4_K_M",
    ]
    assert snapshot["excluded"] == []


def test_unavailable_daemon_adds_no_automatic_ollama_models(tmp_path: Path) -> None:
    root = _builder_repo(tmp_path)
    builder = _Builder(
        root,
        tmp_path / "state",
        _RosterService(
            {
                "available": False,
                "error": "unavailable",
                "models": [],
                "excluded": [],
                "issues": [],
            }
        ),
    )
    assert not any(option[0].startswith("ollama:") for option in builder._model_options())


def test_dry_run_discards_ollama_selection_without_daemon_discovery(
    tmp_path: Path,
) -> None:
    class OfflineControl(_ControlService):
        def __init__(self) -> None:
            super().__init__()
            self.roster_calls = 0

        def roster(self, _entries, *, force=False):
            del force
            self.roster_calls += 1
            return {
                "available": False,
                "error": "daemon intentionally absent",
                "models": [],
                "excluded": [],
                "issues": [],
            }

    service = OfflineControl()
    app = _app(tmp_path, service)
    try:
        command, values, _params = app._compose_from_builder(
            {
                "mode": "dry_run",
                "local": "ollama:absent:latest",
                "corpora": "synth",
                "attackers": "replay",
                "judges": "rules",
                "out": "runs/dry-ollama",
            }
        )
        assert command == "run_matrix" and values["--dry-run"] == "on"
        assert "--local" not in values and "--local-config" not in values
        assert service.roster_calls == 0
    finally:
        app.close()


@pytest.mark.parametrize(
    ("roster", "message"),
    (
        (
            {
                "available": False,
                "error": "daemon unavailable",
                "models": [],
                "excluded": [],
                "issues": [],
            },
            "current exact live roster",
        ),
        (
            {"available": True, "models": [], "excluded": [], "issues": []},
            "absent from the current exact Ollama daemon roster",
        ),
        (
            {
                "available": True,
                "models": [
                    {
                        "spec": "ollama:fixture:latest",
                        "digest": "f" * 64,
                        "modalities": ["text"],
                    }
                ],
                "excluded": [],
                "issues": [],
            },
            "do not match current live Ollama discovery",
        ),
        (
            {
                "available": True,
                "models": [
                    {
                        "spec": "ollama:fixture:latest",
                        "digest": "a" * 64,
                        "modalities": ["text", "image"],
                    }
                ],
                "excluded": [],
                "issues": [],
            },
            "do not match current live Ollama discovery",
        ),
    ),
)
def test_crafted_measured_post_rejects_unavailable_absent_or_stale_live_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    roster: dict[str, object],
    message: str,
) -> None:
    root = _builder_repo(tmp_path)
    spec = "ollama:fixture:latest"
    (root / "experiments" / "local-targets.json").write_text(
        json.dumps(
            {
                spec: {
                    "digest": "a" * 64,
                    "modalities": ["text"],
                }
            }
        ),
        encoding="utf-8",
    )

    class LiveControl(_ControlService):
        def roster(self, _entries, *, force=False):
            del force
            return json.loads(json.dumps(roster))

    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=root,
        gpu_hardware={"available": False, "gpu_count": 0, "gpus": []},
        system_hardware={"available": False},
        ollama_service=LiveControl(),
    )
    monkeypatch.setattr(app, "_validate_builder", lambda _params: {})
    before = set(app.jobs)
    try:
        status, _content_type, body = app.handle(
            "POST", "/build", {"mode": "measured", "local": spec}
        )
        assert status == 200
        assert message in body.decode("utf-8")
        assert set(app.jobs) == before
    finally:
        app.close()
