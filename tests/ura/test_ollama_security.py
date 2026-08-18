from __future__ import annotations

import io
import json
import os
import signal
import stat
import threading
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import ollama_pull, run_matrix
from experiments.rig_web_app.ollama_service import (
    DEFAULT_OLLAMA_URL,
    OllamaAPI,
    OllamaError,
    OllamaService,
    OllamaUnavailable,
)
from ura.data_models import DialogTurn
from ura.ollama_security import NoRedirect, OllamaProcessLock, model_identity_keys
from ura.targets.local import LocalTargetOutputError, OllamaTarget


_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_PROCESS_IDENTITY = "linux-proc-v1:4242:100"


class _Response:
    def __init__(self, document: object) -> None:
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        self.stream = io.BytesIO(raw)
        self.headers: dict[str, str] = {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def read(self, amount: int = -1) -> bytes:
        return self.stream.read(amount)

    def read1(self, amount: int = -1) -> bytes:
        return self.stream.read(amount)

    def close(self) -> None:
        self.closed = True


def _inventory(digest: str = _DIGEST_A, *, count: int = 1) -> dict[str, object]:
    return {
        "models": [
            {"name": "fixture:latest", "model": "fixture:latest", "digest": digest}
            for _index in range(count)
        ]
    }


def _chat(*, model: str = "fixture:latest") -> dict[str, object]:
    return {
        "done": True,
        "done_reason": "stop",
        "eval_count": 2,
        "message": {"role": "assistant", "content": "verified response"},
        "model": model,
        "prompt_eval_count": 3,
    }


def _target_with_sequence(
    monkeypatch: pytest.MonkeyPatch, documents: list[object]
) -> tuple[OllamaTarget, list[str]]:
    target = OllamaTarget("fixture:latest", model_digest=_DIGEST_A, timeout=2.0)
    calls: list[str] = []
    remaining = list(documents)

    def opener(request, *, timeout):
        assert 0 < timeout <= 2.0
        calls.append(request.full_url.rsplit("/", 1)[-1])
        return _Response(remaining.pop(0))

    monkeypatch.setattr(target, "_open_request", opener)
    return target, calls


def test_target_transaction_binds_pre_chat_post_and_loaded_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [_inventory(), _chat(), _inventory(), _inventory()],
    )
    response = target.generate([DialogTurn(role="user", content="probe")], seed=7)
    assert calls == ["tags", "chat", "tags", "ps"]
    assert response.raw["model_identity_transaction"] == (
        "pre-tags/chat/post-tags/post-ps"
    )
    assert response.raw["loaded_verified_model_digest"] == _DIGEST_A


@pytest.mark.parametrize(
    ("documents", "message"),
    (
        ([_inventory(count=2)], "exactly one"),
        (
            [_inventory(), _chat(), _inventory(_DIGEST_B)],
            "does not match declared",
        ),
        (
            [_inventory(), _chat(), _inventory(), {"models": []}],
            "exactly one",
        ),
        (
            [_inventory(), _chat(), _inventory(), _inventory(count=2)],
            "exactly one",
        ),
        (
            [_inventory(), _chat(model="other:latest")],
            "unexpected model identity",
        ),
    ),
)
def test_target_transaction_rejects_duplicate_drift_missing_and_aliases(
    monkeypatch: pytest.MonkeyPatch,
    documents: list[object],
    message: str,
) -> None:
    target, _calls = _target_with_sequence(monkeypatch, documents)
    with pytest.raises(LocalTargetOutputError, match=message):
        target.generate([DialogTurn(role="user", content="probe")])


def test_target_default_transport_has_no_proxy_or_redirect_and_fixed_origin() -> None:
    target = OllamaTarget(
        "fixture:latest",
        model_digest=_DIGEST_A,
        host="http://localhost:11434/",
    )
    assert target.host == DEFAULT_OLLAMA_URL
    opener = target._open_request.__self__
    proxy_handlers = [
        handler
        for handler in opener.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    ]
    # ProxyHandler({}) suppresses the environment-derived default handler; an
    # empty handler has no protocol method and is therefore omitted entirely.
    assert proxy_handlers == []
    assert any(isinstance(handler, NoRedirect) for handler in opener.handlers)
    for unsafe in (
        "http://127.0.0.1.evil.test:11434",
        "http://2130706433:11434",
        "http://user@127.0.0.1:11434",
        "https://127.0.0.1:11434",
    ):
        with pytest.raises(ValueError):
            OllamaTarget("fixture:latest", model_digest=_DIGEST_A, host=unsafe)


def test_api_header_open_is_a_hard_wall_not_an_inactivity_timeout() -> None:
    release = threading.Event()

    def drip_header(_request, *, timeout):
        assert timeout <= 0.1
        release.wait(2.0)
        return _Response({"models": []})

    api = OllamaAPI(timeout=0.1, open_request=drip_header)
    started = time.monotonic()
    try:
        with pytest.raises(OllamaUnavailable, match="unavailable"):
            api.tags()
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_base_family_aliases_overlap_and_runner_rejects_crafted_config(
    tmp_path: Path,
) -> None:
    assert "base-family:llama" in model_identity_keys(
        "ollama:library/llama3.2-vision:latest"
    )
    assert "base-family:llama" in model_identity_keys(
        "vllm:meta-llama/Llama-3.2-11B-Vision-Instruct"
    )
    assert "base-family:phi" in model_identity_keys("opaque", "phi")
    assert "base-family:phi" in model_identity_keys(
        "vllm:microsoft/Phi-3-mini-4k-instruct"
    )
    spec = "ollama:library/llama3.2-vision:latest"
    config = tmp_path / "local.json"
    config.write_text(
        json.dumps(
            {spec: {"digest": _DIGEST_A, "modalities": ["text", "image"]}}
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="overlaps the vLLM roster"):
        run_matrix._load_local_config(str(config), [spec])


def test_runner_independently_rejects_opaque_tag_with_live_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = "ollama:opaque-build:latest"
    config = tmp_path / "local.json"
    config.write_text(
        json.dumps({spec: {"digest": _DIGEST_A, "modalities": ["text"]}}),
        encoding="utf-8",
    )

    def roster(_self, _entries, *, force=False):
        assert force is True
        return {
            "available": True,
            "models": [],
            "excluded": [
                {
                    "spec": spec,
                    "digest": _DIGEST_A,
                    "modalities": ["text"],
                    "overlap_with": ["vllm:meta-llama/Llama-3-8B-Instruct"],
                }
            ],
        }

    monkeypatch.setattr(OllamaService, "roster", roster)
    with pytest.raises(ValueError, match="live /api/show identity overlaps"):
        run_matrix._load_local_config(str(config), [spec])


def test_runner_live_admission_binds_exact_digest_and_modalities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = "ollama:security-fixture-unique:latest"
    config = tmp_path / "local.json"
    config.write_text(
        json.dumps({spec: {"digest": _DIGEST_A, "modalities": ["text"]}}),
        encoding="utf-8",
    )

    def roster(_self, _entries, *, force=False):
        assert force is True
        return {
            "available": True,
            "models": [
                {"spec": spec, "digest": _DIGEST_B, "modalities": ["text"]}
            ],
            "excluded": [],
        }

    monkeypatch.setattr(OllamaService, "roster", roster)
    with pytest.raises(ValueError, match="do not match current live"):
        run_matrix._load_local_config(str(config), [spec])


def test_cross_process_lock_blocks_mutation_while_inference_lock_is_held() -> None:
    with OllamaProcessLock(
        base_url=DEFAULT_OLLAMA_URL,
        exclusive=False,
        deadline=time.monotonic() + 1.0,
    ):
        with pytest.raises(TimeoutError, match="lock acquisition"):
            with OllamaProcessLock(
                base_url=DEFAULT_OLLAMA_URL,
                exclusive=True,
                deadline=time.monotonic() + 0.05,
            ):
                raise AssertionError("exclusive lock unexpectedly admitted")


def test_pull_requires_frozen_process_listener_and_storage_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    opened = False

    def opener(*_args, **_kwargs):
        nonlocal opened
        opened = True
        return _Response(b'{"status":"success"}\n')

    result = ollama_pull.pull(
        "fixture:latest",
        models_path=str(tmp_path.resolve()),
        owned_pid=4242,
        owned_process_identity=_PROCESS_IDENTITY,
        open_request=opener,
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: "linux-proc-v1:4242:101",
        listener_owner=lambda *_args: True,
    )
    assert result == 1 and opened is False
    assert "process identity changed" in capsys.readouterr().err

    result = ollama_pull.pull(
        "fixture:latest",
        models_path=str(tmp_path.resolve()),
        owned_pid=4242,
        owned_process_identity=_PROCESS_IDENTITY,
        open_request=opener,
        disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
        process_identity=lambda _pid: _PROCESS_IDENTITY,
        listener_owner=lambda *_args: False,
    )
    assert result == 1 and opened is False
    assert "no longer owns" in capsys.readouterr().err


def test_pull_header_open_obeys_hard_runtime_deadline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    def drip_header(_request, *, timeout):
        assert timeout <= 0.05
        release.wait(2.0)
        return _Response(b'{"status":"success"}\n')

    monkeypatch.setattr(ollama_pull, "_MAX_RUNTIME_SECONDS", 0.05)
    started = time.monotonic()
    try:
        assert (
            ollama_pull.pull(
                "fixture:latest",
                models_path=str(tmp_path.resolve()),
                owned_pid=4242,
                owned_process_identity=_PROCESS_IDENTITY,
                timeout_seconds=1.0,
                open_request=drip_header,
                disk_usage=lambda _path: SimpleNamespace(free=100 * 1024**3),
                process_identity=lambda _pid: _PROCESS_IDENTITY,
                listener_owner=lambda *_args: True,
            )
            == 1
        )
        assert time.monotonic() - started < 0.5
        assert "hard wall-clock deadline" in capsys.readouterr().err
    finally:
        release.set()


class _Process:
    pid = 4242

    def __init__(self, code: int | None) -> None:
        self.code = code

    def poll(self):
        return self.code

    def wait(self, timeout=None):
        del timeout
        if self.code is None:
            raise TimeoutError
        return self.code

    def kill(self):
        self.code = -getattr(signal, "SIGKILL", 9)


class _SwitchingAPI:
    timeout = 0.05
    base_url = DEFAULT_OLLAMA_URL

    def __init__(self, running: bool = False) -> None:
        self.running = running

    def tags(self, *, timeout=None):
        del timeout
        if not self.running:
            raise OllamaUnavailable("absent")
        return {"models": []}

    def ps(self, *, timeout=None):
        del timeout
        if not self.running:
            raise OllamaUnavailable("absent")
        return {"models": []}


def test_unconfirmed_descendant_cleanup_retains_owned_error_for_stop_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    residue = [True]
    process = _Process(code=1)

    def killpg(_pgid: int, sent: int) -> None:
        if sent == 0 and not residue[0]:
            raise ProcessLookupError

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    service = OllamaService(
        tmp_path,
        api=_SwitchingAPI(),
        platform="posix",
        monotonic=lambda: clock[0],
        sleep=lambda delay: clock.__setitem__(0, clock[0] + max(delay, 0.05)),
        process_identity=lambda _pid: _PROCESS_IDENTITY,
    )
    service._owned_process = process
    service._owned_pgid = process.pid
    service._owned_process_identity = _PROCESS_IDENTITY
    failed = service.status()
    assert failed["state"] == "error"
    assert failed["owned_by_console"] is True and failed["can_stop"] is True
    assert "ownership is retained" in str(failed["last_error"])

    residue[0] = False
    stopped = service.stop()
    assert stopped["state"] == "stopped" and stopped["owned_by_console"] is False


@pytest.mark.parametrize("action", ["status", "stop", "close"])
@pytest.mark.parametrize("current_identity", [None, "linux-proc-v1:4242:reused"])
def test_exited_parent_reused_pid_and_pgid_are_never_signalled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    current_identity: str | None,
) -> None:
    process = _Process(code=1)
    signals: list[int] = []

    def killpg(_pgid: int, sent: int) -> None:
        if sent != 0:
            signals.append(sent)

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    service = OllamaService(
        tmp_path,
        api=_SwitchingAPI(),
        platform="posix",
        process_identity=lambda _pid: current_identity,
    )
    service._owned_process = process
    service._owned_pgid = process.pid
    service._owned_process_identity = _PROCESS_IDENTITY

    if action == "status":
        result = service.status()
        assert result["state"] == "error" and result["can_stop"] is True
    elif action == "stop":
        with pytest.raises(OllamaError, match="ownership is retained"):
            service.stop()
    else:
        service.close()

    assert signals == []
    assert service._owned_process is process
    assert "leader identity" in service._owned_cleanup_error


def test_sigkill_is_forbidden_after_leader_identity_disappears_during_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _Process(code=None)
    identities = iter((_PROCESS_IDENTITY, None, None))
    signals: list[int] = []

    def killpg(_pgid: int, sent: int) -> None:
        if sent != 0:
            signals.append(sent)

    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    service = OllamaService(
        tmp_path,
        api=_SwitchingAPI(),
        platform="posix",
        process_identity=lambda _pid: next(identities, None),
    )
    service._owned_process = process
    service._owned_pgid = process.pid
    service._owned_process_identity = _PROCESS_IDENTITY

    with pytest.raises(OllamaError, match="disappeared during cleanup"):
        service.stop()
    assert signals == [getattr(signal, "SIGTERM", 15)]
    assert getattr(signal, "SIGKILL", 9) not in signals
    assert service._owned_process is process
    assert service.status()["state"] == "error"


def test_bind_race_stays_ambiguous_until_listener_ownership_is_proven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "ollama"
    executable.write_text("fixture", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    api = _SwitchingAPI()
    process = _Process(code=None)
    clock = [0.0]

    def popen(_argv, **_kwargs):
        api.running = True
        return process

    monkeypatch.setattr(os, "killpg", lambda *_args: None, raising=False)
    service = OllamaService(
        tmp_path / "state",
        api=api,
        platform="posix",
        popen_factory=popen,
        which=lambda _name: str(executable),
        monotonic=lambda: clock[0],
        sleep=lambda delay: clock.__setitem__(0, clock[0] + max(delay, 0.1)),
        start_timeout=0.5,
        listener_owner=lambda *_args: False,
        process_identity=lambda _pid: _PROCESS_IDENTITY,
    )
    result = service.start()
    assert result["state"] == "ambiguous"
    assert result["owned_by_console"] is True
    assert result["listener_owner_verified"] is False
    assert result["can_pull"] is False and result["can_stop"] is True
    with pytest.raises(OllamaUnavailable, match="external/ambiguous"):
        service.validate_pull_storage()


def test_external_daemon_never_has_a_pull_storage_contract(tmp_path: Path) -> None:
    service = OllamaService(
        tmp_path,
        api=_SwitchingAPI(running=True),
        platform="posix",
    )
    assert service.status()["state"] == "external"
    with pytest.raises(OllamaUnavailable, match="external/ambiguous"):
        service.validate_pull_storage()
