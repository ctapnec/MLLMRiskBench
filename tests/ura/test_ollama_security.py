from __future__ import annotations

import io
import json
import os
import signal
import stat
import tempfile
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
from ura.ollama_security import (
    NoRedirect,
    OllamaProcessLock,
    model_identity_keys,
    ollama_lock_path,
)
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


def _inventory(
    digest: str = _DIGEST_A,
    *,
    count: int = 1,
    model: str = "fixture:latest",
) -> dict[str, object]:
    return {
        "models": [
            {"name": model, "model": model, "digest": digest}
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


def _unload(*, model: str = "fixture:latest") -> dict[str, object]:
    return {
        "done": True,
        "done_reason": "unload",
        "model": model,
    }


def _target_with_sequence(
    monkeypatch: pytest.MonkeyPatch, documents: list[object]
) -> tuple[OllamaTarget, list[str]]:
    target = OllamaTarget("fixture:latest", model_digest=_DIGEST_A, timeout=2.0)
    calls: list[str] = []
    remaining = documents

    def opener(request, *, timeout):
        assert 0 < timeout <= 2.0
        calls.append(request.full_url.rsplit("/", 1)[-1])
        return _Response(remaining.pop(0))

    monkeypatch.setattr(target, "_open_request", opener)
    return target, calls


def test_chat_request_binds_explicit_thinking_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = OllamaTarget(
        "fixture:latest", model_digest=_DIGEST_A, think="low", timeout=2.0
    )
    observed: dict[str, object] = {}

    def bounded(request, *, purpose, deadline):
        observed.update(json.loads(request.data))
        assert purpose == "chat response"
        assert deadline > 0
        return _chat()

    monkeypatch.setattr(target, "_bounded_json_request", bounded)

    value = target._chat_http(
        [{"role": "user", "content": "probe"}], seed=7
    )

    assert value == _chat()
    assert observed["think"] == "low"
    assert observed["options"] == {
        "temperature": 0.0,
        "num_ctx": 8192,
        "num_predict": 512,
        "seed": 7,
    }


def test_target_transaction_exclusively_controls_and_releases_residency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _LifetimeLock:
        def __init__(
            self, *, exclusive: bool, namespace: str, **_kwargs: object
        ) -> None:
            events.append(f"{namespace}-{'exclusive' if exclusive else 'shared'}")
            self.namespace = namespace

        def __enter__(self) -> None:
            events.append(f"{self.namespace}-enter")

        def __exit__(self, *_args: object) -> None:
            events.append(f"{self.namespace}-exit")

    monkeypatch.setattr("ura.targets.local.OllamaProcessLock", _LifetimeLock)
    target = OllamaTarget("fixture:latest", model_digest=_DIGEST_A, timeout=2.0)
    calls: list[str] = []
    remaining = [
        _inventory(),
        {"models": []},
        _chat(),
        _inventory(),
        _inventory(),
        _inventory(),
        _inventory(),
        _unload(),
        {"models": []},
    ]

    def opener(request, *, timeout):
        assert 0 < timeout <= 2.0
        endpoint = request.full_url.rsplit("/", 1)[-1]
        calls.append(endpoint)
        if endpoint == "generate":
            payload = json.loads(request.data)
            assert payload == {
                "keep_alive": 0,
                "model": "fixture:latest",
                "stream": False,
            }
        document = remaining.pop(0)
        return _Response(document)

    monkeypatch.setattr(target, "_open_request", opener)

    response = target.generate([DialogTurn(role="user", content="probe")], seed=7)
    assert calls == ["tags", "ps", "chat", "tags", "ps"]
    assert events == [
        "inference-exclusive",
        "inference-enter",
    ]
    target.close()
    target.close()

    assert events == [
        "inference-exclusive",
        "inference-enter",
        "inference-exit",
    ]
    assert calls == [
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "generate", "ps",
    ]
    assert response.raw["model_residency_transaction"] == (
        "empty-pre/exact-selected-post/process-cleanup-registered"
    )
    assert remaining == []


def test_target_lifetime_lease_blocks_mutation_but_admits_status_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "http://127.0.0.1:18434"
    target = OllamaTarget(
        "fixture:latest",
        model_digest=_DIGEST_A,
        host=host,
        timeout=2.0,
    )
    remaining = [
        _inventory(),
        {"models": []},
        _chat(),
        _inventory(),
        _inventory(),
        _inventory(),
        _inventory(),
        _unload(),
        {"models": []},
    ]

    def opener(_request, *, timeout):
        assert 0 < timeout <= 2.0
        return _Response(remaining.pop(0))

    monkeypatch.setattr(target, "_open_request", opener)
    target.generate([DialogTurn(role="user", content="probe")])

    with OllamaProcessLock(
        base_url=host,
        exclusive=False,
        namespace="endpoint",
        deadline=time.monotonic() + 1.0,
    ):
        pass
    with pytest.raises(TimeoutError, match="lock acquisition"):
        with OllamaProcessLock(
            base_url=host,
            exclusive=True,
            namespace="endpoint",
            deadline=time.monotonic() + 0.05,
        ):
            raise AssertionError("endpoint mutation entered an active target lease")
    with pytest.raises(TimeoutError, match="lock acquisition"):
        with OllamaProcessLock(
            base_url=host,
            exclusive=True,
            namespace="inference",
            deadline=time.monotonic() + 0.05,
        ):
            raise AssertionError("second inference owner entered an active lease")

    target.close()
    with OllamaProcessLock(
        base_url=host,
        exclusive=True,
        namespace="endpoint",
        deadline=time.monotonic() + 1.0,
    ):
        pass
    with OllamaProcessLock(
        base_url=host,
        exclusive=True,
        namespace="inference",
        deadline=time.monotonic() + 1.0,
    ):
        pass
    assert remaining == []


def test_target_transaction_binds_pre_chat_post_and_loaded_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [
            _inventory(),
            {"models": []},
            _chat(),
            _inventory(),
            _inventory(),
            _inventory(),
            _inventory(),
            _unload(),
            {"models": []},
        ],
    )
    response = target.generate([DialogTurn(role="user", content="probe")], seed=7)
    target.close()
    assert calls == [
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "generate", "ps",
    ]
    assert response.raw["model_identity_transaction"] == (
        "pre-tags/chat/post-tags/post-ps"
    )
    assert response.raw["loaded_verified_model_digest"] == _DIGEST_A


def test_target_reuses_only_the_selected_residency_until_one_final_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [
            _inventory(),
            {"models": []},
            _chat(),
            _inventory(),
            _inventory(),
            _inventory(),
            _inventory(),
            _chat(),
            _inventory(),
            _inventory(),
            _inventory(),
            _inventory(),
            _unload(),
            {"models": []},
        ],
    )

    first = target.generate([DialogTurn(role="user", content="first")])
    second = target.generate([DialogTurn(role="user", content="second")])
    target.close()

    assert first.raw["model_residency_transaction"].startswith("empty-pre/")
    assert second.raw["model_residency_transaction"].startswith("selected-pre/")
    assert calls == [
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "generate", "ps",
    ]


def test_target_rejects_foreign_preloaded_model_without_mutating_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [_inventory(), _inventory(model="foreign:latest")],
    )

    with pytest.raises(LocalTargetOutputError, match="exactly one"):
        target.generate([DialogTurn(role="user", content="probe")])
    target.close()

    assert calls == ["tags", "ps"]


def test_target_refuses_to_adopt_selected_model_preloaded_by_another_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [_inventory(), _inventory()],
    )

    with pytest.raises(LocalTargetOutputError, match="outside this target lifecycle"):
        target.generate([DialogTurn(role="user", content="probe")])
    target.close()

    assert calls == ["tags", "ps"]


def test_invalid_chat_is_unloaded_before_the_original_error_is_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [
            _inventory(),
            {"models": []},
            {**_chat(), "done": False},
            _inventory(),
            _inventory(),
            _unload(),
            {"models": []},
        ],
    )

    with pytest.raises(LocalTargetOutputError, match="done=true"):
        target.generate([DialogTurn(role="user", content="probe")])
    target.close()

    assert calls == [
        "tags", "ps", "chat", "tags", "ps", "generate", "ps"
    ]


def test_cleanup_rejects_a_generate_response_that_did_not_confirm_unload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = [
        _inventory(),
        {"models": []},
        _chat(),
        _inventory(),
        _inventory(),
        _inventory(),
        _inventory(),
        {**_unload(), "done_reason": "stop"},
    ]
    target, calls = _target_with_sequence(monkeypatch, documents)

    target.generate([DialogTurn(role="user", content="probe")])
    with pytest.raises(LocalTargetOutputError, match="done_reason='unload'"):
        target.close()

    assert calls == [
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "generate",
    ]
    documents.extend([_inventory(), _inventory(), _unload(), {"models": []}])
    target.close()


def test_cleanup_polls_only_the_selected_model_until_residency_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, calls = _target_with_sequence(
        monkeypatch,
        [
            _inventory(),
            {"models": []},
            _chat(),
            _inventory(),
            _inventory(),
            _inventory(),
            _inventory(),
            _unload(),
            _inventory(),
            _inventory(),
            {"models": []},
        ],
    )
    sleeps: list[float] = []
    target._sleep = sleeps.append

    target.generate([DialogTurn(role="user", content="probe")])
    target.close()

    assert calls == [
        "tags", "ps", "chat", "tags", "ps",
        "tags", "ps", "generate", "ps", "ps", "ps",
    ]
    assert sleeps == [0.05, 0.05]


@pytest.mark.parametrize(
    ("failed_cleanup", "message"),
    (
        ([_inventory(_DIGEST_B)], "does not match declared"),
        (
            [_inventory(), _inventory(model="foreign:latest")],
            "did not resolve exactly one",
        ),
    ),
)
def test_cleanup_revalidates_without_posting_on_drift_or_foreign_residency(
    monkeypatch: pytest.MonkeyPatch,
    failed_cleanup: list[object],
    message: str,
) -> None:
    documents = [
        _inventory(),
        {"models": []},
        _chat(),
        _inventory(),
        _inventory(),
        *failed_cleanup,
        _inventory(),
        _inventory(),
        _unload(),
        {"models": []},
    ]
    target, calls = _target_with_sequence(monkeypatch, documents)
    target.generate([DialogTurn(role="user", content="probe")])

    before = len(calls)
    with pytest.raises(LocalTargetOutputError, match=message):
        target.close()
    assert "generate" not in calls[before:]

    target.close()
    assert documents == []


@pytest.mark.parametrize(
    ("documents", "message"),
    (
        ([_inventory(count=2)], "exactly one"),
        (
            [
                _inventory(),
                {"models": []},
                _chat(),
                _inventory(_DIGEST_B),
                _inventory(),
                _inventory(),
                _unload(),
                {"models": []},
            ],
            "does not match declared",
        ),
        (
            [
                _inventory(),
                {"models": []},
                _chat(),
                _inventory(),
                {"models": []},
                _inventory(),
                {"models": []},
            ],
            "exactly one",
        ),
        (
            [
                _inventory(),
                {"models": []},
                _chat(),
                _inventory(),
                _inventory(count=2),
                _inventory(),
                _inventory(count=2),
                _inventory(),
                _inventory(),
                _unload(),
                {"models": []},
            ],
            "co-resident",
        ),
        (
            [
                _inventory(),
                {"models": []},
                _chat(model="other:latest"),
                _inventory(),
                _inventory(),
                _unload(),
                {"models": []},
            ],
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
    target.close()


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


def test_catalog_only_base_family_alias_does_not_reject_ollama_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    def roster(_self, entries, *, force=False):
        assert entries == {}
        assert force is True
        return {
            "available": True,
            "models": [
                {"spec": spec, "digest": _DIGEST_A, "modalities": ["text", "image"]}
            ],
            "excluded": [],
        }

    monkeypatch.setattr(OllamaService, "roster", roster)
    loaded, _profile = run_matrix._load_local_config(str(config), [spec])
    assert loaded[spec]["digest"] == _DIGEST_A


def test_runner_allows_overlap_with_vllm_selected_in_same_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ollama_spec = "ollama:library/llama3.2-vision:latest"
    vllm_spec = "vllm:meta-llama/Llama-3.2-11B-Vision-Instruct"
    config = tmp_path / "local.json"
    config.write_text(
        json.dumps(
            {
                vllm_spec: {
                    "revision": "a" * 40,
                    "modalities": ["text", "image"],
                },
                ollama_spec: {
                    "digest": _DIGEST_A,
                    "modalities": ["text", "image"],
                },
            }
        ),
        encoding="utf-8",
    )

    def roster(_self, entries, *, force=False):
        assert entries == {}
        assert force is True
        return {
            "available": True,
            "models": [
                {
                    "spec": ollama_spec,
                    "digest": _DIGEST_A,
                    "modalities": ["text", "image"],
                }
            ],
            "excluded": [],
        }

    monkeypatch.setattr(OllamaService, "roster", roster)
    loaded, _profile = run_matrix._load_local_config(
        str(config),
        [vllm_spec, ollama_spec],
        hardware={"available": False},
    )
    assert set(loaded) == {vllm_spec, ollama_spec}


def test_runner_ignores_legacy_live_overlap_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = "ollama:opaque-build:latest"
    config = tmp_path / "local.json"
    vllm_spec = "vllm:meta-llama/Llama-3-8B-Instruct"
    config.write_text(
        json.dumps(
            {
                vllm_spec: {"revision": "a" * 40, "modalities": ["text"]},
                spec: {"digest": _DIGEST_A, "modalities": ["text"]},
            }
        ),
        encoding="utf-8",
    )

    def roster(_self, entries, *, force=False):
        assert entries == {}
        assert force is True
        return {
            "available": True,
            "models": [
                {
                    "spec": spec,
                    "digest": _DIGEST_A,
                    "modalities": ["text"],
                    "overlap_with": ["vllm:meta-llama/Llama-3-8B-Instruct"],
                }
            ],
            "excluded": [],
        }

    monkeypatch.setattr(OllamaService, "roster", roster)
    loaded, _profile = run_matrix._load_local_config(
        str(config), [vllm_spec, spec], hardware={"available": False}
    )
    assert set(loaded) == {vllm_spec, spec}


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


def test_lock_directory_is_per_account_and_never_the_shared_literal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Windows has no os.getuid.  The old fallback used the literal "windows"
    # for every account, so all identities shared ONE directory created with
    # mode 0o700 - which Windows honours as a DACL carrying no user ACE.  The
    # first creator then locked out every other account, and the workstation
    # itself once the entry went stale (36 tests failed this way).  The suffix
    # must be per-account and must never be that shared literal again.
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.delattr(os, "getuid", raising=False)

    monkeypatch.setenv("USERDOMAIN", "DOMAIN-A")
    monkeypatch.setenv("USERNAME", "alice")
    alice = ollama_lock_path()
    monkeypatch.setenv("USERNAME", "bob")
    bob = ollama_lock_path()

    assert alice.parent != bob.parent, "accounts must not share a lock directory"
    for path in (alice, bob):
        assert path.parent.name != "ura-ollama-lock-windows"
        assert path.parent.name.startswith("ura-ollama-lock-")
    # The same endpoint still maps to the same lock file name within an account.
    assert alice.name == bob.name

    # The POSIX branch stays byte-identical to the original behaviour.
    monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
    assert ollama_lock_path().parent.name == "ura-ollama-lock-1000"
