from __future__ import annotations

import http.client
import io
import json
from pathlib import Path
import urllib.error

import experiments.local_campaign.ollama_acquire as acquire_module
from experiments.local_campaign.ollama_acquire import acquire, canonical


class _Response(io.BytesIO):
    def __iter__(self):
        return iter(self.readlines())


class _InterruptedResponse(_Response):
    def __iter__(self):
        raise http.client.IncompleteRead(b'{"status":"pulling"', 1)


def _json_response(value: object) -> _Response:
    return _Response(json.dumps(value).encode("ascii"))


def test_resume_skips_completed_models_and_retries_interrupted_partial_pull(
    tmp_path: Path,
) -> None:
    models = ["gemma4:12b-it-q4_K_M", "deepseek-r1:32b-qwen-distill-q4_K_M"]
    root = tmp_path / "ollama-acquisition"
    root.mkdir()
    (root / "events.jsonl").write_bytes(
        b"".join(
            (
                canonical({"event": "start", "models": models, "version": {"version": "1"}}),
                canonical({"event": "pull_complete", "model": models[0]}),
                canonical(
                    {
                        "done_reason": "stop",
                        "elapsed_seconds": 1.0,
                        "event": "load_smoke_complete",
                        "model": models[0],
                        "response": "OK",
                    }
                ),
                canonical({"event": "pull_start", "model": models[1]}),
            )
        )
    )
    installed = {models[0]}
    pulls: list[str] = []
    generated: list[str] = []
    final_tag_failures = 0

    def request(_base, path, payload=None, *, timeout):
        nonlocal final_tag_failures
        assert timeout > 0
        if path == "/api/tags":
            if len(installed) == len(models) and len(generated) == 2 and not final_tag_failures:
                final_tag_failures += 1
                raise urllib.error.URLError("temporary DNS failure")
            return _json_response(
                {"models": [{"name": model, "digest": model} for model in installed]}
            )
        if path == "/api/pull":
            model = payload["model"]
            pulls.append(model)
            if len(pulls) == 1:
                return _InterruptedResponse()
            if len(pulls) == 2:
                return _Response(b'{"error":"max retries exceeded: DNS connection refused"}\n')
            installed.add(model)
            return _Response(b'{"status":"success"}\n')
        if path == "/api/generate":
            generated.append(payload["model"])
            if len(generated) == 1:
                raise urllib.error.URLError("temporary connection refused")
            return _json_response({"done": True, "done_reason": "stop", "response": "OK"})
        raise AssertionError(path)

    sleeps: list[float] = []
    assert (
        acquire(
            out_dir=root,
            models=models,
            resume=True,
            retry_delay_seconds=1,
            max_retry_delay_seconds=2,
            deadline_seconds=60,
            request_fn=request,
            sleep=sleeps.append,
        )
        == 0
    )
    assert pulls == [models[1], models[1], models[1]]
    assert generated == [models[1], models[1]]
    assert final_tag_failures == 1
    assert sleeps == [1, 2, 1, 1]
    events = [
        json.loads(line)
        for line in (root / "events.jsonl").read_text(encoding="ascii").splitlines()
    ]
    retries = [row for row in events if row["event"] == "pull_retry"]
    assert retries == [
        {
            "attempt": 1,
            "delay_seconds": 1,
            "event": "pull_retry",
            "model": models[1],
            "reason_code": "pull_attempt_failed",
        },
        {
            "attempt": 2,
            "delay_seconds": 2,
            "event": "pull_retry",
            "model": models[1],
            "reason_code": "ollama_internal_retry_exhausted",
        },
    ]
    assert [row["event"] for row in events if row["event"].endswith("_retry")] == [
        "pull_retry",
        "pull_retry",
        "load_smoke_retry",
        "roster_retry",
    ]
    assert (root / ".exit").read_bytes() == b"0\n"
    assert [
        row["name"]
        for row in json.loads((root / "selected-roster.json").read_text(encoding="ascii"))["models"]
    ] == models


def test_resume_rejects_a_different_model_roster(tmp_path: Path) -> None:
    root = tmp_path / "ollama-acquisition"
    root.mkdir()
    (root / "events.jsonl").write_bytes(
        canonical({"event": "start", "models": ["gemma4:12b"], "version": {}})
    )

    try:
        acquire(
            out_dir=root,
            models=["ministral-3:14b"],
            resume=True,
            deadline_seconds=60,
        )
    except ValueError as exc:
        assert "roster differs" in str(exc)
    else:
        raise AssertionError("resume accepted a different model roster")


def test_terminal_failure_unblocks_waiters_without_retaining_transport_text(
    tmp_path: Path,
    monkeypatch,
) -> None:
    model = "deepseek-r1:32b-qwen-distill-q4_K_M"
    root = (tmp_path / "ollama-acquisition").resolve()
    root.mkdir()
    (root / "events.jsonl").write_bytes(
        canonical({"event": "start", "models": [model], "version": {}})
    )

    def fail(**_kwargs):
        raise RuntimeError("signed https://example.invalid/private?credential=value")

    monkeypatch.setattr(acquire_module, "acquire", fail)
    assert acquire_module.main(["--resume", "--out-dir", str(root), model]) == 1
    assert (root / ".exit").read_bytes() == b"1\n"
    failure = json.loads((root / "failure.json").read_text(encoding="ascii"))
    assert failure == {
        "error_type": "RuntimeError",
        "reason_code": "pull_attempt_failed",
        "schema": "ura-ollama-acquisition-failure/1",
        "status": "failed",
    }
    assert "credential" not in (root / "failure.json").read_text(encoding="ascii")
