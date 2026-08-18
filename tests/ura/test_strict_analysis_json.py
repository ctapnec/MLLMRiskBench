from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from experiments import human_audit, judge_sensitivity, local_targets, transfer_matrix
from experiments.analysis_integrity import read_bound_json
from experiments.rig_web_app.builder_models import BuilderModelsMixin
from ura.strict_json import DuplicateJSONKeyError, strict_json_loads


def test_strict_json_rejects_utf8_bom_equally_for_text_and_bytes() -> None:
    errors: list[tuple[type[BaseException], str]] = []
    for payload in (
        '\ufeff{"status":"complete"}',
        b'\xef\xbb\xbf{"status":"complete"}',
    ):
        with pytest.raises(json.JSONDecodeError) as exc_info:
            strict_json_loads(payload)
        errors.append((type(exc_info.value), str(exc_info.value)))
    assert errors[0] == errors[1]


def test_strict_json_rejects_duplicate_decoded_key_names() -> None:
    with pytest.raises(DuplicateJSONKeyError, match="duplicate JSON object key 'model'"):
        strict_json_loads('{"model":"first","\\u006dodel":"second"}')


def test_strict_json_normalizes_decoder_recursion_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def recursive_decoder(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("decoder recursion")

    monkeypatch.setattr(json, "loads", recursive_decoder)
    with pytest.raises(ValueError, match="decoder limit") as exc_info:
        strict_json_loads("[]")
    assert not isinstance(exc_info.value, RecursionError)


def _read_bound(path: Path) -> object:
    return read_bound_json(path)


def _read_transfer_object(path: Path) -> object:
    return transfer_matrix._read_object(path)


def _read_transfer_jsonl(path: Path) -> object:
    return transfer_matrix._read_jsonl(path)


def _read_human_jsonl(path: Path) -> object:
    return human_audit._read_jsonl_paths([path])


def _read_judge_jsonl(path: Path) -> object:
    return judge_sensitivity._read_jsonl(path)


@pytest.mark.parametrize(
    "reader",
    [
        _read_bound,
        _read_transfer_object,
        _read_transfer_jsonl,
        _read_human_jsonl,
        _read_judge_jsonl,
    ],
)
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ('{"status":"unvalidated","status":"validated"}\n', "duplicate JSON"),
        ('{"metric":NaN}\n', "numeric constant"),
    ],
)
def test_analysis_trust_roots_reject_ambiguous_or_nonfinite_json(
    tmp_path: Path,
    reader: Callable[[Path], object],
    payload: str,
    message: str,
) -> None:
    artifact = tmp_path / "artifact.jsonl"
    artifact.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        reader(artifact)


def test_operator_model_registries_fall_back_without_admitting_duplicate_keys(
    tmp_path: Path,
) -> None:
    experiments = tmp_path / "experiments"
    rig = experiments / "rig"
    rig.mkdir(parents=True)

    (experiments / "vllm-roster.json").write_text(
        '{"models":{"vllm:ambiguous/model":{"revision":"a"},'
        '"vllm:ambiguous/model":{"revision":"b"}}}',
        encoding="utf-8",
    )
    (rig / "vllm-roster.example.json").write_text(
        '{"models":{"vllm:safe/model":{"revision":"c"}}}',
        encoding="utf-8",
    )
    roster = local_targets.load_roster(tmp_path)
    assert set(local_targets._models_map(roster)) == {"vllm:safe/model"}

    (experiments / "api-targets.json").write_text(
        '{"anthropic:ambiguous":{"modalities":["text"]},'
        '"anthropic:ambiguous":{"modalities":["image"]}}',
        encoding="utf-8",
    )
    (rig / "api-targets.example.json").write_text(
        '{"anthropic:safe":{"modalities":["text"]}}',
        encoding="utf-8",
    )
    loader = object.__new__(BuilderModelsMixin)
    loader.repo_root = tmp_path
    registry = loader._load_registry(
        "api-targets.json", "rig/api-targets.example.json"
    )
    assert set(registry) == {"anthropic:safe"}
