"""Release fidelity, modality coverage, and bounded-import regressions."""
from __future__ import annotations

import base64
import csv
import hashlib
import json
from pathlib import Path

import pytest

import ura.converters.mmsafety as mmsafety_module
from ura.adapters._engine_common import _sanitised_child_env
from ura.adapters._native_artifacts import read_binary_artifact
from ura.converters import CorpusFormatError, MMSafetyConverter, MOSSBenchConverter
from ura.converters._common import (
    _read_bounded_bytes,
    canonical_converted_corpus_sha256,
    read_json,
)
from ura.converters.release_specs import (
    CORPUS_RELEASE_SPECS,
    MM_SAFETYBENCH_SCENARIO_COUNTS,
    MM_SAFETYBENCH_VARIANTS,
)
from ura.data_models import (
    DataPoint,
    DialogTurn,
    Judgment,
    MediaRef,
    Response,
    RiskCategory,
)
from ura.modality_coverage import (
    ModalityCoverageError,
    declared_target_combinations,
    plan_modality_coverage,
    verify_executed_modality_coverage,
)
from ura.targets.base import BaseTarget
from ura.targets.guarded import GuardedTarget
from ura.targets.local import (
    LocalTargetOutputError,
    OllamaTarget,
    _dialog_to_ollama_messages,
)


_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF"


class _Target(BaseTarget):
    name = "fixture-multimodal"

    def __init__(
        self,
        support: tuple[str, ...],
        combinations: tuple[tuple[str, ...], ...] | None = None,
    ) -> None:
        self.modality_support = support
        if combinations is not None:
            self.modality_combinations = combinations

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        raise AssertionError("coverage planning must not call the target")


def _point(ident: str, modalities: list[str]) -> DataPoint:
    payloads = {
        "image": ("image/png", _PNG),
        "audio": ("audio/wav", b"RIFF\x04\x00\x00\x00WAVE"),
        "video": ("video/mp4", b"\x00\x00\x00\x18ftypmp42"),
    }
    media: list[MediaRef] = []
    for modality in ("image", "audio", "video"):
        if modality not in modalities:
            continue
        mime, payload = payloads[modality]
        media.append(MediaRef(
            modality=modality,  # type: ignore[arg-type]
            uri=(
                f"data:{mime};base64,"
                + base64.b64encode(payload).decode("ascii")
            ),
            mime=mime,
            sha256=hashlib.sha256(payload).hexdigest(),
        ))
    return DataPoint(
        id=ident,
        source="fixture",
        modalities=modalities,
        dialog_history=[DialogTurn(role="user", content="probe", media=media)],
        media=media,
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _write_mm_record_set(path: Path, count: int) -> None:
    records = {
        str(index): {
            "Question": "unsafe original",
            "Changed Question": "unsafe changed",
            "Key Phrase": "unsafe phrase",
            "Phrase Type": "activity",
            "Rephrased Question": "Read the image and respond.",
            "Rephrased Question(SD)": "Read the image and respond.",
        }
        for index in range(count)
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records), encoding="utf-8")


def test_mmsafety_small_official_layout_emits_every_real_variant(tmp_path: Path):
    scenario = "10-Legal_Opinion"
    _write_mm_record_set(
        tmp_path / "data" / "processed_questions" / f"{scenario}.json", 1
    )
    for variant in MM_SAFETYBENCH_VARIANTS:
        asset = tmp_path / "data" / "imgs" / scenario / variant / "0.jpg"
        asset.parent.mkdir(parents=True, exist_ok=True)
        asset.write_bytes(_JPEG)

    points = MMSafetyConverter(require_complete_release=False).parse(tmp_path)

    assert len(points) == 3
    assert {point.meta["official_variant"] for point in points} == set(
        MM_SAFETYBENCH_VARIANTS
    )
    assert {point.expected_behavior for point in points} == {"refuse"}
    assert {point.meta["source_cluster_id"] for point in points} == {
        "mmsafety/10-Legal_Opinion/0"
    }
    assert {point.meta["official_evaluator_policy"] for point in points} == {
        "legal_advice_caution"
    }
    assert all(point.source_policy is not None for point in points)
    assert all(
        point.source_policy.intended_metric == "mmsafety_official_attack_rate"
        for point in points
        if point.source_policy is not None
    )
    assert all(point.meta["common_metrics_eligible"] is True for point in points)
    assert all(
        point.meta["judge_reference_text"] == "unsafe phrase" for point in points
    )
    assert all(
        point.meta["judge_reference_kind"]
        == "official_key_phrase_not_sent_to_target"
        for point in points
    )
    assert all(Path(point.media[0].path).is_file() for point in points)


def test_mmsafety_default_rejects_partial_release_before_any_model_call(
    tmp_path: Path,
):
    _write_mm_record_set(
        tmp_path / "data" / "processed_questions" / "01-Illegal_Activitiy.json",
        1,
    )
    with pytest.raises(CorpusFormatError, match="exactly the 13 official"):
        MMSafetyConverter().parse(tmp_path)


def test_mmsafety_pinned_population_emits_5040_policy_bound_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    qdir = tmp_path / "data" / "processed_questions"
    for scenario, count in MM_SAFETYBENCH_SCENARIO_COUNTS.items():
        _write_mm_record_set(qdir / f"{scenario}.json", count)

    # The preceding layout test exercises real asset resolution for all three
    # variants.  This population test avoids creating 5,040 duplicate files while
    # retaining exact manifest counts and converter expansion.
    digest = hashlib.sha256(_JPEG).hexdigest()

    def inline_image(relative: str, _root: Path) -> MediaRef:
        return MediaRef(
            modality="image",
            uri="data:image/jpeg;base64,/9j/",
            mime="image/jpeg",
            sha256=digest,
            meta={"fixture_relative_path": relative},
        )

    monkeypatch.setattr(mmsafety_module, "image", inline_image)
    points = MMSafetyConverter(verify_manifest_hashes=False).parse(tmp_path)

    spec = CORPUS_RELEASE_SPECS["mmsafety"]
    assert spec.expected_source_records == 1680
    assert len(points) == spec.expected_emitted_points == 5040
    assert len({point.id for point in points}) == 5040
    assert all(point.source_policy and len(point.source_policy.sha256) == 64 for point in points)


def test_mossbench_full_official_layout_preserves_every_dimension(tmp_path: Path):
    images = tmp_path / "images"
    images.mkdir()
    table = tmp_path / "information.csv"
    fields = [
        "pid", "question", "image_path", "short description", "description",
        "meta_data_over", "meta_data_human", "meta_data_child",
        "meta_data_syn", "meta_data_ocr", "meta_data_harm",
    ]
    with table.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        over_types = (
            "Exaggerated Risk", "Negated Harm", "Counterintuitive Interpretation"
        )
        for pid in range(1, 301):
            (images / f"{pid}.png").write_bytes(_PNG)
            writer.writerow({
                "pid": pid,
                "question": f"Benign question {pid}?",
                "image_path": f"images/{pid}.png",
                "short description": "benign scene",
                "description": "long benign scene",
                "meta_data_over": over_types[(pid - 1) % 3],
                "meta_data_human": (pid - 1) % 2,
                "meta_data_child": pid % 2,
                "meta_data_syn": 1,
                "meta_data_ocr": 0,
                "meta_data_harm": (pid - 1) % 8,
            })

    points = MOSSBenchConverter(verify_manifest_hash=False).parse(tmp_path)

    assert len(points) == 300
    assert {point.risk_category for point in points} == {RiskCategory.OVER_REFUSAL}
    assert all(point.taxonomy_refs == [] for point in points)
    assert all(point.expected_behavior == "safe_answer" for point in points)
    first = points[0]
    assert first.meta["official_metadata"] == {
        "over": "Exaggerated Risk",
        "human": "0",
        "child": "1",
        "syn": "1",
        "ocr": "0",
        "harm": "0",
    }
    assert first.meta["official_metadata_normalized"]["harm"] == 0
    assert first.meta["official_harm_code_semantics"] == "opaque_source_code_0_to_7"
    assert first.meta["required_metric"] == "mossbench_refusal_rate"
    assert first.meta["official_evaluator_executed"] is False
    assert first.source_policy is not None
    assert first.source_policy.intended_metric == "mossbench_refusal_rate"


def test_converted_identity_is_independent_of_checkout_root(tmp_path: Path):
    digest = hashlib.sha256(_PNG).hexdigest()

    def converted_at(root: Path) -> list[DataPoint]:
        asset = root / "images" / "probe.png"
        asset.parent.mkdir(parents=True)
        asset.write_bytes(_PNG)
        return [DataPoint(
            id="portable",
            source="fixture",
            modalities=["text", "image"],
            dialog_history=[DialogTurn(role="user", content="probe")],
            media=[MediaRef(
                modality="image",
                path=str(asset.resolve()),
                sha256=digest,
                mime="image/png",
            )],
            risk_category=RiskCategory.JAILBREAK,
            expected_behavior="refuse",
        )]

    assert canonical_converted_corpus_sha256(
        converted_at(tmp_path / "checkout-a")
    ) == canonical_converted_corpus_sha256(
        converted_at(tmp_path / "checkout-b")
    )


def test_modality_planner_scopes_coverage_to_the_selected_grid():
    target = _Target(("text", "image"))
    plan = plan_modality_coverage(
        [target], {"strongreject": [_point("text", ["text"])]}
    )
    by_combination = {item.combination: item for item in plan.items}
    assert by_combination[("text",)].status == "planned"
    assert by_combination[("text", "image")].status == "unavailable"
    assert "selected datapoint" in (
        by_combination[("text", "image")].justification or ""
    )


def test_modality_planner_rejects_selected_media_for_text_only_target():
    with pytest.raises(ModalityCoverageError, match=r"text\+image"):
        plan_modality_coverage(
            [_Target(("text",))],
            {"mmsafety": [_point("image", ["text", "image"])]},
        )


def test_modality_planner_requires_real_execution_for_each_combination():
    target = _Target(("text", "image"))
    plan = plan_modality_coverage(
        [target],
        {
            "strongreject": [_point("text", ["text"])],
            "mmsafety": [_point("image", ["text", "image"])],
        },
    )
    assert {item.combination for item in plan.items} == {
        ("text",), ("text", "image"),
    }
    with pytest.raises(ModalityCoverageError, match=r"text\+image"):
        verify_executed_modality_coverage(
            plan, {target.name: {("text", ("text",))}}
        )
    result = verify_executed_modality_coverage(
        plan,
        {target.name: {
            ("text", ("text",)),
            ("image", ("text", "image")),
        }},
    )
    assert {item.status for item in result.items} == {"executed"}


def test_flat_capabilities_never_invent_cross_media_combinations():
    target = _Target(("text", "image", "audio", "video"))
    assert declared_target_combinations(target) == (
        ("text",),
        ("text", "image"),
        ("text", "audio"),
        ("text", "video"),
    )


def test_every_declared_text_image_audio_video_capability_can_be_proven():
    target = _Target(("text", "image", "audio", "video"))
    plan = plan_modality_coverage(
        [target],
        {
            "strongreject": [_point("p-text", ["text"])],
            "mmsafety": [_point("p-image", ["text", "image"])],
            "jalmbench": [_point("p-audio", ["text", "audio"])],
            "videosafetybench": [_point("p-video", ["text", "video"])],
        },
    )
    result = verify_executed_modality_coverage(
        plan,
        {target.name: {
            ("p-text", ("text",)),
            ("p-image", ("text", "image")),
            ("p-audio", ("text", "audio")),
            ("p-video", ("text", "video")),
        }},
    )
    assert {item.combination for item in result.items} == {
        ("text",),
        ("text", "image"),
        ("text", "audio"),
        ("text", "video"),
    }
    assert all(item.status == "executed" for item in result.items)


def test_explicit_unavailable_combination_is_recorded_with_justification():
    target = _Target(
        ("text", "image", "audio"),
        combinations=(("text", "image", "audio"),),
    )
    plan = plan_modality_coverage([target], {})
    assert len(plan.items) == 1
    assert plan.items[0].status == "unavailable"
    assert plan.items[0].justification


def test_modality_planner_rejects_tag_only_physical_datapoints():
    malformed = DataPoint(
        id="tag-only",
        source="fixture",
        modalities=["text", "image"],
        dialog_history=[DialogTurn(role="user", content="probe")],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    with pytest.raises(ModalityCoverageError, match="byte-backed MediaRefs"):
        plan_modality_coverage(
            [_Target(("text", "image"))], {"mmsafety": [malformed]}
        )


def test_modality_planner_rejects_inline_mime_spoofing():
    media = [MediaRef(
        modality="image",
        uri=(
            "data:image/png;base64,"
            + base64.b64encode(_JPEG).decode("ascii")
        ),
        mime="image/png",
        sha256=hashlib.sha256(_JPEG).hexdigest(),
    )]
    malformed = DataPoint(
        id="spoofed-inline",
        source="fixture",
        modalities=["text", "image"],
        dialog_history=[DialogTurn(role="user", content="probe", media=media)],
        media=media,
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    with pytest.raises(ModalityCoverageError, match="MIME/signature mismatch"):
        plan_modality_coverage(
            [_Target(("text", "image"))], {"mmsafety": [malformed]}
        )


def test_modality_planner_revalidates_duplicate_content_with_changed_mime(
    tmp_path: Path,
):
    asset = tmp_path / "probe.png"
    asset.write_bytes(_PNG)
    digest = hashlib.sha256(_PNG).hexdigest()
    valid = MediaRef(
        modality="image", path=str(asset), mime="image/png", sha256=digest,
    )
    spoofed = MediaRef(
        modality="image", path=str(asset), mime="image/gif", sha256=digest,
    )
    malformed = DataPoint(
        id="duplicate-content-changed-mime",
        source="fixture",
        modalities=["text", "image"],
        # The valid top-level reference comes first. The actually replayed dialog
        # reference must still be checked rather than deduplicated by bytes alone.
        media=[valid],
        dialog_history=[DialogTurn(
            role="user", content="probe", media=[spoofed],
        )],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )

    with pytest.raises(ModalityCoverageError, match="MIME/signature mismatch"):
        plan_modality_coverage(
            [_Target(("text", "image"), (("text", "image"),))],
            {"mmsafety": [malformed]},
        )


def test_modality_planner_rehashes_local_media_before_accepting_plan(
    tmp_path: Path,
):
    asset = tmp_path / "probe.png"
    asset.write_bytes(_PNG)
    media = [MediaRef(
        modality="image",
        path=str(asset),
        mime="image/png",
        sha256=hashlib.sha256(_PNG).hexdigest(),
    )]
    point = DataPoint(
        id="changed-local-media",
        source="fixture",
        modalities=["text", "image"],
        dialog_history=[DialogTurn(role="user", content="probe", media=media)],
        media=media,
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    asset.write_bytes(_JPEG)

    with pytest.raises(ModalityCoverageError, match="SHA-256 mismatch"):
        plan_modality_coverage(
            [_Target(("text", "image"))], {"mmsafety": [point]}
        )


def test_modality_planner_rejects_duplicate_ids_before_evidence_can_cross_prove():
    with pytest.raises(ModalityCoverageError, match="duplicate datapoint id 'same'"):
        plan_modality_coverage(
            [_Target(("text", "image"))],
            {
                "strongreject": [_point("same", ["text"])],
                "mmsafety": [_point("same", ["text", "image"])],
            },
        )


def test_bounded_corpus_and_native_readers_reject_oversized_and_symlinked_inputs(
    tmp_path: Path,
):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"12345")
    with pytest.raises(CorpusFormatError, match="parser limit"):
        _read_bounded_bytes(oversized, max_bytes=4)

    target = tmp_path / "artifact.json"
    target.write_bytes(b"{}")
    link = tmp_path / "artifact-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this Windows account cannot create symlinks")
    with pytest.raises(ValueError, match="symbolic link"):
        read_binary_artifact(link, max_bytes=10)


def test_corpus_json_rejects_nonfinite_numbers(tmp_path: Path):
    source = tmp_path / "nonfinite.json"
    source.write_text('{"value": 1e999}', encoding="utf-8")
    with pytest.raises(CorpusFormatError, match="invalid JSON"):
        read_json(source)


def test_sensitive_environment_carriers_are_dropped_and_overrides_require_allowlist(
    monkeypatch: pytest.MonkeyPatch,
):
    carriers = {
        "PGPASSFILE": "db.pass",
        "AWS_PROFILE": "prod",
        "GNUPGHOME": "keyring",
        "SSH_AUTH_SOCK": "agent.sock",
    }
    for name, value in carriers.items():
        monkeypatch.setenv(name, value)
    child = _sanitised_child_env()
    assert not set(carriers).intersection(name.upper() for name in child)
    with pytest.raises(ValueError, match="credential-like"):
        _sanitised_child_env(env_overrides={"PGPASSFILE": "override.pass"})


class _HTTPResponse:
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        self._body = body
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


def test_ollama_transport_uses_configured_timeout_and_preparse_body_bound(
    monkeypatch: pytest.MonkeyPatch,
):
    observed: dict[str, float] = {}

    def oversized_urlopen(_request, *, timeout: float):
        observed["timeout"] = timeout
        return _HTTPResponse(b"{}", str(4 * 1024 * 1024 + 1))

    monkeypatch.setattr("urllib.request.urlopen", oversized_urlopen)
    target = OllamaTarget("fixture", model_digest="0" * 64, timeout=12.5)
    with pytest.raises(LocalTargetOutputError, match="4 MiB"):
        target._verify_daemon_identity()
    assert observed["timeout"] == 12.5


def test_ollama_transport_rejects_duplicate_json_keys(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda _request, *, timeout: _HTTPResponse(
            b'{"models":[],"models":[]}'
        ),
    )
    target = OllamaTarget("fixture", model_digest="0" * 64)
    with pytest.raises(LocalTargetOutputError, match="standards-conforming JSON"):
        target._verify_daemon_identity()


def test_ollama_reverifies_daemon_digest_before_each_generation_boundary(
    monkeypatch: pytest.MonkeyPatch,
):
    expected = "a" * 64
    inventories = iter([
        {"models": [{"model": "fixture", "digest": f"sha256:{expected}"}]},
        {"models": [{"model": "fixture", "digest": "sha256:" + "b" * 64}]},
    ])
    target = OllamaTarget("fixture", model_digest=expected)
    monkeypatch.setattr(
        target, "_bounded_json_request", lambda *_args, **_kwargs: next(inventories)
    )

    assert target._verify_daemon_identity() == expected
    with pytest.raises(LocalTargetOutputError, match="does not match"):
        target._verify_daemon_identity()


def test_ollama_declared_vision_path_embeds_verified_images():
    digest = hashlib.sha256(_PNG).hexdigest()
    media = MediaRef(
        modality="image",
        uri="data:image/png;base64," + base64.b64encode(_PNG).decode("ascii"),
        sha256=digest,
        mime="image/png",
    )
    messages = _dialog_to_ollama_messages(
        [DialogTurn(role="user", content="Describe it", media=[media])],
        multimodal=True,
    )
    assert messages == [{
        "role": "user",
        "content": "Describe it",
        "images": [base64.b64encode(_PNG).decode("ascii")],
    }]
    target = OllamaTarget(
        "vision", model_digest="0" * 64,
        modality_support=("text", "image"),
    )
    target.validate_research_identity()
    assert target.modality_combinations == (("text",), ("text", "image"))


class _AuditedVisionTarget(BaseTarget):
    name = "audited-vision"
    modality_support = ("text", "image")
    modality_combinations = (("text",), ("text", "image"))
    max_transport_attempts_per_call = 3

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        return Response(
            attempt_id="pending",
            target=self.name,
            output_turns=[DialogTurn(role="assistant", content="unsafe output")],
            tokens={"input": 2, "output": 2, "total": 4},
            raw={
                "requested_seed": seed,
                "target_sampling_control": "provider_seed",
                "transport_attempt_count": 2,
                "transport_attempts": [{"outcome": "retry"}, {"outcome": "success"}],
                "resolved_model": "pinned-model",
            },
        )


class _OutputBlockingGuard:
    name = "fixture-guard"

    def judge(self, _datapoint: DataPoint, response: Response) -> Judgment:
        return Judgment(
            attempt_id=response.attempt_id,
            judge=self.name,
            label="violation",
            score=1.0,
        )


def test_guarded_target_preserves_capabilities_and_queried_output_audit():
    target = GuardedTarget(
        _AuditedVisionTarget(), _OutputBlockingGuard(), mode="output"
    )
    assert target.modality_combinations == (("text",), ("text", "image"))
    assert target.max_transport_attempts_per_call == 3

    response = target.generate(
        [DialogTurn(role="user", content="probe")], seed=7
    )

    assert response.raw["stage"] == "output"
    assert response.raw["base_target_queried"] is True
    assert response.raw["transport_attempt_count"] == 2
    assert response.raw["resolved_model"] == "pinned-model"
    assert response.raw["target_sampling_control"] == "provider_seed"
    assert response.tokens == {"input": 2, "output": 2, "total": 4}
    assert "unsafe output" not in (response.output_turns[0].content or "")
