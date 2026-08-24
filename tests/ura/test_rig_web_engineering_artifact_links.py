"""Generic retained-artifact links for external engineering campaigns."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.campaigns import load_engineering_campaign


_SCHEMA = "ura-engineering-campaign-artifact-links/1"
_ERROR = "Engineering artifact-link descriptor is invalid."


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _campaign(tmp_path: Path, campaign_id: str = "linked-campaign") -> tuple[Path, Path]:
    results = tmp_path / "runs"
    root = results / "engineering" / campaign_id
    root.mkdir(parents=True)
    _write_json(
        root / "ENGINEERING_ONLY.json",
        {
            "schema": "ura-engineering-campaign/1",
            "campaign_id": campaign_id,
            "release_commit": "1" * 40,
            "evidence_class": "engineering_test",
            "thesis_empirical_evidence": False,
            "hosted_calls_allowed": False,
            "hard_stop_hours": 1,
            "started_at": "2026-08-24T12:00:00Z",
            "planned_tasks": ["inspect"],
        },
    )
    events = (
        {
            "at": "2026-08-24T12:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
            "detail": "started",
        },
        {
            "at": "2026-08-24T12:00:01Z",
            "event": "campaign_end",
            "task": "bootstrap",
            "status": "passed",
            "detail": "complete",
        },
    )
    (root / "task-log.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )
    return results, root


def _links(campaign_id: str) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "campaign_id": campaign_id,
        "links": [
            {
                "label": "Control files",
                "path": "retained/control",
                "kind": "directory",
                "required": True,
            },
            {
                "label": "Summary file",
                "path": "retained/summary.json",
                "kind": "file",
                "required": True,
            },
            {
                "label": "Future output",
                "path": "retained/future",
                "kind": "directory",
                "required": False,
            },
        ],
    }


def _retained_targets(results: Path) -> None:
    (results / "retained" / "control").mkdir(parents=True)
    _write_json(results / "retained" / "summary.json", {"complete": True})


def _load(results: Path, root: Path):
    campaign = load_engineering_campaign(results, root.name)
    assert campaign is not None
    return campaign


def test_generic_artifact_links_render_and_optional_target_appears_when_published(
    tmp_path: Path,
) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    _write_json(root / "artifact-links.json", _links(root.name))
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        gpu_hardware={},
        system_hardware={},
    )
    try:
        status, _content_type, body = app.handle("GET", f"/jobs/campaign/{root.name}")
        assert status == 200
        page = body.decode("utf-8")
        assert "Related retained artifacts" in page
        assert "/artifacts?path=engineering/linked-campaign/artifact-links.json" in page
        assert "/artifacts?path=retained/control" in page
        assert "/artifacts?path=retained/summary.json" in page
        assert "Future output" not in page
        assert app.handle("GET", "/artifacts?path=retained/control")[0] == 200
        assert app.handle("GET", "/artifacts?path=retained/summary.json")[0] == 200

        (results / "retained" / "future").mkdir()
        published = app.handle("GET", f"/jobs/campaign/{root.name}")[2].decode(
            "utf-8"
        )
        assert "Future output" in published
        assert "/artifacts?path=retained/future" in published
        assert app.handle("GET", "/artifacts?path=retained/future")[0] == 200
    finally:
        app.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_schema",
        "campaign_mismatch",
        "top_level_extra",
        "link_extra",
        "duplicate_label",
        "duplicate_path",
        "absolute_path",
        "parent_path",
        "dot_path",
        "empty_parts_path",
        "control_path",
        "repeated_separator",
        "backslash_path",
        "colon_path",
        "bad_label",
        "bad_kind",
        "bad_required_type",
        "missing_required",
        "kind_mismatch",
    ),
)
def test_generic_artifact_links_reject_tampered_contracts(
    tmp_path: Path,
    mutation: str,
) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    value = _links(root.name)
    if mutation == "wrong_schema":
        value["schema"] = "wrong"
    elif mutation == "campaign_mismatch":
        value["campaign_id"] = "another-campaign"
    elif mutation == "top_level_extra":
        value["extra"] = True
    elif mutation == "link_extra":
        value["links"][0]["extra"] = True
    elif mutation == "duplicate_label":
        value["links"][1]["label"] = value["links"][0]["label"]
    elif mutation == "duplicate_path":
        value["links"][1]["path"] = value["links"][0]["path"]
    elif mutation == "absolute_path":
        value["links"][0]["path"] = "/retained/control"
    elif mutation == "parent_path":
        value["links"][0]["path"] = "../outside"
    elif mutation == "dot_path":
        value["links"][0]["path"] = "retained/./control"
    elif mutation == "empty_parts_path":
        value["links"][0]["path"] = "."
    elif mutation == "control_path":
        value["links"][0]["path"] = "retained/\x00control"
    elif mutation == "repeated_separator":
        value["links"][0]["path"] = "retained//control"
    elif mutation == "backslash_path":
        value["links"][0]["path"] = "retained\\control"
    elif mutation == "colon_path":
        value["links"][0]["path"] = "C:/outside"
    elif mutation == "bad_label":
        value["links"][0]["label"] = "<script>"
    elif mutation == "bad_kind":
        value["links"][0]["kind"] = "socket"
    elif mutation == "bad_required_type":
        value["links"][0]["required"] = 1
    elif mutation == "missing_required":
        value["links"][0]["path"] = "retained/missing"
    else:
        assert mutation == "kind_mismatch"
        value["links"][0]["kind"] = "file"
    _write_json(root / "artifact-links.json", value)

    campaign = _load(results, root)
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR


@pytest.mark.parametrize("path_value", (".", "retained/\x00control"))
def test_invalid_artifact_link_paths_do_not_break_dashboard_jobs_or_detail(
    tmp_path: Path,
    path_value: str,
) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    value = _links(root.name)
    value["links"][0]["path"] = path_value
    _write_json(root / "artifact-links.json", value)
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        gpu_hardware={},
        system_hardware={},
    )
    try:
        for route in ("/", "/jobs", f"/jobs/campaign/{root.name}"):
            status, _content_type, body = app.handle("GET", route)
            assert status == 200
            assert body.startswith(b"<!doctype html>")
        detail = app.handle("GET", f"/jobs/campaign/{root.name}")[2]
        assert root.name.encode("utf-8") in detail
        assert _ERROR.encode("utf-8") in detail
    finally:
        app.close()


def test_generic_artifact_links_require_a_single_link_descriptor(tmp_path: Path) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    descriptor = root / "artifact-links.json"
    _write_json(descriptor, _links(root.name))
    os.link(descriptor, tmp_path / "descriptor-hardlink.json")

    campaign = _load(results, root)
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR


@pytest.mark.parametrize("marker_identity", (None, "another-campaign", 7))
def test_generic_artifact_links_require_exact_marker_campaign_identity(
    tmp_path: Path,
    marker_identity: object,
) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    _write_json(root / "artifact-links.json", _links(root.name))
    marker_path = root / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    if marker_identity is None:
        del marker["campaign_id"]
    else:
        marker["campaign_id"] = marker_identity
    _write_json(marker_path, marker)

    campaign = _load(results, root)
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR


@pytest.mark.skipif(os.name == "nt", reason="open-file replacement is POSIX-only")
def test_generic_artifact_links_reject_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    results, root = _campaign(tmp_path)
    _retained_targets(results)
    descriptor = root / "artifact-links.json"
    _write_json(descriptor, _links(root.name))
    replacement = root / "replacement.json"
    replacement.write_bytes(descriptor.read_bytes())
    real_read = campaigns_module.os.read
    replaced = False

    def replace_after_read(fd: int, count: int) -> bytes:
        nonlocal replaced
        payload = real_read(fd, count)
        if not replaced:
            replaced = True
            os.replace(replacement, descriptor)
        return payload

    monkeypatch.setattr(campaigns_module.os, "read", replace_after_read)
    campaign = _load(results, root)
    assert replaced
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR


@pytest.mark.skipif(os.name == "nt", reason="directory symlinks are POSIX-only")
@pytest.mark.parametrize("outside", (False, True))
def test_generic_artifact_links_reject_intermediate_aliases(
    tmp_path: Path,
    outside: bool,
) -> None:
    results, root = _campaign(tmp_path)
    target = (tmp_path / "outside") if outside else (results / "actual")
    (target / "control").mkdir(parents=True)
    (results / "retained").symlink_to(target, target_is_directory=True)
    value = _links(root.name)
    value["links"] = [value["links"][0]]
    _write_json(root / "artifact-links.json", value)

    campaign = _load(results, root)
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR


@pytest.mark.skipif(os.name == "nt", reason="file symlinks are POSIX-only")
def test_generic_artifact_links_reject_descriptor_symlink(tmp_path: Path) -> None:
    results, root = _campaign(tmp_path)
    _retained_targets(results)
    target = tmp_path / "real-descriptor.json"
    _write_json(target, _links(root.name))
    (root / "artifact-links.json").symlink_to(target)

    campaign = _load(results, root)
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == _ERROR
