from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

import pytest

from experiments import rig_check, run_matrix
from ura.eligibility import canonical_json_sha256
from ura.project_revision import (
    project_revision_binding,
    validate_project_revision,
)
from ura.runner import _harness_source_identity


@dataclass(frozen=True)
class ProjectRevisionTestArgs:
    values: tuple[str, ...]
    binding: dict[str, Any]

    def __iter__(self) -> Iterator[str]:
        return iter(self.values)


def _fake_project_revision_receipt() -> dict[str, Any]:
    driver_digest = run_matrix._source_tree_digest(
        Path(run_matrix.__file__).resolve()
    )[0]
    assert isinstance(driver_digest, str)
    body: dict[str, Any] = {
        "schema": "ura-project-revision/1",
        "status": "complete",
        "purpose": "immutable_clean_project_source_receipt",
        "repository": {
            "expected_commit": "e" * 40,
            "observed_commit": "e" * 40,
            "head_tree": "f" * 40,
            "clean": True,
            "root_relationship": (
                "experiments_driver_and_src_ura_share_one_git_toplevel"
            ),
        },
        "source": {
            "harness_source": _harness_source_identity(),
            "driver_source": {
                "module": "run_matrix.py",
                "sha256": driver_digest,
                "file_count": 1,
            },
        },
        "limitations": {
            "empirical_evidence_established": False,
            "remote_repository_authenticity_established": False,
            "dependency_environment_bound": False,
            "upstream_project_revisions_bound": False,
            "source_archive_included": False,
            "interpretation": (
                "local clean-checkout and executed-source identity only; dependency, "
                "upstream-runtime, remote-authenticity, and empirical claims require "
                "separate evidence"
            ),
        },
    }
    body["revision_id"] = "project-revision-" + canonical_json_sha256(body)[:24]
    return validate_project_revision(body)


@pytest.fixture
def approved_local_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Install explicit assessed metadata for tests of later local-run gates."""
    registry = tmp_path / "profiles.json"
    evidence = tmp_path / "profile-readiness.json"
    evidence.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("URA_LOCAL_MODEL_PROFILE_REGISTRY", str(registry))

    def install(spec: str, config: dict[str, Any]) -> None:
        identity = "revision" if "revision" in config else "digest"
        profiles = json.loads(registry.read_text()) if registry.exists() else {
            "schema": "ura-local-model-execution-profiles/3", "models": {},
        }
        profiles["models"][spec] = {
                "identity": {identity: config[identity].lower()},
                "modalities": config["modalities"],
                "generation_tokens": config.get("max_tokens", 4096),
                "request_timeout_seconds": 120.0,
                "local_execution": ({
                    "max_model_len": -1,
                    "tensor_parallel_size": config.get("tensor_parallel_size", 1),
                    "gpu_memory_utilization": config.get("gpu_memory_utilization", 0.9),
                } if spec.startswith("vllm:") else {"num_ctx": "fit", "think": False}),
                "readiness": {"path": str(evidence), "sha256": "a" * 64,
                              "readiness_id": "b" * 64},
        }
        registry.write_text(json.dumps(profiles), encoding="utf-8")

    return install


@pytest.fixture
def project_revision_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> ProjectRevisionTestArgs:
    """Explicit fake receipt for tests of later gates; RUN-009 tests use real temp Git."""

    receipt = _fake_project_revision_receipt()
    payload = (json.dumps(
        receipt, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False,
    ) + "\n").encode("utf-8")
    path = tmp_path / f"{receipt['revision_id']}.project-revision.json"
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor = {
        "file": path.name,
        "sha256": digest,
        "bytes": len(payload),
        "revision_id": receipt["revision_id"],
    }

    def load(candidate: Path, expected: str, *_args: Any, **_kwargs: Any):
        candidate = Path(candidate)
        assert candidate.read_bytes() == payload
        assert expected == digest
        return receipt, dict(descriptor)

    def recheck(value: object, *_args: Any, **_kwargs: Any):
        assert validate_project_revision(value) == receipt
        return receipt

    monkeypatch.setattr(run_matrix, "load_project_revision_file", load)
    monkeypatch.setattr(run_matrix, "recheck_project_revision", recheck)
    monkeypatch.setattr(rig_check, "load_project_revision_file", load)
    binding = project_revision_binding(receipt, descriptor)
    return ProjectRevisionTestArgs(
        values=(
            "--project-revision", str(path),
            "--project-revision-sha256", digest,
        ),
        binding=binding,
    )
