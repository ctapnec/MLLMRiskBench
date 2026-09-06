"""Original counter readers consume real receipt layout, not a grid binding."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from experiments.local_campaign import rr_parallel_analysis as analysis


def test_original_counter_reader_flattens_the_validated_receipt(
    tmp_path, monkeypatch, project_revision_args,
):
    args = list(project_revision_args)
    receipt_path = Path(args[args.index("--project-revision") + 1])
    receipt = json.loads(receipt_path.read_text())
    assert "harness_source_sha256" not in receipt["repository"]
    assert "harness_source" in receipt["source"]
    launch = {"expected_commit": "e" * 40,
              "project_revision": analysis._descriptor(receipt_path)}
    git_calls = []

    def git(project, *arguments):
        git_calls.append(arguments)
        if arguments == ("rev-parse", "HEAD"):
            return "e" * 40
        if arguments == ("rev-parse", "e" * 40 + "^{tree}"):
            return "f" * 40
        assert arguments[0] in {"merge-base", "worktree"}
        return ""

    def execute(command, *, input, **kwargs):
        assert command[-1] == analysis._COVERAGE_WORKER
        request = json.loads(input)
        assert request["launch"] == launch
        assert request["revision"] == project_revision_args.binding
        assert request["commit"] == "e" * 40
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "validator_commit": "e" * 40, "coverage": {"retained_inputs": 515},
        }))

    monkeypatch.setattr(analysis.retained, "_git", git)
    monkeypatch.setattr(analysis.subprocess, "run", execute)
    assert analysis._execution_source_coverage(launch, project=tmp_path) == {"retained_inputs": 515}
    assert any(args[:2] == ("merge-base", "--is-ancestor") for args in git_calls)
    assert git_calls[-1][:3] == ("worktree", "remove", "--force")
