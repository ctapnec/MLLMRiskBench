"""Level-2 exporter contracts: exact keys, no pooling, native separation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from experiments import level2_report
from experiments import live_attestation as live_attestation_cli
from experiments.native_import import CONFIG_SCHEMA, main as native_main
from ura.data_models import DialogTurn, Response
from ura.targets.base import BaseTarget


_LOCAL_REVISION = "a" * 40
_REQUESTED_SPEC = "vllm:fixture/local-model"
_RESOLVED_TARGET = f"{_REQUESTED_SPEC}@{_LOCAL_REVISION}"


class _StableLocalTarget(BaseTarget):
    name = _RESOLVED_TARGET
    modality_support = ("text",)
    max_transport_attempts_per_call = 0

    def generate(self, dialog, *, seed=None):
        return Response(
            attempt_id="target-placeholder",
            target=self.name,
            output_turns=[
                DialogTurn(role="assistant", content="I cannot help."),
            ],
            raw={
                "sampling_control": "seeded",
                "resolved_model": "fixture/local-model",
                "model_revision": _LOCAL_REVISION,
            },
        )


def _finite_budget_args() -> list[str]:
    return [
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000",
        "--deadline-seconds", "3600",
    ]


def _measured_cohort(
    tmp_path: Path,
    monkeypatch,
    project_revision_args,
    name: str,
    extra_args: list[str] | None = None,
) -> Path:
    local_config_path = tmp_path / "local-targets.json"
    if not local_config_path.exists():
        local_config_path.write_text(json.dumps({_REQUESTED_SPEC: {
            "revision": _LOCAL_REVISION,
            "modalities": ["text"],
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.5,
            "max_tokens": 64,
        }}), encoding="utf-8")
    monkeypatch.setattr(
        run_matrix, "build_target", lambda *_a, **_kw: _StableLocalTarget()
    )
    common = [
        "--local", _REQUESTED_SPEC,
        "--local-config", str(local_config_path),
        "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1",
        "--max-queries", "1", "--max-turns", "1",
        *_finite_budget_args(),
        *project_revision_args,
    ]
    receipt_path = tmp_path / "live-attestation.json"
    if not receipt_path.exists():
        probe_root = tmp_path / "probe"
        assert run_matrix.main([
            *common,
            "--attestation-probe", "--execution-scope-id", "level2-test-scope",
            "--out", str(probe_root),
        ]) == 0
        assert live_attestation_cli.main([
            "--probe-root", str(probe_root),
            "--execution-scope-id", "level2-test-scope",
            "--out", str(receipt_path),
        ]) == 0
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    root = tmp_path / name
    assert run_matrix.main([
        *common,
        *(extra_args or []),
        "--execution-scope-id", "level2-test-scope",
        "--live-attestation", str(receipt_path),
        "--live-attestation-sha256", receipt_sha256,
        "--live-attestation-max-age-hours", "1",
        "--out", str(root),
    ]) == 0
    return root


def _out_args(directory: Path) -> list[str]:
    return [
        "--out-json", str(directory / "l2.json"),
        "--out-csv", str(directory / "l2.csv"),
        "--out-md", str(directory / "l2.md"),
    ]


def test_exports_deterministic_compatible_tables(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    root = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-a"
    )
    out = tmp_path / "out"
    assert level2_report.main(["--results", str(root), *_out_args(out)]) == 0

    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "ura-level2-report/1"
    assert report["empirical_validity_established"] is False
    assert report["pooling_policy"]["universal_safety_score_defined"] is False
    rows = report["common"]["estimates"]
    assert rows
    for row in rows:
        assert row["run_id"]
        assert row["ordered_judges"] == ["rules"]
        assert row["resolved_model"] == _RESOLVED_TARGET
        assert row["source_policy_id"]
        assert row["cross_stratum_pooling_permitted"] is False
        assert row["polarity"] in {
            "higher_adverse", "higher_favorable", "source_defined",
        }
        assert row["judgments_completed"] >= row["judgments_decided"]
        assert (
            row["judgments_decided"]
            + row["judgments_abstained"]
            + row["judgments_non_evaluable"]
            == row["judgments_completed"]
        )
    header = (out / "l2.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",")[:4] == [
        "run_id", "corpus_arm", "model_spec", "resolved_model",
    ]
    assert "Level-2 compatible-family tables" in (
        out / "l2.md"
    ).read_text(encoding="utf-8")

    # A second export from identical inputs is byte-identical.
    out2 = tmp_path / "out2"
    assert level2_report.main(["--results", str(root), *_out_args(out2)]) == 0
    for stem in ("l2.json", "l2.csv", "l2.md"):
        assert (out / stem).read_bytes() == (out2 / stem).read_bytes()


def test_distinct_conditions_never_merge(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    root_a = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-a"
    )
    root_b = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-b",
        extra_args=["--sample-seed", "1"],
    )
    out_a = tmp_path / "out-a"
    out_b = tmp_path / "out-b"
    out_ab = tmp_path / "out-ab"
    assert level2_report.main(["--results", str(root_a), *_out_args(out_a)]) == 0
    assert level2_report.main(["--results", str(root_b), *_out_args(out_b)]) == 0
    assert level2_report.main([
        "--results", str(root_a), "--results", str(root_b), *_out_args(out_ab),
    ]) == 0
    rows_a = json.loads((out_a / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    rows_b = json.loads((out_b / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    rows_ab = json.loads((out_ab / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    # Different run conditions stay distinct rows even when their group
    # buckets coincide; nothing merges and nothing is dropped.
    assert len(rows_ab) == len(rows_a) + len(rows_b)
    assert {row["run_id"] for row in rows_ab} == (
        {row["run_id"] for row in rows_a} | {row["run_id"] for row in rows_b}
    )

    # The same completed run supplied twice fails closed as a duplicate.
    out_dup = tmp_path / "out-dup"
    assert level2_report.main([
        "--results", str(root_a), "--results", str(root_a),
        *_out_args(out_dup),
    ]) == 1
    assert not (out_dup / "l2.json").exists()


def test_dry_run_cohort_is_rejected(tmp_path: Path) -> None:
    dry = tmp_path / "dry"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1", "--seeds", "0",
        "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(dry),
    ]) == 0
    out = tmp_path / "rejected"
    assert level2_report.main(["--results", str(dry), *_out_args(out)]) == 1
    assert not (out / "l2.json").exists()
    assert not (out / "l2.csv").exists()


def _easyjailbreak_envelope(tmp_path: Path) -> Path:
    rows = [
        {
            "jailbreak_prompt": "Encoded instruction: {query}",
            "query": "harmful objective",
            "target_responses": ["native target output"],
            "eval_results": [1],
        },
        {
            "jailbreak_prompt": "Nested scenario: {query}",
            "query": "second objective",
            "target_responses": ["native refusal"],
            "eval_results": [False],
        },
    ]
    results = tmp_path / "attack_results.jsonl"
    results.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    config = tmp_path / "import.json"
    config.write_text(json.dumps({
        "schema_version": CONFIG_SCHEMA,
        "engine": "easyjailbreak",
        "adapter": {
            "recipe": "ReNeLLM",
            "attack_model": "provider/attacker",
            "target_model": "provider/target",
            "eval_model": "provider/evaluator",
        },
        "import": {
            "result_jsonl": results.name,
            "upstream_revision": "a" * 40,
            "expected_records": 2,
        },
    }), encoding="utf-8")
    envelope = tmp_path / "native-envelope.json"
    assert native_main(["--config", str(config), "--out", str(envelope)]) == 0
    return envelope


def test_native_runs_stay_on_their_own_scales(tmp_path: Path) -> None:
    envelope = _easyjailbreak_envelope(tmp_path)
    out = tmp_path / "native-out"
    assert level2_report.main(["--native", str(envelope), *_out_args(out)]) == 0
    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    assert report["common"]["estimates"] == []
    native = report["native"]
    assert native["n_native_runs"] == 1
    assert native["runs"][0]["native_scale_pooling_permitted"] is False
    # Native evidence never enters the common estimate table.
    csv_text = (out / "l2.csv").read_text(encoding="utf-8")
    assert csv_text.count("\n") == 1
    assert "easyjailbreak" not in csv_text
    markdown = (out / "l2.md").read_text(encoding="utf-8")
    assert "Source-native evidence" in markdown
    assert "easyjailbreak" in markdown


def test_outputs_are_create_only(tmp_path: Path) -> None:
    envelope = _easyjailbreak_envelope(tmp_path)
    out = tmp_path / "existing"
    out.mkdir()
    (out / "l2.csv").write_text("occupied", encoding="utf-8")
    assert level2_report.main(["--native", str(envelope), *_out_args(out)]) == 1
    assert (out / "l2.csv").read_text(encoding="utf-8") == "occupied"
    assert not (out / "l2.json").exists()
    assert not (out / "l2.md").exists()


def test_survival_and_refinement_rows_export_distinctly(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    # Live crescendo cells emit kaplan_meier_survival rows whose group_by
    # carries a survival_turn refinement key; each refined row must export as
    # its own line instead of failing the grouping check or merging.
    root = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-crescendo",
        extra_args=["--attackers", "crescendo", "--max-turns", "2",
                    "--max-queries", "2"],
    )
    out = tmp_path / "out-crescendo"
    assert level2_report.main(["--results", str(root), *_out_args(out)]) == 0
    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    rows = report["common"]["estimates"]
    survival = [r for r in rows if r["metric"] == "kaplan_meier_survival"]
    assert survival, [r["metric"] for r in rows]
    refinements = {r["group_refinements"] for r in survival}
    assert all(ref for ref in refinements)
    assert len(refinements) == len(survival)
    for row in survival:
        assert "survival_turn" in row["group_refinements"]
        assert row["execution_modes"] == ["direct_prompt"]


def test_coarser_grouping_fails_closed() -> None:
    from experiments.level2_report import _estimate_rows

    cell = {
        "run_id": "run-x",
        "model": "model-A",
        "manifest": {"config": {"run": {
            "corpus": "synth", "model_spec": "model-A", "defense": "none",
        }}, "judges": ["rules"], "seeds": [0]},
        "judgments": [],
        "aggregate_results": [{
            "metric": "ASR", "value": 1.0, "n": 1,
            "group_by": {"model": "model-A"},
            "provenance": {},
        }],
    }
    with pytest.raises(ValueError, match="safe default aggregation"):
        _estimate_rows(cell)


def test_markdown_cells_escape_pipes() -> None:
    from experiments.level2_report import _md_cell

    assert _md_cell("a|b") == r"a\|b"
    assert _md_cell("a\nb") == "a b"
    assert _md_cell("back\\slash|x") == r"back\\slash\|x"


def test_attestation_probe_roots_are_rejected_everywhere(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    import experiments.suite_summary as suite_summary
    from experiments.figure_results import _load_cells
    from experiments.human_audit import _validated_artifacts

    _measured_cohort(tmp_path, monkeypatch, project_revision_args, "measured-a")
    probe_root = tmp_path / "probe"
    assert probe_root.is_dir()

    out = tmp_path / "probe-rejected"
    assert level2_report.main(["--results", str(probe_root), *_out_args(out)]) == 1
    assert not (out / "l2.json").exists()
    assert suite_summary.main([
        "--results", str(probe_root), "--out", str(tmp_path / "suite.json"),
    ]) == 1
    with pytest.raises(ValueError, match="probe is not measured"):
        _load_cells(probe_root)
    with pytest.raises(ValueError, match="probe is not measured"):
        _validated_artifacts(probe_root)
