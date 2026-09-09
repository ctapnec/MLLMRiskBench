"""Read saved hosted answers with completed, separately attributed local scoring.

This view supplies judging candidates, never a completed generation grid.
It restores existing records only; no target or classifier is executed.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import stat
import tempfile

from experiments import level1_evidence, run_matrix
from experiments.local_campaign import rr_retained_judging as scoring
from experiments.local_campaign.rr_retained_judging_analysis import _report_views
from experiments.local_campaign.rr_parallel_analysis import _merge_judge_views
from experiments.retained_response_judge_execute import _read_regular, _strict_json, _write_new
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import RunManifest
from ura.project_revision import load_project_revision_file, project_revision_binding
from ura.runner import GlobalCallBudget, Runner, _component_config, _portable_attempt_dump

SCHEMA = "ura-retained-scoring-view/1"
FILE = "retained-scoring-view.json"


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _descriptor(path: Path) -> dict:
    _require(path.is_absolute() and path.resolve(strict=True) == path
             and stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(),
             "scoring view requires canonical regular source files")
    _require(path.stat().st_size <= 64 * 1024 * 1024, "scoring source file exceeds its bound")
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _bound(item: dict):
    _require(isinstance(item, dict) and set(item) == {"path", "sha256", "bytes"},
             "scoring source descriptor fields changed")
    path = Path(item["path"])
    _require(_descriptor(path) == item, "scoring source content changed")
    return _read_regular(path, label="retained scoring source", max_bytes=64 * 1024 * 1024)[0]


class _Source(scoring.RetainedUnit):
    def validate_unchanged(self):
        # An interrupted cell legitimately retains empty judgment exports.
        for item in self.source["files"]:
            _require(_descriptor(Path(item["path"])) == item, "original scoring source changed")


def _restore_nonresponse_prefix(reader, inputs, responses, completed, run_id):
    """Keep typed nonresponse records; never replace an existing answer verdict."""
    restored = {}
    for key, record in completed.items():
        saved = responses.get(key)
        _require(saved is not None and key in inputs
                 and record["response"] == saved["response"]
                 and saved["response"]["raw"].get("model_stability_status") == "failed_output",
                 "separate scoring cannot replace original completed answer judgments")
        restored[key] = reader._restore_record(*inputs[key], record, run_id)
    return restored


def _jsonl_rows(path):
    _descriptor(path)
    return [_strict_json(line, label="retained original judgment export")
            for line in path.read_bytes().splitlines() if line.strip()]


def _source(part: dict, *, project: Path) -> _Source:
    files = part["source"]["files"]
    _require(isinstance(files, list) and len(files) >= 3, "scoring source inventory is incomplete")
    for item in files:
        _require(_descriptor(Path(item["path"])) == item, "original scoring source changed")
    prepared = _bound(files[0])
    program = _bound(files[1])
    _require(prepared.get("status") == "prepared_no_calls" and prepared["program"] == files[1],
             "scoring source lacks its original admitted program")
    paths = [Path(item["path"]) for item in files]
    manifests = [p for p in paths if p.name.endswith(".manifest.json")]
    _require(len(manifests) == 1, "scoring source needs one generation manifest")
    manifest_path = manifests[0]
    root = manifest_path.parent
    manifest = RunManifest.model_validate(_bound(_descriptor(manifest_path)), strict=True)
    revision = scoring._original_identity(manifest, manifest_path, project)
    _require(revision == part["source"]["generation_revision"]
             and manifest.run_id == part["generation_run_id"]
             and manifest.models == [program["target"]], "scoring generation identity changed")
    _require(not list(root.glob("*.complete.json")) and not list(root.glob("*.lock")),
             "separate scoring requires its closed incomplete generation source")
    grid = _bound(_descriptor(scoring._one_file(root, "*.grid.json", label="scoring source grid")))
    eligibility = level1_evidence._plan_artifact(
        scoring._one_file(root, "*.eligibility.json", label="scoring source eligibility"))
    _require(level1_evidence._grid_id(grid) == grid["grid_id"] == manifest.config["run"]["grid_id"]
             and level1_evidence._plan_descriptor_matches(grid["request"]["eligibility_plan"], eligibility),
             "scoring source request or eligibility changed")
    level1_evidence._validate_grid_plan_bindings(grid["request"], eligibility[0])
    level1_evidence._validate_grid_model_acquisition(grid["request"], evidence_root=root)
    jobs = [(job, run_matrix.build_parser().parse_args(job["argv"])) for job in program["jobs"]
            if job["purpose"] == "measured_run"]
    jobs = [(job, args) for job, args in jobs if args.corpora == manifest.config["run"]["corpus"]]
    _require(len(jobs) == 1, "scoring source has ambiguous measured input ownership")
    job, args = jobs[0]
    configs, _ = run_matrix._load_attacker_config(args.attacker_config, ["replay"], args.attacker_config_sha256)
    saved = manifest.config["components"]["attacker"]
    attacker = ReplayAttacker(replay_artifact=configs["replay"]["replay_artifact"],
        replay_artifact_sha256=saved["replay_artifact_sha256"], retained_input_ids=saved["retained_input_ids"])
    _require(_component_config(attacker) == saved, "scoring source input selection changed")
    instances, _ = run_matrix._load_source_config(args.source_config, [args.corpora], args.source_config_sha256)
    _require(instances == grid["request"]["source_instances"], "scoring source instance changed")
    corpus, _ = run_matrix.load_corpus_with_audit(args.corpora, 0, 0, source_instance=instances[args.corpora])
    corpus = attacker.select_corpus(args.corpora, corpus)
    reader = scoring._reader_runner(manifest, scoring.source_cascade(manifest))
    reader.attacker = attacker
    reader.target_answer_retries = 0
    contracts = reader._plan_attacker_input_contracts(corpus)
    corpus, media = reader._prepare_corpus(corpus)
    _require(reader._dataset_hashes(corpus, media) == manifest.dataset_hashes
             and reader._attacker_input_plan_payload(contracts) == manifest.config["attacker_input_plan"],
             "scoring source corpus or original input contracts changed")
    checkpoint = scoring._one_file(root, "*.responses.checkpoint.jsonl", label="saved target responses")
    records = Runner.load_response_checkpoint(checkpoint, expected_run_id=manifest.run_id)
    ledger = _bound(_descriptor(scoring._one_file(root, "*.budget.json", label="original target budget")))
    run_matrix._response_checkpoint_budget_snapshots(root, ledger)
    reader.call_budget = GlobalCallBudget(budget_id=ledger["budget_id"])
    stem = str(checkpoint).removesuffix(".responses.checkpoint.jsonl")
    original_checkpoint = Path(stem + ".checkpoint.jsonl")
    _require(not [p for p in root.glob("*.checkpoint.jsonl")
                  if p not in {checkpoint, original_checkpoint} and p.stat().st_size],
             "separate scoring has an unrelated completed checkpoint")
    completed = Runner.load_checkpoint(original_checkpoint, expected_run_id=manifest.run_id)
    inputs, all_inputs, usable, checked = {}, {}, {}, set()
    for point in corpus:
        for index, proposed in enumerate(attacker.generate(point, AttackBudget(**manifest.config["budget"]))):
            attempt = reader._prepare_attempt(proposed, dp=point, seed=0, logical_turn=index,
                run_id=manifest.run_id, corpus_hash=manifest.dataset_hashes["corpus"], stateful=False,
                input_contract=contracts[(point.id, 0)])
            if attempt.id not in records:
                continue
            record = records[attempt.id]
            _require(_portable_attempt_dump(attempt) == record["attempt"], "saved target input changed")
            response = reader._restore_response(attempt, record, manifest.run_id)
            checked.add(attempt.id)
            all_inputs[attempt.id] = (point, attempt)
            if response.raw.get("model_stability_status") == "failed_output":
                continue
            _require(response.raw.get("target_input_status") != "incompatible"
                     and any((turn.content or "").strip() for turn in response.output_turns),
                     "separate scoring source lacks a retained visible response")
            inputs[attempt.id], usable[attempt.id] = (point, attempt), record
    _require(checked == set(records) and len(usable) == part["pending_judgments"] and usable,
             "scoring source omits or adds a saved response")
    prefix = _restore_nonresponse_prefix(reader, all_inputs, records, completed, manifest.run_id)
    _require(_jsonl_rows(Path(stem + ".jsonl")) == [value[1].model_dump(mode="json") for value in prefix.values()],
             "separate scoring cannot replace original judgment exports")
    with tempfile.TemporaryDirectory(prefix="ura-nonresponse-trail-") as scratch:
        trail_path = Path(scratch).resolve() / "trails.jsonl"
        reader.trails = {key: value[2] for key, value in prefix.items()}
        reader.trail_meta = {key: value[3] for key, value in prefix.items()}
        reader.save_trails(trail_path)
        _require(_jsonl_rows(Path(stem + ".trails.jsonl")) == _jsonl_rows(trail_path),
                 "separate scoring cannot replace original judgment trails")
    reader.call_budget = None  # Original target accounting was validated above.
    source = _Source(manifest, {"result_root": str(root), "selected_records": len(usable)},
                     part["source"], reader, inputs, usable, {})
    source.validate_unchanged()
    return source


def _records(source, path: Path):
    records = Runner.load_checkpoint(path, expected_run_id=source.manifest.run_id)
    _require(set(records) == set(source.responses), "completed scoring omits or adds a retained answer")
    for key, record in records.items():
        _require(record["response"] == source.responses[key]["response"], "scoring changed a retained answer")
        source.runner._restore_record(*source.inputs[key], record, source.manifest.run_id)
    return records


def _judging_revision(receipt: dict, project: Path):
    # This is retained scoring attribution, not the currently imported reader.
    # Recheck both source paths against the exact judging checkout and receipt.
    value, descriptor = load_project_revision_file(
        Path(receipt["path"]), receipt["sha256"], project / "experiments/run_matrix.py",
        recheck_checkout=True, harness_module_path=project / "src/ura/runner.py",
    )
    return project_revision_binding(value, descriptor)


def _load(value: dict):
    _require(set(value) == {"schema", "launch", "result", "judging_repository", "project_revision"}
             and value["schema"] == SCHEMA, "retained scoring view fields changed")
    launch, result = _bound(value["launch"]), _bound(value["result"])
    root = Path(value["launch"]["path"]).parent
    _require(Path(value["result"]["path"]) == root / "result.json"
             and launch.get("kind") == "retained_hosted_prefix_local_judging"
             and result.get("status") == "complete"
             and launch.get("old_grids_promoted") is False and result.get("old_grids_promoted") is False
             and all(item.get(key) == 0 for item in [launch, result] for key in ["target_calls", "hosted_calls"]),
             "scoring view lacks completed no-target scoring provenance")
    project = Path(value["judging_repository"]).resolve(strict=True)
    receipt = value["project_revision"]
    _bound(receipt)
    judging_revision = _judging_revision(receipt, project)
    _require(judging_revision["expected_commit"] == launch["judging_commit"], "scoring code identity changed")
    parts, seen, total = [], set(), 0
    _require(len(launch["sources"]) == len(result["routes"]), "scoring unit inventory changed")
    for part in launch["sources"]:
        route = part["route"]
        outcomes = [item for item in result["routes"] if item["route"] == route]
        _require(route not in seen and len(outcomes) == 1, "scoring unit is duplicate or absent")
        seen.add(route)
        item = outcomes[0]
        checkpoint = Path(item["checkpoint"]["path"])
        _require(checkpoint.parent == root and _descriptor(checkpoint) == item["checkpoint"],
                 "completed scoring checkpoint changed")
        source = _source(part, project=project)
        records = _records(source, checkpoint)
        _require(len(records) == item["new_judgments"], "scoring unit count changed")
        # The existing strict lossless join accepts separate scoring provenance.
        # The result remains a generation foreign key, never a promoted grid.
        joined = _report_views(source, records, {
            "schema": SCHEMA, "launch": value["launch"], "invocation": value["result"],
            "checkpoint": item["checkpoint"], "judging_revision": judging_revision,
        }, joined=True, completion_path=Path(value["result"]["path"]))
        _predictors, metadata, judgments, audit = joined["joined"]
        parts.append(([joined["input_cell"]], metadata, judgments, audit))
        total += len(records)
        source.validate_unchanged()
    _require(total == result["new_local_judgments"] == launch["usable_responses"], "scoring total changed")
    return _merge_judge_views(parts)


def create_view(*, scoring_root: Path, judging_repository: Path, project_revision: Path,
                project_revision_sha256: str, out: Path):
    _require(not out.exists() and out.is_absolute() and out.parent.resolve(strict=True) / out.name == out,
             "scoring view needs a fresh canonical directory")
    value = {"schema": SCHEMA, "launch": _descriptor(scoring_root / "launch.json"),
             "result": _descriptor(scoring_root / "result.json"),
             "judging_repository": str(judging_repository.resolve(strict=True)),
             "project_revision": _descriptor(project_revision)}
    _require(value["project_revision"]["sha256"] == project_revision_sha256, "scoring revision digest changed")
    view = _load(value)
    out.mkdir()
    _write_new(out / FILE, value)
    return view


def read_view(root: Path):
    return _load(_read_regular(root / FILE, label="retained scoring view", max_bytes=1024 * 1024)[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("scoring-root", "judging-repository", "project-revision", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    args = parser.parse_args(argv)
    create_view(**vars(args))
    print(args.out / FILE)


if __name__ == "__main__":
    main()
