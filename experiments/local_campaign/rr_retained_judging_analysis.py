"""Read separately completed RR scoring without inventing a completed old grid."""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from experiments import retained_artifact_reader as retained
from experiments.local_campaign import rr_retained_judging as recovery
from experiments.local_campaign.vllm_stability_phase6 import (
    _descriptor, _load_json, _validate_descriptor,
)
from ura.runner import Runner


def _completed_view(path: Path, *, work: Path, project: Path) -> dict:
    """Called inside the actual scoring-source checkout; never performs inference."""
    completion = _load_json(path, label="RR scoring completion")
    launch_path = _validate_descriptor(completion["launch"], label="RR scoring launch")
    launch, source = recovery.load_launch(
        launch_path, completion["launch"]["sha256"], work=work, project=project,
    )
    root = Path(launch["data_root"])
    checkpoint = _validate_descriptor(completion["checkpoint"], label="RR new judgments")
    invocation_path = _validate_descriptor(completion["invocation"], label="RR scoring invocation")
    invocation = _load_json(invocation_path, label="RR scoring invocation")
    if (path != root / "completion.json" or checkpoint != root / "judgments.checkpoint.jsonl"
            or completion.get("schema") != recovery.COMPLETION_SCHEMA
            or completion.get("generation_run_id") != source.manifest.run_id
            or completion.get("judging_revision") != launch["judging_revision"]
            or completion.get("target_calls") != 0 or completion.get("hosted_calls") != 0
            or completion.get("old_grid_promoted") is not False
            or invocation_path.parent.parent != work / "runs/engineering"
            or invocation_path.name != "invocation.json"
            or invocation.get("launch") != completion["launch"]
            or invocation.get("generation_run_id") != source.manifest.run_id):
        raise ValueError("RR scoring completion changed its execution or generation identity")
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source.manifest.run_id)
    counts = {"retained_responses": len(source.responses), "total_judgments": len(source.responses),
              "existing_judgments": len(source.judgments), "new_judgments": len(source.pending_ids)}
    if (set(saved) != set(source.pending_ids)
            or any(type(completion.get(key)) is not int or completion[key] != count
                   for key, count in counts.items())):
        raise ValueError("RR scoring completion omits or repeats retained response judgments")
    # Exact restore validates every original/new input, Response and judge trail.
    # No missing checkpoint entry can fall through to the classifier.
    runner = recovery._reader_runner(source.manifest, recovery.source_cascade(source.manifest))
    records = {**source.judgments, **saved}
    for key, (point, attempt) in source.inputs.items():
        if records[key]["response"] != source.responses[key]["response"]:
            raise ValueError("RR scoring analysis changed a retained target response")
        runner._restore_record(point, attempt, records[key], source.manifest.run_id)
    source.validate_unchanged()
    _validate_descriptor(completion["checkpoint"], label="RR restored judgments")
    return {
        "source_completion": _descriptor(path, label="RR scoring completion"),
        "launch": launch, "generation_manifest": source.manifest.model_dump(mode="json"),
        "records": {key: records[key] for key in source.inputs},
        "judging_strata": {
            "original_generation_judging": list(source.judgments),
            "separately_recovered_judging": source.pending_ids,
        },
        "counts": counts, "target_calls": 0, "judge_calls": 0, "old_grid_promoted": False,
    }


_WORKER = '''
import json, sys
from pathlib import Path
from experiments.local_campaign import rr_retained_judging as recovery
from experiments.local_campaign.vllm_stability_phase6 import _descriptor, _load_json, _validate_descriptor
from ura.runner import Runner
request = json.load(sys.stdin)
exec(request["reader_source"], globals())
result = _completed_view(Path(request["completion"]), work=Path(request["work"]), project=Path.cwd())
print(json.dumps(result, allow_nan=False))
'''


def load_completed(path: Path, *, work: Path, project: Path) -> dict:
    """Run the strict record reader against the actual retained scoring source."""
    path = path.resolve(strict=True)
    bound = _descriptor(path, label="RR scoring completion")
    completion = _load_json(path, label="RR scoring completion")
    revision = completion["judging_revision"]
    commit = revision["expected_commit"]
    if (revision["observed_commit"] != commit
            or retained._git(project, "rev-parse", f"{commit}^{{tree}}") != revision["head_tree"]):
        raise ValueError("RR scoring analysis source identity changed")
    retained._git(project, "merge-base", "--is-ancestor", commit,
                  retained._git(project, "rev-parse", "HEAD"))
    with tempfile.TemporaryDirectory(prefix="ura-rr-scoring-reader-") as scratch:
        checkout = Path(scratch).resolve() / "source"
        installed = False
        try:
            retained._git(project, "worktree", "add", "--quiet", "--detach", str(checkout), commit)
            installed = True
            env = dict(os.environ, PYTHONPATH=str(checkout / "src"), PYTHONDONTWRITEBYTECODE="1")
            for key in list(env):
                if key.endswith(("_API_KEY", "_TOKEN")):
                    env.pop(key)
            request = {"completion": str(path), "work": str(work),
                       "reader_source": inspect.getsource(_completed_view)}
            process = subprocess.run(
                [sys.executable, "-c", _WORKER], cwd=checkout, env=env,
                input=json.dumps(request), capture_output=True, text=True,
                encoding="utf-8", timeout=600, check=False,
            )
            if process.returncode:
                raise ValueError("RR scoring exact-source reader failed: " + process.stderr[-4000:])
            view = retained._decode_validator_ipc(process.stdout)
            if (view.get("source_completion") != bound
                    or view.get("launch", {}).get("judging_revision") != revision):
                raise ValueError("RR scoring reader changed its completion/source binding")
            _validate_descriptor(bound, label="RR scoring completion after read")
            return view
        finally:
            if installed:
                retained._git(project, "worktree", "remove", str(checkout))
