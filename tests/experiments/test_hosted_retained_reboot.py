import json
import shutil
import stat

import pytest

from experiments import hosted_retained_execute as subject
from experiments.hosted_retained_inputs import _descriptor
from experiments.local_campaign import continuation_stats, execution_accounting, rr_parallel_analysis
from experiments import retained_artifact_reader


def test_retained_input_copy_survives_device_renumbering(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    source.write_text('{}\n')
    view_root = tmp_path / "view"
    view_root.mkdir()
    copied = view_root / "copy.json"
    shutil.copyfile(source, copied)
    copied.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    original, observed = source.stat(), copied.stat()
    row = {"source": _descriptor(source), "view": _descriptor(copied),
           "source_file_identity": {"device": original.st_dev + 16, "inode": original.st_ino},
           "view_file_identity": {"device": observed.st_dev + 16, "inode": observed.st_ino},
           "relative_path": "copy.json", "independent_copy": True,
           "source_view_samefile": False, "view_link_count": 1,
           "view_mode": stat.S_IMODE(observed.st_mode)}
    view = {"schema": "ura-phase7-human-audit-sampling-view/9", "status": "complete",
            "view_root": str(view_root), "source_files_modified": False,
            "permitted_view_outputs": [], "file_inventory": [row],
            "file_inventory_sha256": subject._sha([row]),
            "regular_files_copied": 1, "logical_bytes": observed.st_size}

    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return _descriptor(path)

    view_ref = save("view-receipt.json", view)
    index_ref = save("index.json", {"view_receipt": view_ref})
    accounting = {"generated_from": {"human_audit_runner_input_view": view_ref,
                                     "human_audit_sampling_index": index_ref}}
    accounting_ref = save("accounting.json", accounting)
    monkeypatch.setattr(continuation_stats, "retained_continuation_reports", lambda *a: [
        ("terminal_inventory", "inventory", {}), ("execution_accounting", "accounting", accounting_ref)])
    monkeypatch.setattr(retained_artifact_reader, "load_cells", lambda *a: [{"run_id": "historical"}])
    monkeypatch.setattr(execution_accounting, "build_execution_accounting", lambda *a, **kw: accounting)
    monkeypatch.setattr(rr_parallel_analysis, "load_judge_view", lambda *a: ([{"run_id": "rr"}], {}))
    program = {"results_root": str(tmp_path), "sources": {"historical_result": {}},
               "runner_view": str(view_root), "rr_analysis_root": str(tmp_path / "rr")}
    assert len(subject._load_local_cells(program)[0]) == 2

    # Renumbering is accepted, but replacement of a retained file is not.
    row["view_file_identity"]["inode"] += 1
    view["file_inventory_sha256"] = subject._sha([row])
    view_ref = save("view-receipt.json", view)
    accounting["generated_from"]["human_audit_runner_input_view"] = view_ref
    accounting["generated_from"]["human_audit_sampling_index"] = save("index.json", {"view_receipt": view_ref})
    accounting_ref.update(save("accounting.json", accounting))
    with pytest.raises(ValueError, match="copy identity changed"):
        subject._load_local_cells(program)
