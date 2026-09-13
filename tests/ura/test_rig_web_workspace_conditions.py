"""Historical and corrected settings remain explicit across every result view."""
import csv
import io
import json
from pathlib import Path
from urllib.parse import quote
import xml.etree.ElementTree as ET

import pytest

from experiments.rig_web import RigWebApp


@pytest.fixture
def app(tmp_path):
    app = RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state", repo_root=tmp_path,
        gpu_hardware={}, system_hardware={})
    yield app
    app.close()


def publish(app, owner, key, *, model="local-model", condition="initial", outcome="usable",
            truncated=False, context=65536, allowance=4096, pending=False):
    assignment = dict(assignment_id=key, model=model, input_id="same-input", condition_id=condition,
        modality="text", framework="replay", corpus="corpus", response_id=None if pending else key,
        evidence_class="measured")
    response = dict(response_id=key, assignment_id=key, condition_id=condition, outcome=outcome,
        truncated=truncated, source_ref=f"{key}.responses.jsonl:1", context_tokens=context,
        output_allowance=allowance, input_tokens=100, output_tokens=200)
    judgment = dict(response_id=key, judge_id="haiku", status="valid", label="safe", source_ref=f"{key}.judge.jsonl:1")
    app.db.publish_workspace_results(owner, assignments=[assignment], responses=[] if pending else [response],
        judgments=[] if pending else [judgment])


def test_condition_filters_reconcile_totals_rows_and_judgments_without_hiding_history(app):
    owner = app.db.create_workspace("Local", "local")
    publish(app, owner, "old", outcome="missing", allowance=512)
    publish(app, owner, "new", condition="corrected")
    publish(app, owner, "waiting", condition="corrected", pending=True)
    publish(app, owner, "other", model="other-model", condition="corrected")
    rows = app.db.workspace_model_totals(owner, model="local-model", condition="corrected")
    assert len(rows) == 1
    assert (rows[0]["assigned"], rows[0]["usable"], rows[0]["pending"], rows[0]["missing"]) == (2, 1, 1, 0)
    assert {r["assignment_id"] for r in app.db.workspace_result_rows(owner, model="local-model", condition="corrected")} == {"new", "waiting"}
    assert app.db.workspace_judging_totals(owner, model="local-model", condition="corrected")[0]["count"] == 1
    assert app.db.workspace_model_totals(owner, model="local-model")[0]["missing"] == 1
    assert len(app.db._query("SELECT * FROM campaign_responses")) == 3


def test_scope_tracks_the_explicitly_selected_response_condition_not_assignment_creation(app):
    owner = app.db.create_workspace("Local", "local")
    publish(app, owner, "old", outcome="missing")
    app.db.publish_workspace_results(owner, assignments=[], judgments=[], responses=[dict(
        response_id="replacement", assignment_id="old", condition_id="corrected", outcome="usable",
        truncated=False, source_ref="new.responses.jsonl:1", output_allowance=8192)])
    assert app.db.workspace_model_totals(owner, model="local-model", condition="corrected") == []
    old = dict(app.db.workspace_result_rows(owner)[0])
    old["response_id"] = "replacement"
    app.db.publish_workspace_results(owner, assignments=[old], responses=[], judgments=[])
    assert app.db.workspace_model_totals(owner, model="local-model", condition="initial") == []
    assert app.db.workspace_model_totals(owner, model="local-model", condition="corrected")[0]["usable"] == 1
    assert app.db.workspace_result_conditions(owner, model="local-model")[0]["condition_id"] == "corrected"
    assert app.db.workspace_judging_totals(owner, model="local-model", condition="corrected") == []


def test_condition_labels_show_reported_ranges_native_maximum_and_unknown_settings(app):
    owner = app.db.create_workspace("Local", "local")
    publish(app, owner, "a", condition="fitted", context=32768)
    publish(app, owner, "b", condition="fitted", context=65536)
    publish(app, owner, "c", condition="fitted", pending=True)
    publish(app, owner, "d", condition="native", allowance=-1, context=None)
    body = app.handle("GET", f"/campaigns/{owner}?model=local-model")[2].decode()
    assert "context 32,768 to 65,536 (partly unknown)" in body
    assert "output 4,096 (partly unknown)" in body
    assert "context unknown; output native maximum" in body
    assert "All retained conditions (includes history)" in body
    assert "Choose model" in body and "View condition" in body


def test_results_keep_full_identities_in_details_without_widening_summary_columns(app):
    owner = app.db.create_workspace("API", "api")
    model = "provider:example;max_tokens=8192"
    identity = "ab" * 32
    app.db.publish_workspace_results(owner, assignments=[dict(assignment_id="long-id", model=model,
        input_id=identity, condition_id="condition", modality="image", framework="replay",
        corpus="corpus", response_id=None, evidence_class="measured")], responses=[], judgments=[])
    page = app._workspace_results(owner, "results", {})
    assert "class='campaign-output-table'" in page
    assert "<td>provider:example</td>" in page
    assert "<span title='" + identity + "'>abababababab...</span>" in page
    assert "Exact model: " + model in page and "Input identity: " + identity in page
    from experiments.rig_web_app.ui import _STYLE
    assert ".campaign-output-table table { table-layout:fixed;" in _STYLE
    assert ".campaign-output-table th, .campaign-output-table td { overflow-wrap:anywhere; }" in _STYLE


def test_filters_persist_in_tabs_output_pagination_and_matching_exports(app):
    owner = app.db.create_workspace("Local", "local")
    condition = "corrected / & 8192"
    for index in range(52):
        publish(app, owner, f"new-{index:02}", condition=condition, allowance=8192)
    publish(app, owner, "historical", condition="old", outcome="missing", allowance=512)
    query = "model=local-model&condition=" + quote(condition, safe="")
    escaped = query.replace("&", "&amp;")
    body = app.handle("GET", f"/campaigns/{owner}?{query}")[2].decode()
    assert f"?section=judging&amp;{escaped}" in body
    assert f"/figures/model-counts.csv?page=0&amp;{escaped}" in body
    assert "n=52" in body and "Missing: 0/52 terminal outcomes" in body
    rows = app.handle("GET", f"/campaigns/{owner}?section=results&{query}")[2].decode()
    assert f"?section=results&amp;{escaped}&amp;page=1" in rows
    assert "historical.responses.jsonl" not in rows
    status, _, body = app.handle("GET", f"/campaigns/{owner}/figures/model-counts.csv?{query}")
    assert status == 200
    data = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
    assert len(data) == 1 and data[0]["assigned"] == "52" and data[0]["missing"] == "0"
    assert data[0]["condition_filter"] == condition
    for figure in ("coverage.svg", "quality.svg"):
        status, _, body = app.handle("GET", f"/campaigns/{owner}/figures/{figure}?{query}")
        assert status == 200
        svg = ET.fromstring(body)
        metadata = svg.find("{http://www.w3.org/2000/svg}metadata")
        assert json.loads(metadata.text) == dict(model_filter="local-model", condition_filter=condition)
        assert "Selected execution condition" in body.decode()


def test_unknown_filters_do_not_fall_back_to_unfiltered_counts_or_sql(app):
    owner = app.db.create_workspace("Local", "local")
    publish(app, owner, "r")
    malicious = "' OR 1=1 -- <script>"
    assert app.db.workspace_model_totals(owner, model=malicious) == []
    assert app.db.workspace_result_rows(owner, model="local-model", condition=malicious) == []
    assert app.db.workspace_judging_totals(owner, model="local-model", condition=malicious) == []
    query = "model=local-model&condition=" + quote(malicious, safe="")
    body = app.handle("GET", f"/campaigns/{owner}?{query}")[2].decode()
    assert "Unknown execution condition" in body and "No indexed overview rows for this selection" in body
    assert "<script>\"" not in body and "&lt;script&gt;" in body
    assert app.handle("GET", f"/campaigns/{owner}/figures/coverage.svg?{query}")[0] == 404
    assert app.handle("GET", f"/campaigns/{owner}?condition=initial")[0] == 400


def test_filtered_reads_do_not_reopen_response_artifacts(app, monkeypatch):
    owner = app.db.create_workspace("Local", "local")
    publish(app, owner, "r")
    def forbidden(*args, **kwargs):
        raise AssertionError("Result filters must use the existing SQLite index")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    for suffix in ("?section=overview", "?section=results", "?section=judging", "/figures/coverage.svg?"):
        joiner = "" if suffix.endswith("?") else "&"
        status, _, _ = app.handle("GET", f"/campaigns/{owner}{suffix}{joiner}model=local-model&condition=initial")
        assert status == 200
