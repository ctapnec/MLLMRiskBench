"""Figure counts, denominators and exported tables must agree."""
import csv
import io
import xml.etree.ElementTree as ET

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.workspace_charts import coverage_html, coverage_svg, quality_svg, model_counts_csv


def row(**changes):
    return dict(model="provider:example", evidence_class="measured", conditions=1,
                assigned=10, usable=4, policy=1, missing=2, retry_pending=1, pending=2,
                truncated=3, truncation_unknown=1, updated_at=1234, **changes)


def test_coverage_svg_sums_to_one_hundred_percent_without_adding_truncation():
    root = ET.fromstring(coverage_svg([row()], title="Coverage", scope="Matched selection"))
    segments = [node for node in root.iter() if node.get("data-category")]
    assert sum(int(node.get("data-count")) for node in segments) == 10
    assert sum(float(node.get("width")) for node in segments) == pytest.approx(700)
    assert not any(node.get("data-category") == "truncated" for node in segments)
    assert "n=10" in "".join(root.itertext())


def test_unknown_truncation_and_retry_pending_are_not_counted_as_nontruncated():
    figure = quality_svg([row()], scope="Matched selection")
    ET.fromstring(figure)
    assert "Missing: 2/7 (28.6%)" in figure
    assert "Truncated: 3/6 (50.0%)" in figure
    page = coverage_html([row()])
    assert "Missing: 2/7 terminal outcomes" in page
    assert "Truncated: 3/6 known flags" in page


def test_csv_uses_same_counts_and_keeps_exact_labels():
    data = row()
    data["model"] = "=not-a-spreadsheet-formula"
    exported = list(csv.DictReader(io.StringIO(model_counts_csv([data]).decode("utf-8-sig"))))
    assert exported[0]["model"] == "'=not-a-spreadsheet-formula"
    assert exported[0]["assigned"] == "10"
    assert exported[0]["truncated"] == "3"


def test_chart_refuses_inconsistent_counts_instead_of_drawing_invented_percentages():
    data = {**row(), "assigned": 9}
    with pytest.raises(ValueError, match="reconcile"):
        coverage_svg([data], title="Coverage", scope="Test")


def test_zero_terminal_denominator_is_unknown():
    data = {**row(), "assigned": 3, "usable": 0, "policy": 0, "missing": 0,
            "retry_pending": 1, "pending": 2, "truncated": 0, "truncation_unknown": 0}
    assert "Truncated: unknown" in quality_svg([data], scope="Test")
    assert "Truncation rate: unknown" in coverage_html([data])


def test_responsive_labels_stay_outside_scaled_geometry_and_escape_html():
    data = {**row(), "model": "provider:<unsafe>" + "x" * 300}
    page = coverage_html([data])
    assert "<unsafe>" not in page
    assert "&lt;unsafe&gt;" in page
    assert "<figcaption" in page and "overflow-wrap:anywhere" in page
    assert "preserveAspectRatio='none'" in page
    assert "<text" not in page  # labels remain full-size HTML on narrow screens


def test_vector_and_table_exports_share_the_same_index_page(tmp_path):
    app = RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state", repo_root=tmp_path)
    try:
        owner = app.db.create_workspace("API", "api")
        app.db.publish_workspace_results(owner,
            assignments=[dict(assignment_id="a", input_id="i", model="api", condition_id="c",
                              framework="replay", corpus="synth", modality="text", response_id=None, evidence_class="measured")],
            responses=[], judgments=[])
        status, mime, body = app.handle("GET", f"/campaigns/{owner}/figures/coverage.svg")
        assert status == 200 and mime.startswith("image/svg+xml")
        ET.fromstring(body)
        assert b"n=1" in body and b"page 1" in body
        assert app.handle("GET", f"/campaigns/{owner}/figures/quality.svg")[0] == 200
        status, mime, body = app.handle("GET", f"/campaigns/{owner}/figures/model-counts.csv")
        assert status == 200 and mime.startswith("text/csv")
        assert list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))[0]["assigned"] == "1"
        assert app.handle("GET", f"/campaigns/{owner}/figures/coverage.svg?page=1")[0] == 404
        assert app.handle("GET", f"/campaigns/{owner}/figures/missing.svg")[0] == 404
    finally:
        app.close()
