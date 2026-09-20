"""Display labels remain text, including in dynamically assembled headings."""

import ast
import html
import re
from pathlib import Path

import pytest

from experiments.rig_web_app import display_labels, ui
from test_operator_operations import app  # noqa: F401
from test_human_review_ui import prepared

# Imported pytest fixtures deliberately share names with test parameters.
# ruff: noqa: F811


def unescaped_html_labels(source):
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    findings = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_ui_label"
        ):
            continue
        expression = node
        while isinstance(
            parents.get(expression), (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.IfExp)
        ):
            expression = parents[expression]
        literals = [
            n.value
            for n in ast.walk(expression)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        if any(re.search(r"</?[A-Za-z][^>]*>", text) for text in literals):
            findings.append(node.lineno)
    return findings


def test_display_labels_are_escaped_at_direct_html_boundaries():
    root = Path(ui.__file__).parent
    findings = {
        p.name: unescaped_html_labels(p.read_text(encoding="utf-8")) for p in root.glob("*.py")
    }
    assert not {name: lines for name, lines in findings.items() if lines}


def test_boundary_audit_detects_markup_but_allows_plain_data_and_later_escaping():
    assert unescaped_html_labels("body = '<h2>' + _ui_label(key) + '</h2>'")
    assert unescaped_html_labels('body = f"<th>{_ui_label(key)}</th>"')
    assert not unescaped_html_labels("body = '<h2>' + html.escape(_ui_label(key)) + '</h2>'")
    assert not unescaped_html_labels(
        "label = _ui_label(key); body = '<h2>' + html.escape(label) + '</h2>'"
    )
    assert not unescaped_html_labels("rows = [(_ui_label(key), count)]")


@pytest.mark.parametrize(
    "section", ["overview", "definition", "results", "judging", "compare", "costs", "activity"]
)
def test_campaign_navigation_escapes_labels_without_changing_routes(app, monkeypatch, section):
    owner = app.db.create_workspace("Catalog boundaries", "local")
    sentinel = 'Section <em>literal</em> & "'
    monkeypatch.setitem(display_labels.LABELS, section, sentinel)
    status, _, raw = app.handle("GET", "/campaigns/" + owner + "?section=" + section)
    body = raw.decode()
    assert status == 200
    assert html.escape(sentinel) in body and sentinel not in body
    assert "?section=" + section in body
    assert app.db.workspace(owner)["name"] == "Catalog boundaries"


def test_campaign_index_heading_is_text_not_markup(app, monkeypatch):
    sentinel = "Workspaces <em>literal</em> &"
    monkeypatch.setitem(display_labels.LABELS, "campaigns", sentinel)
    status, _, raw = app.handle("GET", "/campaigns")
    body = raw.decode()
    assert status == 200 and html.escape(sentinel) in body and sentinel not in body


@pytest.mark.parametrize("key", ["common", "label", "outputs"])
def test_review_mode_qualifications_and_progress_escape_labels(app, monkeypatch, key):
    owner = app.db.create_workspace("Review boundaries", "local")
    sample = app.results_root / "review-boundaries.csv"
    prepared(sample)
    store = app._human_store()
    study = store.create(
        campaign=owner,
        name="Synthetic boundary test",
        prepared=sample,
        mode="common",
        metadata=dict(
            ethics="test fixture",
            consent="synthetic consent",
            compensation="test terms",
            stop_contact="test operator",
            results=str(app.results_root),
        ),
    )
    sentinel = "Review <em>literal</em> &"
    monkeypatch.setitem(display_labels.LABELS, key, sentinel)
    route = (
        "/human-evaluation?campaign_id=" + owner
        if key == "common"
        else "/human-evaluation/" + study
    )
    status, _, raw = app.handle("GET", route)
    body = raw.decode()
    assert status == 200 and html.escape(sentinel) in body and sentinel not in body
    assert store.study(study)["mode"] == "common"
    assert store.summary(study)["counts"]["submitted"] == 0
