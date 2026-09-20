"""Runtime presentation must not bypass the catalog or change stored states."""
# Pytest resolves these imported fixtures by the parameter names below.
# ruff: noqa: F811

import html
from urllib.parse import urlsplit

import pytest

from experiments.rig_web_app import display_labels, i18n, ui
from experiments.rig_web_app.artifacts import Job
from test_operator_operations import app  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from test_builder_native_judging import native, complete_preparation  # noqa: F401
from test_builder_collection import study  # noqa: F401


def saved_job(app, command="run_matrix", state="failed"):
    directory = app.state_dir / "catalog-job"
    directory.mkdir(exist_ok=True)
    job = Job(
        job_id="catalog-job",
        command=command,
        argv=["--out", str(directory / "analysis")] if command == "response_svm" else [],
        directory=directory,
        process=None,
        restored_state=state,
        restored_exit=1,
    )
    app.jobs[job.job_id] = job
    assert app.db.record_terminal(job, "a" * 40, [], state=state, exit_code=1)
    return job


@pytest.mark.parametrize(
    "surface",
    [
        "jobs",
        "detail",
        "runs",
        "standalone",
        "activity",
        "assessment",
        "analysis",
        "human",
    ],
)
def test_failed_job_labels_use_catalog_on_each_surface(app, monkeypatch, surface):
    sentinel = "Failure label <&>"
    monkeypatch.setitem(display_labels.LABELS, "failed", sentinel)
    command = {"assessment": "campaign_assess", "analysis": "response_svm"}.get(
        surface, "run_matrix"
    )
    job = saved_job(app, command)
    owner = app.db.create_workspace("State test", "local")
    if surface in {"activity", "assessment", "analysis"}:
        app.db.attach_workspace_member(owner, "job", job.job_id, "analysis")
    if surface == "runs":
        body = app._runs_card()
    else:
        route = {
            "jobs": "/jobs?view=all",
            "detail": "/jobs/catalog-job",
            "standalone": "/stats?view=standalone",
            "activity": "/campaigns/" + owner + "?section=activity",
            "assessment": "/assessment?campaign_id=" + owner,
            "analysis": "/analysis?campaign_id=" + owner,
        }.get(surface)
        if surface == "human":
            key = app._human_store().save_preparation(
                owner,
                job.job_id,
                dict(
                    name="Pending review",
                    mode="common",
                    prepared=str(app.results_root / "sample.csv"),
                    metadata=dict(review_kind="personal"),
                ),
            )
            route = "/human-evaluation/preparations/" + key
        status, _, raw = app.handle("GET", route)
        assert status == 200, raw.decode().partition("<main>")[2][:1500]
        body = raw.decode()
        if surface == "jobs":
            start = body.index("href='/jobs/catalog-job'")
            body = body[body.rfind("<tr", 0, start) : body.find("</tr>", start)]
            assert "data-state='failed'" in body
    assert html.escape(sentinel) in body
    assert app.db.load_job(job.job_id)["state"] == "failed"
    assert job.state() == "failed"


def test_dashboard_indeterminate_job_uses_catalog(app, monkeypatch):
    monkeypatch.setitem(display_labels.LABELS, "orphaned", "Detached <&>")
    saved_job(app, state="orphaned")
    status, _, body = app.handle("GET", "/")
    assert status == 200 and b"Detached &lt;&amp;&gt;" in body


@pytest.mark.parametrize(
    "state", ["stopped", "starting", "external", "owned", "ambiguous", "busy", "error", "unknown"]
)
def test_service_labels_do_not_change_ownership_actions(app, monkeypatch, state):
    key = "absent" if state == "stopped" else state
    assert key in display_labels.LABELS
    monkeypatch.setitem(display_labels.LABELS, key, "Service <&>")
    body = app._ollama_service_card(dict(state=state), dict(models=[]), action_state=state)
    assert "Service &lt;&amp;&gt;" in body
    assert "action='/ollama/start'" in body
    assert "type='submit' disabled" in body  # Non-owned stop/pull remain disabled.


@pytest.mark.parametrize(
    "command,argv,key",
    [
        ("run_matrix", ["--preflight-only"], "pages.preflight_work"),
        ("harmbench_capture", [], "pages.preparation_work"),
    ],
)
def test_single_word_work_descriptions_are_catalog_messages(app, monkeypatch, command, argv, key):
    messages = dict(i18n.catalog())
    assert key in messages
    messages[key] = "Work label <&>"
    monkeypatch.setattr(i18n, "catalog", lambda: messages)
    job = saved_job(app, command)
    job.argv = argv
    assert app._job_work_label(job) == "Work label <&>"


def test_native_judging_selector_translates_only_its_display(native, monkeypatch):
    from experiments.rig_web_app import builder_native_judging

    app, _, _, _ = native
    params = complete_preparation(native, failed=True)
    monkeypatch.setitem(display_labels.LABELS, "failed", "Preparation <&>")
    body = builder_native_judging.native_judging_panel(app, params)
    assert "Preparation &lt;&amp;&gt;" in body
    assert "value='" + params["retained_native_judging_job"] + "'" in body
    assert app.db.load_job(params["retained_native_judging_job"])["state"] == "failed"


@pytest.mark.parametrize("width", [390, 1440])
def test_jobs_filter_uses_raw_state_despite_translated_visible_labels(
    app, browser, monkeypatch, width
):
    sentinel = 'Failure <strong>literal</strong> & "'
    monkeypatch.setitem(display_labels.LABELS, "failed", sentinel)
    saved_job(app)
    page = browser.new_page(viewport=dict(width=width, height=1000))
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(item):
        path = urlsplit(item.request.url)
        if path.path == "/static/style.css":
            return item.fulfill(status=200, content_type="text/css", body=ui._STYLE)
        status, mime, body = app.handle("GET", path.path + ("?" + path.query if path.query else ""))
        item.fulfill(status=status, content_type=mime, body=body)

    page.route("http://states.test/**", route)
    try:
        page.goto("http://states.test/jobs?view=all")
        page.get_by_role("tab", name="History", exact=True).click()
        row = page.locator("tr[data-state=failed]")
        assert row.locator(".badge").inner_text() == sentinel
        chip = page.locator("button.chip[data-state=failed]")
        assert chip.inner_text().startswith(sentinel)
        assert chip.locator("strong").count() == 0
        chip.click()
        assert row.is_visible()
        page.locator("button.chip[data-state='']").click()
        assert row.is_visible()
        assert not errors
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
    finally:
        page.close()
