"""Focused contracts for the large-page tabbed information architecture."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

from experiments.rig_web import Job, RigWebApp
from experiments.rig_web_app.ui import _BUILDER_SCRIPT, _PAGE_TABS_SCRIPT


class _StructureParser(HTMLParser):
    """Track IDs and the nearest tab-panel/form ancestors in source DOM."""

    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, str | None, str | None]] = []
        self.ids: Counter[str] = Counter()
        self.context: dict[str, tuple[str | None, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        parent_panel = next((item[1] for item in reversed(self.stack) if item[1]), None)
        parent_form = next((item[2] for item in reversed(self.stack) if item[2]), None)
        node_id = values.get("id")
        if node_id:
            self.ids[node_id] += 1
            self.context[node_id] = (parent_panel, parent_form)
        panel = values.get("data-page-panel") or parent_panel
        form = (values.get("id") if tag == "form" else None) or parent_form
        if tag not in self._VOID:
            self.stack.append((tag, panel, form))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


def _app(tmp_path: Path) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir()
    return RigWebApp(results_root=results, state_dir=tmp_path / "state")


def _opening_tag(document: str, marker: str) -> str:
    marker_at = document.index(marker)
    start = document.rfind("<", 0, marker_at)
    return document[start : document.index(">", marker_at) + 1]


def test_shared_page_tabs_are_accessible_and_progressive(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        dashboard = app.handle("GET", "/")[2].decode("utf-8")
        style = app.handle("GET", "/static/style.css")[2].decode("utf-8")
    finally:
        app.close()

    assert "role='tablist' aria-orientation='horizontal'" in dashboard
    assert "role='tab'" in dashboard
    assert "role='tabpanel'" in dashboard
    assert "aria-controls='dashboard-system'" in dashboard
    assert "aria-labelledby='dashboard-system-tab'" in dashboard
    assert 'event.key==="ArrowRight"' in dashboard
    assert 'event.key==="ArrowLeft"' in dashboard
    assert 'event.key==="Home"' in dashboard and 'event.key==="End"' in dashboard
    assert "window.sessionStorage.setItem" in dashboard
    assert "window.location.hash.slice(1)" in dashboard
    assert "target.closest(\"[data-page-panel]\")" in dashboard

    # The server never hides a panel. Without JavaScript the tab bar stays out
    # of the way and the complete document remains readable in source order.
    panel_tags = re.findall(r"<section[^>]+data-page-panel='[^']+'[^>]*>", dashboard)
    assert panel_tags and all(" hidden" not in tag for tag in panel_tags)
    assert ".page-tablist { display:none; }" in style
    assert ".page-tabs.tabs-ready .page-tablist { display:flex" in style
    assert ".page-tabpanel[hidden] { display:none; }" in style


def test_dashboard_and_build_sections_have_sensible_boundaries(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        dashboard = app.handle("GET", "/")[2].decode("utf-8")
        builder = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    system_at = dashboard.index("data-page-panel='dashboard-system'")
    campaigns_at = dashboard.index("data-page-panel='dashboard-campaigns'")
    governance_at = dashboard.index("data-page-panel='dashboard-governance'")
    system = dashboard[system_at:campaigns_at]
    campaigns = dashboard[campaigns_at:governance_at]
    governance = dashboard[governance_at:]
    assert "Rig hardware" in system and "Console database" in system
    assert "Campaign pipeline" in campaigns and "Campaign bindings" in campaigns
    assert "Provider budgets" in governance
    assert "Campaign sampling policy" not in governance and "Boundaries" in governance

    general_at = builder.index("data-page-panel='build-general'")
    builder_form_at = builder.index("<form method='post' action='/build' id='builder'>")
    pipeline_at = builder.index("data-page-panel='build-pipeline'")
    evaluation_at = builder.index("data-page-panel='build-evaluation'")
    admission_at = builder.index("data-page-panel='build-admission'")
    execution_at = builder.index("data-page-panel='build-execution'")
    modal_at = builder.index("id='model-picker'")
    builder_form_end = builder.index("</form>", modal_at)
    assert general_at < builder_form_at < pipeline_at < evaluation_at
    assert evaluation_at < admission_at < execution_at < modal_at < builder_form_end
    assert "Local hardware" in builder[general_at:builder_form_at]
    assert "Local Ollama service" in builder[general_at:builder_form_at]
    assert "Mode" in builder[pipeline_at:evaluation_at]
    assert "Arms &amp; corpora" in builder[pipeline_at:evaluation_at]
    assert "Isolated framework runtimes" in builder[pipeline_at:evaluation_at]
    assert "name='engine_runtime_config'" in builder[pipeline_at:evaluation_at]
    assert "name='engine_runtime_config_sha'" in builder[pipeline_at:evaluation_at]
    assert "each framework must have its own virtual environment" in (
        builder[pipeline_at:evaluation_at].lower()
    )
    assert "completion is published only after the closing seal verifies" in (
        builder[pipeline_at:evaluation_at].lower()
    )
    assert "Judges &amp; defense" in builder[evaluation_at:admission_at]
    assert "Receipts (fail-closed admission)" in builder[admission_at:execution_at]
    assert "Sampling &amp; turns" in builder[execution_at:modal_at]
    assert "Compose &amp; review" in builder[execution_at:modal_at]
    assert builder.count("id='buildpreview'") == 1
    # Ollama owns independent controls; the campaign form itself remains one
    # non-nested form, and the modal has no hidden tab-panel ancestor.
    assert builder[builder_form_at:builder_form_end].count("<form") == 1
    assert "</section>" in builder[execution_at:modal_at]


def test_rig_web_core_does_not_embed_local_campaign_policy(tmp_path: Path) -> None:
    """Local evidence-collection policy belongs outside generic Rig Web core."""

    app = _app(tmp_path)
    app._budgets = lambda: []
    try:
        dashboard = app.handle("GET", "/")[2].decode("utf-8")
        builder = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    repo_root = Path(__file__).parents[2]
    core_root = repo_root / "experiments" / "rig_web_app"
    boundary_files = [
        *sorted(core_root.glob("*.py")),
        repo_root / "experiments" / "rig_web.py",
        repo_root / "experiments" / "rig" / "budgets.example.json",
    ]
    core_text = "\n".join(
        path.read_text(encoding="utf-8") for path in boundary_files
    )
    forbidden = (
        "LOCAL_CAMPAIGN_PLAN",
        "100 clusters per core arm",
        "50 per extended arm",
        "sample seed 0",
        "Current local tiers",
        "Current paid-API tier",
        "thesis ledger",
        "ledger 11.22",
        "runbook section 5.2",
        "_PROVIDER_BUDGETS",
        "focal Fable target",
        "metered Haiku judge",
        "ura-phase6-campaign-terminal-inventory",
        "65-row",
        "output_policy_amendment",
        "followon_prepared",
        "gate5_failed",
        "target_runtime_terminal",
    )
    for term in forbidden:
        assert term.casefold() not in core_text.casefold()
        assert term.casefold() not in dashboard.casefold()

    budget_example = json.loads(boundary_files[-1].read_text(encoding="utf-8"))
    assert budget_example == {"providers": []}
    assert "No provider budgets are configured" in dashboard

    # The generic controls remain available and are not assigned a fixed
    # campaign tier or seed by the server-rendered form.
    assert "name='limit'" in builder
    assert "name='sample_seed'" in builder
    assert "name='sampling_policy'" in builder
    assert "name='cap_target'" in builder and "--max-total-target-calls" in builder
    assert "name='cap_judge'" in builder and "--max-total-judge-calls" in builder
    assert "name='cap_http'" in builder and "--max-total-http-attempts" in builder
    assert "name='deadline'" in builder and "--deadline-seconds" in builder


def test_tab_dom_has_unique_ids_safe_form_ownership_and_no_disabled_state(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        pages = (
            app.handle("GET", "/")[2].decode("utf-8"),
            app.handle("GET", "/build")[2].decode("utf-8"),
            app.handle("GET", "/jobs")[2].decode("utf-8"),
            app.handle("GET", "/stats")[2].decode("utf-8"),
        )
    finally:
        app.close()

    for page in pages:
        parser = _StructureParser()
        parser.feed(page)
        assert {node_id: count for node_id, count in parser.ids.items() if count != 1} == {}

    builder = pages[1]
    parser = _StructureParser()
    parser.feed(builder)
    # The campaign form spans its four panels. The independent Ollama forms
    # live in General; the picker modal remains in the campaign form but has no
    # hidden tab-panel ancestor, so either target/judge opener can display it.
    assert parser.context["builder"] == (None, None)
    assert parser.context["ollama-service"] == ("build-general", None)
    assert parser.context["model-picker"] == (None, "builder")
    for field in ("name='mode'", "name='corpora'", "name='judge_model'"):
        assert " disabled" not in _opening_tag(builder, field)
    # The synchronized per-arm sampling fields are the one intentional dynamic
    # disabled state: they become visible/enabled only after an arm is selected.
    assert " disabled" in _opening_tag(builder, "name='limit'")
    assert "syncSampleSizeControl" in _BUILDER_SCRIPT

    # Tab switching changes only panel visibility. It never disables controls
    # or marks them inert, so values in inactive builder sections still submit.
    assert "panel.hidden=" in _PAGE_TABS_SCRIPT
    assert "disabled" not in _PAGE_TABS_SCRIPT
    assert "inert" not in _PAGE_TABS_SCRIPT


def test_general_pipeline_summary_covers_every_builder_section_and_refreshes(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    summary_ids = (
        "build-summary-composition",
        "build-summary-evaluation",
        "build-summary-admission",
        "build-summary-trajectory",
        "build-summary-budget",
        "build-summary-local",
        "build-summary-output",
    )
    for summary_id in summary_ids:
        assert page.count(f"id='{summary_id}'") == 1
        assert f"setBuildSummary('{summary_id}'" in _BUILDER_SCRIPT

    for field in (
        "judge_model",
        "approximate_common_metrics",
        "defense",
        "defense_guard",
        "guardrail_model",
        "defense_guardrail_model",
        "project_revision",
        "source_conformance",
        "scope",
        "max_age",
        "limit",
        "sample_seed",
        "sampling_policy",
        "seeds",
        "max_queries",
        "max_turns",
        "cap_target",
        "cap_judge",
        "cap_http",
        "local_budget_hours",
        "deadline",
        "dtype",
        "quantization",
        "out",
    ):
        assert f"'{field}'" in _BUILDER_SCRIPT
    assert "form.querySelectorAll('.attrow')" in _BUILDER_SCRIPT
    assert "data-target-selected='true'" in _BUILDER_SCRIPT
    assert "form.addEventListener('change',refresh)" in _BUILDER_SCRIPT
    assert "form.addEventListener('input',refresh)" in _BUILDER_SCRIPT
    assert "post-factum after target GPU release" in _BUILDER_SCRIPT
    assert "mode==='attestation_probe'" in _BUILDER_SCRIPT
    assert "loc.length&&!drySynthetic&&!responseConditioned" in _BUILDER_SCRIPT
    assert "!checkedName('attestation_probe')" not in _BUILDER_SCRIPT
    assert _BUILDER_SCRIPT.rstrip().endswith("refresh();\n})();</script>")
    assert "not the final reviewed command" in page


def test_build_error_and_existing_deep_link_targets_select_the_right_panel(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        page = app._build_page(errors={"harm_replay": "fixture problem"}).decode("utf-8")
    finally:
        app.close()

    root_tag = _opening_tag(page, "data-tab-key='build'")
    assert "data-default-tab='build-pipeline'" in root_tag
    assert "data-force-default='true'" in root_tag
    pipeline_at = page.index("data-page-panel='build-pipeline'")
    evaluation_at = page.index("data-page-panel='build-evaluation'")
    assert "id='prepared-workflows'" in page[pipeline_at:evaluation_at]
    general_at = page.index("data-page-panel='build-general'")
    builder_form_at = page.index("id='builder'")
    assert "id='ollama-service'" in page[general_at:builder_form_at]
    assert "initialPanel=hashPanel(root)" in page


def test_jobs_overview_keeps_history_filters_and_count_links_consistent(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    failure_dir = tmp_path / "failed-job"
    failure_dir.mkdir()
    app.jobs["failed-job"] = Job(
        job_id="failed-job",
        command="webui_selftest",
        argv=[],
        directory=failure_dir,
        process=None,
        restored_state="failed",
        restored_exit=1,
    )
    try:
        page = app._jobs_page().decode("utf-8")
        filtered = app._jobs_page({"state": "failed"}).decode("utf-8")
    finally:
        app.close()

    overview_at = page.index("data-page-panel='jobs-overview'")
    history_at = page.index("data-page-panel='jobs-history'")
    assert overview_at < history_at < page.index("id='jobstable'")
    assert "id='job-from'" in page[history_at:]
    assert "id='job-to'" in page[history_at:]
    assert "id='jobfilter'" in page[history_at:]
    assert "url.pathname+url.search+url.hash" in page
    assert "url.pathname+url.search);" not in page

    attention_at = page.index("Needs attention")
    attention_card = page[page.rfind("<div class='card'>", 0, attention_at) : attention_at]
    assert "<span class='value'>1</span>" in attention_card
    assert "href=" not in attention_card
    console_at = page.index("Console jobs")
    console_card = page[page.rfind("<div class='card'>", 0, console_at) : console_at]
    assert "href=" not in console_card
    external_at = page.index("External campaigns")
    external_card = page[page.rfind("<div class='card'>", 0, external_at) : external_at]
    assert "href=" not in external_card
    assert "href='/jobs#jobs-history'" in page
    assert "href='/jobs?state=running#jobs-history'" in page
    assert "href='/jobs?state=passed#jobs-history'" in page
    filtered_root = _opening_tag(filtered, "data-tab-key='jobs'")
    assert "data-default-tab='jobs-history'" in filtered_root
    assert "data-force-default='true'" in filtered_root


def test_jobs_history_globally_orders_heterogeneous_rows_by_start_time(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app = _app(tmp_path)
    now = time.time()
    console_dir = tmp_path / "console-job"
    console_dir.mkdir()
    app.jobs["console-oldest"] = Job(
        job_id="console-oldest",
        command="webui_selftest",
        argv=[],
        directory=console_dir,
        process=None,
        restored_state="passed",
        restored_exit=0,
        started_at=now - 30,
    )
    external = SimpleNamespace(
        job_id="external-newest",
        command="run_matrix",
        argv=(),
        started_at=now - 10,
        state="passed",
        artifact_relative="thesis/runner/external-newest",
        tmux_session="external-newest",
        exit_code=0,
        runtime_seconds=lambda: 1.0,
    )
    campaign = SimpleNamespace(
        route_id="campaign-middle",
        campaign_id="campaign-middle",
        started_at=now - 20,
        state="passed",
        status_tag="passed",
        progress="complete",
        named_session_liveness_verified=False,
        model_tasks=(),
        task_outcomes=(),
        model_execution_error="",
        model_attempted_calls=0,
        model_successful_generations=0,
        model_execution_covered_tasks=0,
        model_execution_scope="",
        download_tasks=(),
        runtime_seconds=lambda: 1.0,
    )
    monkeypatch.setattr(
        app,
        "_external_measured_job_scan",
        lambda: ([external], ""),
    )
    monkeypatch.setattr(
        app,
        "_engineering_campaign_scan",
        lambda **_kwargs: ([campaign], ""),
    )
    try:
        page = app._jobs_page().decode("utf-8")
    finally:
        app.close()

    table = page[page.index("id='jobstable'") : page.index("</table>")]
    assert table.index("external-newest") < table.index("campaign-middle")
    assert table.index("campaign-middle") < table.index("console-oldest")
