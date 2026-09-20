"""Complete count messages must support changed word order and plural wording."""

# Imported pytest fixtures intentionally share their parameter names.
# ruff: noqa: F811

import ast
import json
from pathlib import Path

import pytest

from experiments.rig_web_app import builder_page, i18n, ui
from test_operator_operations import app  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401


def render(browser, content, width):
    page = browser.new_page(viewport=dict(width=width, height=1000))
    page.set_default_timeout(5000)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.route(
        "http://counts.test/**",
        lambda route: route.fulfill(
            status=200,
            content_type="text/css" if route.request.url.endswith("style.css") else "text/html",
            body=ui._STYLE if route.request.url.endswith("style.css") else content,
        ),
    )
    page.goto("http://counts.test/")
    page.wait_for_function("window.uraBusy && !window.uraBusy.isBusy()")
    return page, errors


@pytest.mark.parametrize("width", [390, 1440])
@pytest.mark.parametrize("translated", [False, True])
def test_notice_count_uses_complete_templates_and_preserves_records(
    app, browser, monkeypatch, width, translated
):
    path = app.results_root / "console-warnings.json"
    path.write_text(
        json.dumps(
            {
                "warnings": [
                    dict(level="warning", title="First <&>", detail="Recorded source text"),
                    dict(level="operator-defined", title="Second", detail="Unchanged data"),
                ]
            }
        ),
        encoding="utf-8",
    )
    before = path.read_bytes()
    messages = dict(i18n.catalog())
    one, many = "Show {count} dismissed notice", "Show {count} dismissed notices"
    if translated:
        one, many = "Restore item <&> ({count})", "Restore collection <&> ({count})"
    messages.update({"dashboard.restore_one_notice": one, "dashboard.restore_many_notices": many})
    monkeypatch.setattr(i18n, "catalog", lambda: messages)
    i18n.template.cache_clear()
    page = None
    try:
        page, errors = render(browser, ui._page("Counts", app._warnings_html()), width)
        assert page.locator(".notice strong").first.inner_text() == "First <&>"
        assert not page.locator("#notice-restore").is_visible()
        page.locator(".notice:visible .notice-close").first.click()
        assert page.locator("#notice-restore").inner_text() == one.format(count=1)
        page.locator(".notice:visible .notice-close").first.click()
        assert page.locator("#notice-restore").inner_text() == many.format(count=2)
        saved = page.evaluate("localStorage.getItem('ura-dismissed-notices')")
        page.reload()
        assert page.locator("#notice-restore").inner_text() == many.format(count=2)
        assert page.evaluate("localStorage.getItem('ura-dismissed-notices')") == saved
        assert page.locator("#notice-restore").locator("*").count() == 0
        page.locator("#notice-restore").click()
        assert page.locator(".notice:visible").count() == 2
        assert not page.locator("#notice-restore").is_visible()
        assert not page.evaluate("window.uraBusy.isBusy()")
        assert path.read_bytes() == before
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not errors
    finally:
        if page:
            page.close()
        i18n.template.cache_clear()


@pytest.mark.parametrize("width", [390, 1440])
@pytest.mark.parametrize("arm_count", [1, 2])
@pytest.mark.parametrize("translated", [False, True])
def test_sample_summary_formats_named_counts_without_changing_selection(
    app, browser, monkeypatch, width, arm_count, translated
):
    message = (
        "Arms {arms}; clusters {clusters} <&>"
        if translated
        else "Effective selection - clusters: {clusters}; independently capped arms: {arms}; "
        "converted-row fanout is fixed by the matching preflight."
    )
    messages = dict(i18n.catalog())
    messages["ui.effective_selection_summary"] = message
    monkeypatch.setattr(i18n, "catalog", lambda: messages)
    i18n.template.cache_clear()
    tree = ast.parse(Path(ui.__file__).read_text(encoding="utf-8"))
    template = next(
        n.value.args[0].value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_BUILDER_SCRIPT" for t in n.targets)
    )
    monkeypatch.setattr(builder_page, "_BUILDER_SCRIPT", i18n.template(template))
    arms = [
        dict(
            logical_source_arm=name,
            total_records=count,
            selected_records=1,
            total_clusters=count,
            selected_clusters=1,
            limit=1,
            sample_seed=7,
        )
        for name, count in [("airbench_full", 3), ("strongreject_official", 10)][:arm_count]
    ]
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {
                "projection_id": "lane-projection-" + "1" * 24,
                "call_projection": dict(target_calls=arm_count, judge_calls=0, http_attempts=0),
                "arms": arms,
            },
            "",
        ),
    )
    params = dict(
        mode="measured",
        modality_scope="text",
        corpora=",".join(a["logical_source_arm"] for a in arms),
        limit="1",
        sample_seed="7",
        attackers="replay",
        judges="rules",
    )
    page = None
    try:
        page, errors = render(browser, app._build_page(prefill=params), width)
        page.get_by_role("tab", name="Execution", exact=True).click()
        status = page.locator("#sample-limit-status")
        assert status.inner_text() == message.format(clusters=arm_count, arms=arm_count)
        field = page.locator("#sample-limit-number")
        assert field.input_value() == "1"
        field.fill("0")
        field.dispatch_event("change")
        assert status.inner_text() == message.format(
            clusters=sum(a["total_clusters"] for a in arms), arms=arm_count
        )
        assert page.locator("#sample-seed-input").input_value() == "7"
        assert page.locator(".armbox:checked").count() == arm_count
        assert status.locator("*").count() == 0
        assert not errors
    finally:
        if page:
            page.close()
        i18n.template.cache_clear()
