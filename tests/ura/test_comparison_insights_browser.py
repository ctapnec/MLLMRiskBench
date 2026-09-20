"""Chart navigation and vector exports use actual browser behaviour."""

import xml.etree.ElementTree as ET
import json

import pytest

from test_rig_web_busy_browser import browser  # noqa: F401
from test_workspace_comparison import study, pair  # noqa: F401
from test_workspace_comparison_browser import open_page, ready

expect = pytest.importorskip("playwright.sync_api").expect


@pytest.mark.parametrize("width", [1440, 390])
@pytest.mark.parametrize("theme", ["slate", "parchment", "midnight", "ash", "harbor"])
def test_charts_switch_export_and_survive_comparison_refresh(browser, study, width, theme):  # noqa: F811
    app, left, right, query = study
    pair(study, "first", label="violation")
    pair(study, "second", outcome="missing", status="missing", label=None, truncated=True)
    page, requests, errors = open_page(browser, study, width, query)
    try:
        page.get_by_role("combobox", name="Colour theme").select_option(theme)
        chart = page.locator("[data-insight-detail]")
        expect(chart).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
        before = len(requests)
        for key in ("missing", "policy", "truncated", "label:violation", "usable"):
            chart.locator("[data-insight-metric]").select_option(key)
            expect(chart.locator("[data-insight-panel]:visible")).to_have_attribute(
                "data-insight-panel", key
            )
            assert not page.evaluate("window.uraBusy.isBusy()")
        assert len(requests) == before  # switching figures makes no backend request
        chart.locator("[data-insight-metric]").select_option("label:violation")
        with page.expect_download() as download:
            chart.locator("[data-insight-download]").click()
        root = ET.parse(download.value.path()).getroot()
        assert root.get("width") == "1120"
        points = [n for n in root.iter() if n.get("data-source")]
        assert len(points) == 1 and points[0].get("data-n") == "1"
        assert points[0].get("data-left") == "1" and points[0].get("data-right") == "0"
        assert "Recorded label: violation" in "".join(root.itertext())
        metadata = json.loads(root.find("{http://www.w3.org/2000/svg}metadata").text)
        assert metadata["selection"]["left_campaign"] == left
        assert metadata["selection"]["left_condition"] == "lc"
        assert metadata["selection"]["right_judge"] == "judge"
        assert len(requests) == before
        # The comparison replaces its DOM after this request; listeners must
        # remain functional without inserting/executing a fresh script.
        page.locator("[name=left_condition]").select_option("*")
        ready(page)
        expect(page.locator("[data-insight-overview]")).to_be_visible()
        page.locator("[data-model-comparison] > summary").first.click()
        overview = page.locator("[data-insight-overview]")
        before = len(requests)
        overview.locator("[data-insight-metric]").select_option("missing")
        expect(overview.locator("[data-insight-panel]:visible")).to_have_attribute(
            "data-insight-panel", "missing"
        )
        detail = page.locator("[data-insight-detail]").first
        expect(detail.locator("[data-insight-metric]")).to_have_value("usable")
        detail.locator("[data-insight-metric]").select_option("policy")
        expect(overview.locator("[data-insight-panel]:visible")).to_have_attribute(
            "data-insight-panel", "missing"
        )
        assert len(requests) == before
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()
