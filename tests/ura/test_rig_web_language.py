"""Catalog coverage, escaping and display-only language selection."""

import ast
import json
import re
from pathlib import Path

import pytest

from experiments.rig_web_app import i18n, ui
from test_rig_web_busy_browser import browser  # noqa: F401
from test_rig_web_themes import serve


def test_catalog_references_exist_and_templates_never_receive_dynamic_data():
    root = Path(ui.__file__).parent
    used = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"_ui_text", "_ui_template"}:
                continue
            assert isinstance(node.args[0], ast.Constant), (path, node.lineno)
            value = node.args[0].value
            if node.func.id == "_ui_text":
                used.add(value)
                assert value in i18n.catalog(), (path, node.lineno, value)
            else:
                keys = [m.group(2) for m in i18n._MARKER.finditer(value)]
                assert keys, (path, node.lineno)
                used.update(keys)
                rendered = i18n.template(value)
                assert not i18n._MARKER.search(rendered), (path, node.lineno)
    assert used == set(i18n.catalog()), "Orphaned catalog messages need removal"
    assert not any(
        re.search(r"</?[a-z][^>]*>|<!doctype|\b(?:ORDER BY|GROUP BY|LEFT JOIN)\b|=\?", value)
        for value in i18n.catalog().values()
    ), "Code or SQL must not be translated"


def test_context_escaping_and_unknown_message(monkeypatch):
    payload = "</script><img src=x onerror=alert(1)> \" ' & \u2028"
    monkeypatch.setattr(i18n, "catalog", lambda: {"test": payload})
    assert "<img" not in i18n.template("[[text:test]]")
    assert '"' not in i18n.template("[[attr:test]]")
    encoded = i18n.template("[[js:test]]")
    assert "</script>" not in encoded
    assert json.loads(encoded) == payload
    with pytest.raises(KeyError):
        i18n.text("missing")


def test_catalog_is_cached_read_only_and_research_content_is_untouched():
    assert i18n.catalog() is i18n.catalog()
    with pytest.raises(TypeError):
        i18n.catalog()["language.label"] = "changed"
    body = "<pre>[[text:language.label]] --local model:en en.json</pre>"
    page = ui._page("Research text", body).decode()
    assert body in page
    assert "<html lang='en'>" in page


def test_keyboard_protocol_is_not_a_translated_message():
    assert "event.key==='Escape'" in ui._BUILDER_SCRIPT
    assert not {"Escape", "ArrowLeft", "ArrowRight", "Home", "End", "Tab"}.intersection(
        i18n.catalog().values()
    )
    assert ".modelquant select" not in i18n.catalog().values()
    assert "querySelector('.modelquant select')" in ui._BUILDER_SCRIPT


@pytest.mark.parametrize(
    "module,key,kind",
    [
        ("builder_sources", "builder_sources.run", "text"),
        ("builder_sources", "builder_sources.run_s_selected_copy", "js"),
        ("campaign_flow", "campaign_flow.compose_review", "js"),
        ("settings", "settings.saved", "text"),
        ("workspace_comparison", "workspace_comparison.only", "text"),
        ("workspace_pages", "workspace_pages.condition_copy", "text"),
        ("ui", "ui.modalities", "js"),
        ("ui", "ui.shown_items", "js"),
        ("ui", "ui.one_selected_arm", "js"),
        ("ui", "ui.many_selected_arms", "js"),
        ("ui", "ui.additional_items", "js"),
    ],
)
def test_fragmented_and_client_copy_uses_the_catalog(monkeypatch, module, key, kind):
    """A missing message extraction must fail even when unchanged English renders."""
    tree = ast.parse(Path(ui.__file__).with_name(module + ".py").read_text(encoding="utf-8"))
    marker = f"[[{kind}:{key}]]"
    fragments = [
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_ui_template"
        and marker in node.args[0].value
    ]
    assert fragments, (module, key)
    messages = dict(i18n.catalog())
    messages[key] = "Catalog sentinel <&>"
    monkeypatch.setattr(i18n, "catalog", lambda: messages)
    i18n.template.cache_clear()
    try:
        for fragment in fragments:
            rendered = i18n.template(fragment)
            assert "Catalog sentinel" in rendered
            assert "Catalog sentinel <&>" not in rendered
    finally:
        i18n.template.cache_clear()


@pytest.mark.parametrize("width", [360, 390, 1440])
def test_language_is_next_to_theme_on_navigation_without_requests_or_data_changes(browser, width):
    context = browser.new_context(viewport={"width": width, "height": 1000})
    # A stale or unsupported preference cannot load a path or select a nonexistent locale.
    context.add_init_script("localStorage.setItem('ura-language','../../unknown')")
    page = context.new_page()
    requests = serve(page)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        page.goto("http://ui.test/first", wait_until="networkidle")
        choice = page.get_by_role("combobox", name="Language", exact=True)
        assert choice.locator("option").all_text_contents() == ["EN"]
        # Inline SVG also works on Windows without a country-flag emoji font.
        flag = page.locator('.language-choice [data-language-flag="gb"]')
        assert flag.is_visible() and flag.get_attribute("aria-hidden") == "true"
        assert choice.input_value() == "en"
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.locator(".display-preferences #theme-picker").count() == 1
        assert page.locator(".display-preferences #language-picker").count() == 1
        saved = page.locator("#settings").evaluate("e=>Array.from(new FormData(e))")
        count = len(requests)
        choice.select_option("en")
        page.get_by_role("combobox", name="Colour theme").select_option("midnight")
        assert len(requests) == count
        assert saved == page.locator("#settings").evaluate("e=>Array.from(new FormData(e))")
        assert not page.evaluate("document.documentElement.scrollWidth>innerWidth")
        page.goto("http://ui.test/second", wait_until="networkidle")
        assert choice.input_value() == "en"
        assert page.get_by_role("combobox", name="Colour theme").input_value() == "midnight"
        assert not errors
    finally:
        context.close()
