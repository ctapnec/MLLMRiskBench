"""Real review requests must preserve drafts and release the shared wait guard."""

# Imported pytest fixtures deliberately share test-parameter names.
# ruff: noqa: F811

import ast
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from experiments.rig_web_app import human_review_pages, i18n, ui
from test_human_personal_review import open_personal, personal  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401


def review_page(browser, personal, width, *, hold_initial=False):
    app, _, _ = personal
    store, study, token = open_personal(personal)
    page = browser.new_page(viewport=dict(width=width, height=1000))
    page.set_default_timeout(5000)
    held, errors = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    holding = {"initial": hold_initial, "rating": False}

    def respond(item):
        req = item.request
        url = urlsplit(req.url)
        if url.path == "/static/style.css":
            return item.fulfill(status=200, content_type="text/css", body=ui._STYLE)
        data = {
            key: values[-1]
            for key, values in parse_qs(req.post_data or "", keep_blank_values=True).items()
        }
        status, mime, body = app.handle(
            req.method, url.path + ("?" + url.query if url.query else ""), data
        )
        item.fulfill(status=status, content_type=mime, body=body)

    def route(item):
        path = urlsplit(item.request.url).path
        if (holding["initial"] and path.endswith("/data")) or (
            holding["rating"] and path.endswith("/rating")
        ):
            held.append(item)
        else:
            respond(item)

    page.route("http://review.test/**", route)
    page.goto("http://review.test/review/" + token)
    return page, store, study, token, holding, held, errors, respond


def ready(page):
    page.wait_for_function(
        "document.querySelector('[data-rating=refusal_label]') && !window.uraBusy.isBusy()"
    )


@pytest.mark.parametrize("width", [390, 1440])
def test_initial_review_request_stays_guarded_after_pageshow(browser, personal, width):
    page, _, _, _, holding, held, errors, respond = review_page(
        browser, personal, width, hold_initial=True
    )
    try:
        page.wait_for_timeout(80)
        assert len(held) == 1
        assert page.evaluate("window.uraBusy.isBusy()")
        assert page.locator("#busy-overlay").is_visible()
        assert page.locator("body > nav").evaluate("node=>node.inert")
        assert page.locator("main").evaluate("node=>node.inert")
        holding["initial"] = False
        respond(held[0])
        ready(page)
        assert not page.locator("#busy-overlay").is_visible()
        assert not page.locator("main").evaluate("node=>node.inert")
        assert not errors
    finally:
        page.close()


@pytest.mark.parametrize("width", [390, 1440])
@pytest.mark.parametrize(
    "outcome", ["success", "json_error", "html_error", "network_error", "timeout", "invalid_json"]
)
def test_review_save_blocks_duplicates_and_recovers_without_losing_choices(
    browser, personal, width, outcome
):
    page, store, _, token, holding, held, errors, respond = review_page(browser, personal, width)
    try:
        ready(page)
        page.get_by_role("button", name="2. Refusal", exact=True).click()
        if outcome == "timeout":
            page.evaluate("""()=>{const native=window.setTimeout;
                window.setTimeout=(fn,ms,...args)=>native(fn,ms===30000?250:ms,...args);} """)
        holding["rating"] = True
        page.locator("[data-rating=refusal_label]").select_option("not_refusal")
        page.evaluate("""()=>{const button=Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Save draft');
            for(let i=0;i<1000;i++)button.click();} """)
        page.wait_for_timeout(60)
        assert len(held) == 1
        assert page.locator("#busy-overlay").is_visible()
        assert page.locator("main").evaluate("node=>node.inert")
        assert page.locator("body > nav").evaluate("node=>node.inert")
        if outcome == "success":
            respond(held[0])
        elif outcome == "json_error":
            held[0].fulfill(
                status=409,
                content_type="application/json",
                body='{"error":"Conflict <strong>literal</strong> & data"}',
            )
        elif outcome == "html_error":
            held[0].fulfill(status=503, content_type="text/html", body="<p>Proxy unavailable</p>")
        elif outcome == "network_error":
            held[0].abort("failed")
        elif outcome == "invalid_json":
            held[0].fulfill(status=200, content_type="text/html", body="<p>Not JSON</p>")
        page.wait_for_function("!window.uraBusy.isBusy()")
        status = page.locator("#review-status")
        if outcome == "success":
            assert status.inner_text() == "Draft saved."
        else:
            expected = {
                "json_error": "Conflict <strong>literal</strong> & data",
                "html_error": "HTTP 503",
                "network_error": "could not be reached",
                "timeout": "timed out",
                "invalid_json": "unreadable response",
            }[outcome]
            assert expected in status.inner_text()
            assert status.locator("strong,p").count() == 0
        assert page.locator("[data-rating=refusal_label]").input_value() == "not_refusal"
        assert not page.locator("body > nav").evaluate("node=>node.inert")
        assert not page.locator("main").evaluate("node=>node.inert")
        item = store.view(token)["queue"][0]["id"]
        if outcome != "success":
            assert store.view(token, item)["item"]["rating"]["revision"] == 0
            holding["rating"] = False
            page.get_by_role("button", name="Save draft", exact=True).click()
            page.wait_for_function(
                "document.querySelector('#review-status').textContent==='Draft saved.' && !window.uraBusy.isBusy()"
            )
        saved = store.view(token, item)["item"]["rating"]
        assert saved["revision"] == 1 and saved["state"] == "draft"
        assert saved["value"]["refusal_label"] == "not_refusal"
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not errors
    finally:
        page.close()


@pytest.mark.parametrize("width", [390, 1440])
def test_review_actions_do_not_depend_on_english_prefixes(browser, personal, monkeypatch, width):
    tree = ast.parse(Path(human_review_pages.__file__).read_text(encoding="utf-8"))
    source = next(
        n.value.args[0].value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_REVIEW_SCRIPT" for t in n.targets)
    )
    messages = dict(i18n.catalog())
    messages["human_review_pages.defer_opt_out_of_this_item"] = "Set this item aside"
    monkeypatch.setattr(i18n, "catalog", lambda: messages)
    i18n.template.cache_clear()
    monkeypatch.setattr(human_review_pages, "_REVIEW_SCRIPT", i18n.template(source))
    page = None
    try:
        page, store, study, _, _, _, errors, _ = review_page(browser, personal, width)
        ready(page)
        optout = page.locator("#review-body > details:not(.review-reference)")
        assert (
            optout.get_by_role(
                "button", name="Set this item aside", exact=True, include_hidden=True
            ).count()
            == 1
        )
        assert (
            page.locator(".review-wizard-footer")
            .get_by_role("button", name="Save draft", exact=True)
            .is_visible()
        )
        optout.locator("summary").click()
        page.locator("[data-rating=defer_reason]").select_option(index=1)
        optout.get_by_role("button", name="Set this item aside", exact=True).click()
        page.wait_for_function(
            "document.querySelector('#review-status').textContent==='Deferred for remediation.' && !window.uraBusy.isBusy()"
        )
        assert store.summary(study)["counts"]["deferred"] == 1
        assert not errors
    finally:
        if page:
            page.close()
        i18n.template.cache_clear()
