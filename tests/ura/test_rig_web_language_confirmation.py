"""Independent round trips and browser-generated review-state coverage."""

import html
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from experiments.rig_web_app import display_labels, i18n, ui
from test_human_personal_review import personal  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401


class ParsedText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.attributes = []

    def handle_data(self, value):
        self.text.append(value)

    def handle_starttag(self, tag, attrs):
        self.attributes.extend(attrs)


def test_catalog_has_unique_keys_and_no_hidden_control_characters():
    path = Path(i18n.__file__).with_name("locales") / "en.json"
    entries = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=list)
    keys = [key for key, _ in entries]
    assert len(keys) == len(set(keys))
    for key, value in entries:
        assert all(char >= " " or char in "\n\r\t" for char in value), key
        assert "\x7f" not in value, key


def test_every_catalog_message_round_trips_in_html_and_attribute_contexts():
    for key, message in i18n.catalog().items():
        parsed = ParsedText()
        parsed.feed("<p>" + i18n.template("[[text:" + key + "]]") + "</p>")
        assert "".join(parsed.text) == message, key
        parsed = ParsedText()
        parsed.feed("<input title='" + i18n.template("[[attr:" + key + "]]") + "'>")
        assert dict(parsed.attributes)["title"] == message, key


def test_every_catalog_message_round_trips_in_browser_script_contexts(browser):
    messages = list(i18n.catalog().values())
    keys = list(i18n.catalog())
    javascript = ",".join(i18n.template("[[js:" + key + "]]") for key in keys)
    fragments = ",".join(i18n.template("[[jshtml:" + key + "]]") for key in keys)
    page = browser.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        page.set_content(
            "<script>window.messages=["
            + javascript
            + "];window.fragments=["
            + fragments
            + "];</script>"
        )
        assert page.evaluate("window.messages") == messages
        assert page.evaluate("window.fragments") == [
            html.escape(message, quote=True) for message in messages
        ]
        assert not errors
    finally:
        page.close()


def test_all_review_queue_states_have_explicit_display_labels():
    # The review store supplies an unstarted item before any rating exists.
    assert {"unstarted", "draft", "deferred", "submitted"} <= display_labels.LABELS.keys()


@pytest.mark.parametrize("width", [390, 1440])
def test_review_queue_translates_display_but_preserves_item_and_rating_values(
    browser, personal, monkeypatch, width
):
    assert "unstarted" in display_labels.LABELS
    monkeypatch.setitem(display_labels.LABELS, "unstarted", "Ready <&> for review")
    monkeypatch.setitem(display_labels.LABELS, "not_refusal", "A displayed choice <&>")
    app, owner, _ = personal
    page = browser.new_page(viewport=dict(width=width, height=1000))
    errors = []
    queues = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(item):
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
        if url.path.endswith("/data") and status == 200:
            queues.extend(json.loads(body)["queue"])
        if status == 303:
            item.fulfill(status=status, headers={"Location": mime}, body="")
        else:
            item.fulfill(status=status, content_type=mime, body=body)

    page.route("http://review.test/**", route)
    try:
        page.goto("http://review.test/human-evaluation?campaign_id=" + owner)
        page.locator("[name=source]").select_option(label="Saved text answers")
        page.locator("[name=clusters]").fill("1")
        page.locator("[name=acknowledge]").check()
        page.get_by_role("button", name="Prepare answers for review", exact=True).click()
        page.get_by_role("heading", name="Personal evaluation", exact=True).wait_for()
        queue = page.get_by_role("combobox", name="Assigned item", exact=True)
        assert queue.locator("option").all_text_contents() == ["Item 1 - Ready <&> for review"]
        assert queues and queues[0]["state"] == "unstarted"
        assert queue.input_value() == queues[0]["id"]
        page.get_by_role("button", name="2. Refusal", exact=True).click()
        choice = page.locator("[data-rating=refusal_label]")
        choice.select_option("not_refusal")
        assert choice.locator("option:checked").inner_text() == "A displayed choice <&>"
        page.get_by_role("combobox", name="Language", exact=True).select_option("en")
        page.get_by_role("combobox", name="Colour theme").select_option("midnight")
        assert choice.input_value() == "not_refusal"
        assert queue.input_value() == queues[0]["id"]
        page.get_by_role("button", name="1. Context", exact=True).click()
        # Step navigation awaits the pending draft save before revealing context.
        page.locator(".review-reference[open]").wait_for(state="visible")
        assert "A substantial example answer." in page.locator("#review-body").inner_text()
        token = urlsplit(page.url).path.rsplit("/", 1)[-1]
        saved = app._human_store().view(token, queues[0]["id"])["item"]["rating"]
        assert saved["state"] == "draft"
        assert saved["value"]["refusal_label"] == "not_refusal"
        assert not errors
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    finally:
        page.close()
