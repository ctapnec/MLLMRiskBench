"""Real form parsing and validation, not a mocked successful preparation."""
from urllib.parse import parse_qsl, urlsplit

import pytest

from test_operator_operations import app as operation_app
from test_rig_web_busy_browser import browser as shared_browser
from experiments.rig_web_app import campaign_flow

app = operation_app
browser = shared_browser


def choices(app, **changes):
    owner = app.db.create_workspace("Validation boundary", "local")
    values = dict(
        work_kind="campaign", campaign_id=owner, campaign_flow="on",
        campaign_inputs="fresh", mode="measured", setup_mode="automatic",
        local="vllm:fixture/model", corpora="xstest_full,vlsbench_release",
        modality_scope="text,image", attackers="replay", judges="rules",
        limit="2", seeds="0", sample_seed="0", max_queries="1", max_turns="1",
        target_answer_retries="1", automatic_caps="on", deadline="3600",
        campaign_local="off", campaign_haiku="off", local_budget_hours="1",
    )
    values.update(changes)
    app.db.save_workspace_definition(owner, values)
    return values


@pytest.mark.parametrize("kind", ["campaign", "run"])
@pytest.mark.parametrize("field,value", [
    ("local_budget_hours", "-1"), ("local_budget_hours", "0"),
    ("local_budget_hours", "0.5"), ("max_queries", "-1"),
    ("max_turns", "0"), ("deadline", "-1"),
    ("target_answer_retries", "11"), ("target_answer_retries", "-1"),
    ("limit", "-1"), ("lock_stale_seconds", "0"),
])
def test_review_rejects_bad_fields_before_any_operation(app, kind, field, value):
    params = choices(app, **{field: value, "work_kind": kind})
    status, _, body = app.handle("POST", "/build/review", params)
    assert status == 200
    text = body.decode()
    assert "The lane was not started" in text
    assert "must be" in text
    assert f"name='{field}'" in text
    assert f"value='{value}'" in text
    assert "data-mod='image' checked" in text
    if field == "local_budget_hours":
        assert "<strong>Local process wall-time cap (hours)</strong>" in text
    assert not app._operations and not app.jobs and not app.db.load_jobs()


@pytest.mark.parametrize("value", ["", "1", "3"])
def test_optional_wall_time_uses_blank_not_negative_sentinel(app, value):
    params = app._builder_params(choices(app, local_budget_hours=value))
    errors = app._validate_builder(params, preparation=True)
    assert "local_budget_hours" not in errors
    assert "Local process wall-time cap" in app._build_page(prefill=params).decode()


def test_background_validation_names_field_before_assessment_preparation(app, monkeypatch):
    from experiments.rig_web_app import campaign_assessment

    params = app._builder_params(choices(app, local_budget_hours="-1", campaign_local="on"))
    operation = app._operations[app._start_operation("campaign", params)]
    monkeypatch.setattr(campaign_assessment, "prepare_values", lambda *a, **k: pytest.fail(
        "Invalid choices must not prepare any assessment"
    ))
    app._advance_operation(operation)
    assert operation["status"] == "failed"
    assert "Local process wall-time cap (hours): must be a positive integer" in operation["error"]
    assert not operation.get("preparation") and not app.jobs


def test_campaign_setting_error_preserves_form_choices(app):
    params = choices(app, campaign_haiku="on", campaign_judge_cost="-1")
    status, _, body = app.handle("POST", "/build/review", params)
    assert status == 200
    text = body.decode()
    assert "The lane was not started" in text
    assert "data-mod='image' checked" in text and 'value="-1"' in text
    assert not app._operations and not app.jobs


def test_old_unnamed_failure_shows_field_and_keeps_history(app):
    params = app._builder_params(choices(app, local_budget_hours="-1"))
    operation = app._operations[app._start_operation("campaign", params)]
    operation.update(status="failed", error="must be a positive integer")
    body = campaign_flow.progress(app, operation).decode()
    assert "<strong>Local process wall-time cap (hours)</strong>" in body
    assert "Change the reported campaign choice" in body
    assert "Resume campaign</button>" not in body
    assert operation["status"] == "failed" and operation["error"] == "must be a positive integer"
    assert operation["params"]["local_budget_hours"] == "-1"
    assert not app.jobs


@pytest.mark.parametrize("width", [390, 1440])
@pytest.mark.parametrize("field,value", [
    ("local_budget_hours", "-1"), ("max_queries", "0"),
    ("target_answer_retries", "11"), ("deadline", "0.5"),
])
def test_invalid_hidden_tab_is_revealed_without_request_or_spinner(browser, app, width, field, value):
    params = choices(app)
    page = browser.new_page(viewport=dict(width=width, height=1000))
    posts, errors = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(route):
        req = route.request
        url = urlsplit(req.url)
        if req.method == "POST":
            posts.append(url.path)
        status, mime, body = app.handle(req.method, url.path + ("?" + url.query if url.query else ""),
            dict(parse_qsl(req.post_data or "", keep_blank_values=True)))
        route.fulfill(status=status, content_type=mime, body=body)

    page.route("http://validation.test/**", route)
    try:
        page.goto("http://validation.test/build?campaign_id=" + params["campaign_id"])
        page.get_by_role("tab", name="Execution", exact=True).click()
        control = page.locator("[name=" + field + "]")
        control.fill(value)
        page.get_by_role("tab", name="General", exact=True).click()
        assert not control.is_visible()
        page.get_by_role("button", name="Review campaign", exact=True).filter(visible=True).click()
        assert control.is_visible()
        assert not control.evaluate("node=>node.validity.valid")
        assert not page.evaluate("window.uraBusy.isBusy()")
        assert not posts and not errors and not app._operations
        control.fill("1")
        assert control.evaluate("node=>node.validity.valid")
    finally:
        page.close()


@pytest.mark.parametrize("width", [390, 1440])
def test_multiple_invalid_tabs_reveal_first_error_then_next(browser, app, width):
    params = choices(app)
    page = browser.new_page(viewport=dict(width=width, height=1000))
    posts, messages = [], []
    page.on("console", lambda message: messages.append(message.text) if message.type == "error" else None)

    def route(route):
        req = route.request
        if req.method == "POST":
            posts.append(req.url)
        path = urlsplit(req.url)
        status, mime, body = app.handle(req.method, path.path + ("?" + path.query if path.query else ""))
        route.fulfill(status=status, content_type=mime, body=body)

    page.route("http://validation.test/**", route)
    try:
        page.goto("http://validation.test/build?campaign_id=" + params["campaign_id"])
        page.get_by_role("tab", name="General", exact=True).click()
        first = page.locator("[name=campaign_collection_cost]")
        first.fill("-1")
        page.get_by_role("tab", name="Execution", exact=True).click()
        second = page.locator("[name=local_budget_hours]")
        second.fill("-1")
        page.get_by_role("tab", name="General", exact=True).click()
        page.get_by_role("button", name="Review campaign", exact=True).filter(visible=True).click()
        assert first.is_visible() and not second.is_visible()
        first.fill("")
        page.get_by_role("button", name="Review campaign", exact=True).filter(visible=True).click()
        assert second.is_visible()
        assert not posts and not messages
        assert not page.evaluate("window.uraBusy.isBusy()")
    finally:
        page.close()


def test_automatic_caps_exclude_stale_manual_values_without_erasing_them(browser, app):
    params = choices(app, cap_target="-1", cap_judge="0", cap_http="0.5")
    page = browser.new_page()

    def route(route):
        assert route.request.method == "GET"
        path = urlsplit(route.request.url)
        status, mime, body = app.handle("GET", path.path + ("?" + path.query if path.query else ""))
        route.fulfill(status=status, content_type=mime, body=body)

    page.route("http://validation.test/**", route)
    try:
        page.goto("http://validation.test/build?campaign_id=" + params["campaign_id"])
        page.get_by_role("tab", name="Execution", exact=True).click()
        for field in ("cap_target", "cap_judge", "cap_http"):
            assert page.locator("[name=" + field + "]").is_disabled()
        assert page.evaluate("!new FormData(document.getElementById('builder')).has('cap_target')")
        page.locator("[name=automatic_caps]").uncheck()
        page.get_by_text("Manual call-limit overrides", exact=True).click()
        for field in ("cap_target", "cap_judge", "cap_http"):
            control = page.locator("[name=" + field + "]")
            assert control.is_enabled() and control.input_value() == params[field]
            assert not control.evaluate("node=>node.validity.valid")
    finally:
        page.close()
