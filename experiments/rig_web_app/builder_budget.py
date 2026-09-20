"""Use Build's selected hosted routes for the existing no-call budget command."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

from datetime import date, datetime, timezone
import hashlib
import html
import json
from uuid import uuid4

from ura.strict_json import strict_json_loads


def selected_routes(app, params):
    from experiments.hosted_campaign_budget import ROUTES

    specs = app._split_list(params.get("api", ""))
    if (
        not specs
        or len(specs) != len(set(specs))
        or any(spec.startswith(("ollama:", "vllm:")) for spec in specs)
    ):
        raise ValueError(
            _ui_text("builder_budget.select_distinct_hosted_target_models_for_this_forecast")
        )
    # A forecast does not construct a judge or include it as a target route.
    snapshot, _, _, configs = app._selected_api_config_snapshot(
        dict(params, mode="measured", judges="", judge_model="")
    )
    fixed = {row["spec"]: row for row in ROUTES if row.get("inherent_config")}
    routes, api = [], dict(configs)
    for row in snapshot["routes"]:
        spec = row["requested_spec"]
        config = row["config"]
        if config.get("inherent_route"):
            if spec not in fixed:
                raise ValueError(
                    _ui_text("builder_budget.this_fixed_route_has_no_supported_budget_definition")
                )
            route = dict(fixed[spec])
            api[spec] = {"modalities": config["modalities"]}
        else:
            route = dict(
                label=row["model"],
                spec=spec,
                provider=row["provider"],
                model=row["model"],
                max_output_tokens=config.get("max_tokens"),
            )
            if "reasoning_effort" in config:
                route["reasoning_effort"] = config["reasoning_effort"]
            defaults = next((item for item in ROUTES if item["spec"] == spec), {})
            for name in ("reservation_rate_multiplier", "reservation_price_condition"):
                if name in defaults:
                    route[name] = defaults[name]
        if type(route["max_output_tokens"]) is not int or route["max_output_tokens"] <= 0:
            raise ValueError(
                (_ui_text("builder_budget.configure_an_explicit_output_allowance_for") + f"{spec}")
            )
        routes.append(route)
    return routes, api


def budget_panel(app, params, *, automatic=False):
    if not automatic and not params.get("retained_sources_job"):
        return ""

    def escape(value):
        return html.escape(str(value), quote=True)

    try:
        routes, _ = selected_routes(app, params)
        caps = strict_json_loads(params.get("retained_budget_caps", "{}"))
        if not isinstance(caps, dict):
            caps = {}
    except ValueError as exc:
        return (
            _ui_template(
                "<section class='card' id='matched-forecast'><h2>[[text:builder_budget.matched_work_budget]]</h2><p>"
            )
            + escape(exc)
            + _ui_template(
                "</p><button form='builder' formaction='/build/source-runs'>[[text:builder_budget.refresh_selected_models]]</button></section>"
            )
        )
    fields = "".join(
        "<tr><td>"
        + escape(route["spec"])
        + "</td><td>"
        + escape(route["max_output_tokens"])
        + "</td>"
        "<td><input type='number' form='builder' min='1' step='1' required class='matched-call-cap' "
        "data-target='"
        + escape(route["spec"])
        + "' aria-label='"
        + escape(_ui_text("builder_budget.input_cap_for_model", model=route["spec"]))
        + "' value='"
        + escape(caps.get(route["spec"], 10))
        + "'></td></tr>"
        for route in routes
    )
    as_of = params.get("retained_pricing_date") or datetime.now(timezone.utc).date().isoformat()
    job = params.get("retained_budget_job", "")
    return (
        _ui_template(
            "<section class='card' id='matched-forecast'><h2>[[text:builder_budget.matched_comparison_limits]]</h2><p>[[text:builder_budget.uses_the_selected_hosted_models_and_configured_output_allowances]]</p><div class='scroll'><table><thead><tr><th>[[text:builder_budget.model]]</th><th>[[text:builder_budget.output_allowance]]</th><th>[[text:builder_budget.input_request_cap]]</th></tr></thead><tbody>"
        )
        + fields
        + "</tbody></table></div>"
        "<input type='hidden' form='builder' name='retained_budget_caps' id='retained-budget-caps' value='"
        + escape(json.dumps({route["spec"]: caps.get(route["spec"], 10) for route in routes}))
        + "'>"
        "<input type='hidden' form='builder' name='retained_pricing_date' value='"
        + escape(as_of)
        + _ui_template(
            "'><p class='note'>[[text:builder_budget.uses_configuration_s_prices_and_reported_balances_not_a_live_cred]]</p><div class='campaign-actions'><button form='builder' formaction='/build/source-runs' class='ghost'>[[text:builder_budget.refresh_selected_models]]</button>"
        )
        + (
            ""
            if automatic
            else _ui_template(
                "<button form='builder' formaction='/build/forecast-matched'>[[text:builder_budget.prepare_forecast]]</button>"
            )
        )
        + "</div>"
        + (
            "<p><a href='/jobs/"
            + escape(job)
            + _ui_template(
                "'>[[text:builder_budget.open_the_budget_forecast_and_artifacts]]</a></p><input type='hidden' form='builder' name='retained_budget_job' value='"
            )
            + escape(job)
            + "'>"
            if job
            else ""
        )
        + "<script>document.addEventListener('DOMContentLoaded',()=>{document.getElementById('builder')"
        "?.addEventListener('submit',()=>{const caps={};document.querySelectorAll('.matched-call-cap')"
        ".forEach(input=>{caps[input.dataset.target]=Number(input.value);});"
        "document.getElementById('retained-budget-caps').value=JSON.stringify(caps);});});</script></section>"
    )


def prepare_budget(app, params):
    if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
        raise ValueError(_ui_text("builder_budget.select_campaign_for_a_matched_work_forecast"))
    routes, api = selected_routes(app, params)
    caps = strict_json_loads(params.get("retained_budget_caps", "{}"))
    if not isinstance(caps, dict) or set(caps) != {route["spec"] for route in routes}:
        raise ValueError(
            _ui_text("builder_budget.hosted_target_selection_changed_refresh_the_budget_table")
        )
    for route in routes:
        cap = caps[route["spec"]]
        if type(cap) is not int or cap <= 0:
            raise ValueError(
                _ui_text(
                    "builder_budget.each_selected_model_needs_a_positive_whole_number_request_cap"
                )
            )
        route["call_cap"] = cap
    as_of = params.get("retained_pricing_date", "")
    date.fromisoformat(as_of)
    payloads = {
        "api-config": api,
        "route-configuration": routes,
        "pricing-config": app._load_registry("pricing.json", "rig/pricing.example.json"),
        "budgets": app._load_registry("budgets.json", "rig/budgets.example.json"),
    }
    folder = (app.results_root / "rig-web" / "matched-budgets" / uuid4().hex).resolve()
    folder.mkdir(parents=True, mode=0o700)
    values = {
        "--out": str(folder / "forecast.json"),
        "--pricing-as-of": as_of,
        "--reservation-policy": "per_attempt",
    }
    for name, payload in payloads.items():
        raw = (
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            )
            + "\n"
        ).encode()
        path = folder / (name + ".json")
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o600)
        values["--" + name] = str(path)
        values["--" + name + "-sha256"] = hashlib.sha256(raw).hexdigest()
    params = app._save_build_campaign(params)
    job = app.start_job("hosted_campaign_budget", values, campaign_id=params["campaign_id"])
    app._save_build_campaign(dict(params, retained_budget_job=job.job_id))
    return job
