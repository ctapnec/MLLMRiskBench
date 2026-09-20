"""A clearly labelled direct-run cost scenario, not a token-count guarantee."""

from .i18n import template as _ui_template, text as _ui_text
import html
import math

from .reports import rate_for


def forecast(app, params, projection):
    if not params.get("api") and not (
        params.get("judge_model") and "llm" in params.get("judges", "").split(",")
    ):
        return ""
    body = _ui_template('<section class="card"><h2>[[text:direct_costs.hosted_cost_estimate]]</h2>')
    if not projection:
        return body + _ui_template(
            "<p>[[text:direct_costs.available_after_the_automatic_workload_check]]</p></section>"
        )
    try:
        snapshot, _, _, _ = app._selected_api_config_snapshot(params)
        pricing = app._load_registry("pricing.json", "rig/pricing.example.json")
        totals = projection["call_projection"]
        targets = set(app._split_list(params.get("api", "")))
        rows = []
        first = 0.0
        full = 0.0
        incomplete = False
        for route in snapshot["routes"]:
            spec = route["requested_spec"]
            config = route["config"]
            calls = int(totals["target_calls"] if spec in targets else totals["judge_calls"])
            if not calls:
                continue
            rate, why = rate_for(pricing, route["provider"], route["model"])
            allowance = config.get("max_tokens")
            money = _ui_text("direct_costs.not_estimated") + why if rate is None else ""
            estimated = False
            if rate and isinstance(allowance, int) and allowance > 0:
                rates = rate.get("per_million_tokens", {})
                try:
                    ip = float(rates["input"])
                    op = float(rates["output"])
                    if rate.get("currency") != "USD" or not all(
                        math.isfinite(x) and x >= 0 for x in (ip, op)
                    ):
                        raise ValueError("price")
                    expected = calls * (4096 * ip + max(1, allowance // 4) * op) / 1e6
                    maximum = calls * (4096 * ip + allowance * op) / 1e6
                    first += expected
                    full += maximum
                    money = f"${expected:.4f} / ${maximum:.4f}"
                    estimated = True
                except (KeyError, TypeError, ValueError):
                    money = _ui_text(
                        "direct_costs.not_estimated_complete_usd_token_prices_required"
                    )
            elif rate:
                money = _ui_text("direct_costs.not_estimated_explicit_output_allowance_required")
            incomplete |= not estimated
            cells = (
                spec,
                str(calls),
                str(allowance or _ui_text("direct_costs.not_recorded")),
                money,
            )
            rows.append(
                "<tr>" + "".join("<td>" + html.escape(v) + "</td>" for v in cells) + "</tr>"
            )
        body += (
            _ui_template(
                '<div class="scroll"><table><tr><th>[[text:direct_costs.model]]</th><th>[[text:direct_costs.conservative_call_count]]</th><th>[[text:direct_costs.output_allowance]]</th><th>[[text:direct_costs.quarter_full_output_scenario]]</th></tr>'
            )
            + "".join(rows)
            + "</table></div>"
        )
        body += (
            _ui_template("<p>[[text:direct_costs.priced_route_totals]]")
            + f"{first:.4f}"
            + " / $"
            + f"{full:.4f}"
            + _ui_template(" [[text:direct_costs.before_http_retries]]</p>")
        )
        body += _ui_template(
            "<p>[[text:direct_costs.assumes_4_096_input_tokens_per_call_compares_one_quarter_of_the_c]]</p>"
        )
        body += _ui_template(
            "<p>[[text:direct_costs.images_long_context_caching_paid_transport_retries_and_adaptive_a]]</p>"
        )
        if incomplete:
            body += _ui_template(
                '<p class="notice amber">[[text:direct_costs.some_routes_are_unpriced_the_displayed_sum_is_incomplete_configur]]</p>'
            )
    except (KeyError, TypeError, ValueError, OSError) as exc:
        body += (
            _ui_template('<p class="notice amber">[[text:direct_costs.cost_estimate_unavailable]] ')
            + html.escape(str(exc))
            + "</p>"
        )
    return body + "</section>"
