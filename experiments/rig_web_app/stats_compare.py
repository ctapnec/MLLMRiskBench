"""Stats entry point for the existing exact-input comparison workflow."""

from .i18n import template as _ui_template, text as _ui_text
import html
from urllib.parse import urlencode

from .ui import _page


def response(app, query):
    if query.get("scope") == "jobs":
        from .stats_jobs import response as jobs

        return jobs(app, query)
    rows = app.db.workspaces()
    if rows is None:
        raise ValueError(_ui_text("stats_compare.campaign_index_unavailable"))
    ids = {r["campaign_id"] for r in rows}
    left, right = query.get("left", ""), query.get("right", "")
    if left or right:
        if left not in ids or right not in ids:
            raise ValueError(_ui_text("stats_compare.choose_two_existing_campaigns"))
        params = dict(
            section="compare",
            right_campaign=right,
            left_model="*",
            right_model="*",
            left_condition="*",
            right_condition="*",
        )
        return 303, "/campaigns/" + left + "?" + urlencode(params), b""
    body = _ui_template("<h1>[[text:stats_compare.stats]]</h1>") + app._work_view_tabs(
        "stats", "compare"
    )
    body += _ui_template(
        '<section class="card"><h2>[[text:stats_compare.compare_campaigns]]</h2><p><a href="/stats?view=compare&amp;scope=jobs">[[text:stats_compare.compare_individual_measured_jobs]]</a></p><p>[[text:stats_compare.select_two_campaigns_or_the_same_campaign_twice_to_compare_its_mo]] '
    )
    body += _ui_template(
        "[[text:stats_compare.the_next_screen_offers_models_generation_conditions_and_judging_c]]</p>"
    )
    body += '<form method="get" action="/stats"><input type="hidden" name="view" value="compare"><div class="campaign-grid">'
    for side in ("left", "right"):
        body += (
            '<label class="campaign-field">'
            + side.title()
            + _ui_template(' [[text:stats_compare.campaign]]<select name="')
            + side
            + '" aria-label="'
            + side.title()
            + _ui_template(
                ' campaign" required><option value="">[[text:stats_compare.choose_a_campaign]]</option>'
            )
        )
        body += "".join(
            '<option value="' + r["campaign_id"] + '">' + html.escape(r["name"]) + "</option>"
            for r in rows
        )
        body += "</select></label>"
    body += _ui_template(
        '</div><div class="action-row"><button>[[text:stats_compare.open_matched_input_comparison]]</button></div></form>'
    )
    body += _ui_template(
        "<p>[[text:stats_compare.different_models_generation_conditions_source_tasks_and_judging_c]] "
    )
    body += _ui_text(
        "stats_compare.no_scores_are_pooled_and_no_latest_or_best_answer_is_silently_sel"
    )
    body += _ui_template(
        "[[text:stats_compare.jobs_without_indexed_input_ownership_cannot_be_matched_merely_by]]</p></section>"
    )
    return (
        200,
        "text/html; charset=utf-8",
        _page(
            _ui_text("stats_compare.compare_campaigns"),
            body,
            active=_ui_text("stats_compare.stats"),
        ),
    )
