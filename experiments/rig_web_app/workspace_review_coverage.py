"""Coverage of saved conversational assessments, using only the campaign index."""

from .i18n import template as _ui_template, text as _ui_text
import html
from urllib.parse import urlencode
from .workspace_judge_settings import judge_name


def review_coverage_html(db, campaign, settings, *, model="", condition=""):
    cards = []
    for identity, metadata in settings.items():
        if metadata.get("assessment_method") != "conversation_based_ai_review":
            continue
        rows = db._query(
            "SELECT COUNT(*) available, "
            "COALESCE(SUM(j.status IN ('valid','invalid')),0) reviewed, "
            "COALESCE(SUM(j.status='valid'),0) labelled "
            "FROM campaign_assignments a JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.assignment_id=a.assignment_id AND r.response_id=a.response_id "
            "LEFT JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
            "AND j.judge_id=? WHERE a.campaign_id=? AND a.evidence_class='measured' AND r.outcome='usable' "
            "AND (?='' OR a.model=?) AND (?='' OR r.condition_id=?)",
            (identity, campaign, model, model, condition, condition),
        )
        if not rows:
            cards.append(
                _ui_template(
                    "<p class='notice amber'>[[text:workspace_review_coverage.ai_review_coverage_is_unavailable]]</p>"
                )
            )
            continue
        available, reviewed, labelled = (
            int(rows[0][key]) for key in ("available", "reviewed", "labelled")
        )
        pending = available - reviewed
        scoped = db._query(
            "SELECT 1 FROM campaign_review_selection WHERE campaign_id=? AND judge_id=? LIMIT 1",
            (campaign, identity),
        )
        maximum = available
        heading = (
            f"{reviewed:,}"
            + " / "
            + f"{available:,}"
            + _ui_text("workspace_review_coverage.available_output_records_reviewed")
        )
        detail = f"{pending:,}" + _ui_text("workspace_review_coverage.unreviewed")
        if scoped:
            sample = db._query(
                "SELECT COUNT(*) planned FROM campaign_review_selection s JOIN campaign_responses r "
                "ON r.campaign_id=s.campaign_id AND r.response_id=s.response_id JOIN campaign_assignments a "
                "ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id WHERE s.campaign_id=? "
                "AND s.judge_id=? AND (?='' OR a.model=?) AND (?='' OR r.condition_id=?)",
                (campaign, identity, model, model, condition, condition),
            )
            maximum = int(sample[0]["planned"])
            heading = (
                f"{reviewed:,}"
                + " / "
                + f"{maximum:,}"
                + _ui_text("workspace_review_coverage.selected_output_records_reviewed")
            )
            detail = (
                _ui_text("workspace_review_coverage.selected_review_complete")
                if reviewed == maximum
                else (
                    f"{maximum - reviewed:,}"
                    + _ui_text("workspace_review_coverage.selected_records_pending")
                )
            ) + (
                f"{available:,}"
                + _ui_text("workspace_review_coverage.available_output_records")
                + f"{available - maximum:,}"
                + _ui_text("workspace_review_coverage.outside_this_review_sample_not_pending_work")
            )
        label = html.escape(judge_name(identity, metadata))
        link = (
            "/campaigns/"
            + campaign
            + "?"
            + urlencode(dict(section="judging", model=model, condition=condition, judge=identity))
        )
        cards.append(
            "<section class='card' data-ai-review-coverage style='margin:1rem 0'>"
            + f"<h3>{label}</h3><p><strong>{heading}</strong>; "
            + (
                f"{detail}"
                + " "
                + f"{labelled:,}"
                + _ui_text("workspace_review_coverage.valid_labels")
                + f"{reviewed - labelled:,}"
                + _ui_template(" [[text:workspace_review_coverage.reviewed_but_not_scored]]</p>")
            )
            + (
                _ui_template(
                    "<progress aria-label='[[attr:workspace_review_coverage.saved_ai_review_coverage]]' value='"
                )
                + f"{reviewed}"
                + "' max='"
                + f"{max(1, maximum)}"
                + "'></progress>"
            )
            + _ui_template(
                "<p>[[text:workspace_review_coverage.conversation_based_ai_evaluation_not_human_assessment_coverage_is]]</p>"
            )
            + "<p class='action-row'><a class='button ghost' href='"
            + html.escape(link, quote=True)
            + _ui_template(
                "'>[[text:workspace_review_coverage.show_this_evaluator_s_charts]]</a></p></section>"
            )
        )
    return "".join(cards)
