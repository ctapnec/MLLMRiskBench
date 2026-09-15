"""Coverage of saved conversational assessments, using only the campaign index."""
import html
from .workspace_judge_settings import judge_name


def review_coverage_html(db, campaign, settings, *, model='', condition=''):
    cards=[]
    for identity, metadata in settings.items():
        if metadata.get('assessment_method') != 'conversation_based_ai_review':
            continue
        rows=db._query(
            "SELECT COUNT(*) available, "
            "COALESCE(SUM(j.status IN ('valid','invalid')),0) reviewed, "
            "COALESCE(SUM(j.status='valid'),0) labelled "
            "FROM campaign_assignments a JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.assignment_id=a.assignment_id AND r.response_id=a.response_id "
            "LEFT JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
            "AND j.judge_id=? WHERE a.campaign_id=? AND a.evidence_class='measured' AND r.outcome='usable' "
            "AND (?='' OR a.model=?) AND (?='' OR r.condition_id=?)",
            (identity,campaign,model,model,condition,condition))
        if not rows:
            cards.append("<p class='notice amber'>AI review coverage is unavailable.</p>")
            continue
        available,reviewed,labelled=(int(rows[0][key]) for key in ('available','reviewed','labelled'))
        pending=available-reviewed
        label=html.escape(judge_name(identity,metadata))
        cards.append("<section class='card' data-ai-review-coverage style='margin:1rem 0'>"
            +f"<h3>{label}</h3><p><strong>{reviewed:,} / {available:,} available output records reviewed</strong>; "
            +f"{pending:,} unreviewed. {labelled:,} valid labels; {reviewed-labelled:,} reviewed but not scored.</p>"
            +f"<progress aria-label='Saved AI review coverage' value='{reviewed}' max='{max(1,available)}'></progress>"
            +"<p>Conversation-based AI evaluation, not human assessment. Coverage is for indexed measured, "
            "usable outputs in this selection; historical conditions remain separate. Missing answers, "
            "provider-policy outcomes and unstarted assignments are not response-safety labels. "
            "Unreviewed outputs are not counted as safe. Not-scored records remain outside label comparisons.</p></section>")
    return ''.join(cards)
