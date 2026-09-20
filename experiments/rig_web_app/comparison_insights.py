"""Descriptive paired comparisons from the already selected SQLite counts.

No additional queries, rescoring, pooled model scores or inferred label aliases.
Every plotted rate has the same explicitly reported denominator on both sides.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import html
import json
import textwrap

from .i18n import template as _ui_template, text as _ui_text

FACETS = ("corpus", "framework", "modality")


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(row[k] for k in FACETS)].append(row)
    result = []
    for source, group in sorted(groups.items()):
        matched = [r for r in group if r["match_status"] == "matched"]
        valid = [
            r
            for r in matched
            if all(
                r[s + "_status"] == "valid" and r[s + "_label"] is not None
                for s in ("left", "right")
            )
        ]
        known = [
            r for r in matched if all(r[s + "_truncated"] in (0, 1) for s in ("left", "right"))
        ]

        def count(items):
            return sum(r["count"] for r in items)

        outcomes, labels = {}, {}
        for side in ("left", "right"):
            outcomes[side], labels[side] = Counter(), Counter()
            for row in matched:
                outcomes[side][row[side + "_outcome"] or "not_indexed"] += row["count"]
            for row in valid:
                labels[side][str(row[side + "_label"])] += row["count"]
        result.append(
            dict(
                source=source,
                matched=count(matched),
                union=count(group),
                valid=count(valid),
                different=count([r for r in valid if r["left_label"] != r["right_label"]]),
                known=count(known),
                outcomes=outcomes,
                labels=labels,
                truncated={
                    s: count([r for r in known if r[s + "_truncated"] == 1])
                    for s in ("left", "right")
                },
            )
        )
    return result


def metric(row, key):
    """Numerators and common denominator, never a zero for missing evidence."""
    if key in {"usable", "missing", "policy"}:
        return row["outcomes"]["left"][key], row["outcomes"]["right"][key], row["matched"]
    if key == "truncated":
        return row["truncated"]["left"], row["truncated"]["right"], row["known"]
    label = key.removeprefix("label:")
    return row["labels"]["left"][label], row["labels"]["right"][label], row["valid"]


def _t(message):
    return html.escape(message, quote=True)


def _name(source):
    return " / ".join(source)


STYLE = """<style>
.comparison-insights{--insight-left:#087e8b;--insight-right:#ad4c16;margin:1.5rem 0;min-width:0;overflow-wrap:anywhere}
.insight-heading{display:flex;align-items:baseline;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.insight-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,170px),1fr));gap:.8rem;margin:1rem 0}
.insight-kpi{padding:1rem;border:1px solid var(--line);border-radius:12px;background:var(--soft)}
.insight-kpi strong{display:block;font-size:1.65rem;font-variant-numeric:tabular-nums;color:var(--ink)}
.insight-kpi span{display:block;margin-top:.4rem;color:var(--muted)}
.insight-scroll{overflow:auto;border:1px solid var(--line);border-radius:12px;margin:1rem 0;max-height:660px}
.insight-heatmap{border-collapse:separate;border-spacing:4px;width:100%;font-variant-numeric:tabular-nums}
.insight-heatmap th{background:var(--card,var(--bg));text-align:left;vertical-align:bottom;min-width:190px;max-width:250px;font-weight:500;text-transform:none;letter-spacing:normal;font-size:.85rem;line-height:1.4}
.insight-heatmap thead th{position:sticky;top:0;z-index:2}
.insight-heatmap tbody th{position:sticky;left:0;z-index:1}
.insight-heatmap thead th:first-child{left:0;z-index:3}
.insight-heatmap td{min-width:120px;text-align:center;padding:.8rem;border-radius:7px;color:var(--ink)}
.insight-heatmap td strong,.insight-heatmap td small{display:block}
.insight-heatmap td small{margin-top:.3rem}
.insight-heatmap td[data-direction='left']{background:color-mix(in srgb,var(--insight-left) var(--shade),var(--bg))}
.insight-heatmap td[data-direction='right']{background:color-mix(in srgb,var(--insight-right) var(--shade),var(--bg))}
.insight-heatmap td[data-direction='equal']{background:var(--soft)}
.insight-heatmap td[data-direction='unknown']{background:repeating-linear-gradient(135deg,var(--soft),var(--soft) 5px,var(--bg) 5px,var(--bg) 10px)}
.insight-controls{display:flex;align-items:end;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.insight-controls label{display:grid;gap:.4rem;min-width:0;max-width:100%}
.insight-controls select{max-width:100%}
.insight-panel[hidden]{display:none}
.insight-plot{display:block;width:100%;min-width:1120px;height:auto}
.insight-legend{display:flex;gap:1rem;flex-wrap:wrap;margin:.6rem 0}
.insight-legend span{display:inline-flex;gap:.5rem;align-items:center}
.insight-dot{display:inline-block;width:.8rem;height:.8rem;background:var(--insight-left);border-radius:50%}
.insight-dot.right{background:var(--insight-right);border-radius:0}
</style>"""


def overview(pairs):
    """Page-scoped heatmap, one cell per condition pair and source task."""
    if not pairs:
        return ""
    summaries = [summarize(p["rows"]) for p in pairs]
    sources = sorted({r["source"] for group in summaries for r in group})
    if not sources:
        return ""
    lookups = [{r["source"]: r for r in group} for group in summaries]
    result = STYLE + '<section class="comparison-insights" data-insight-overview data-insight-root>'
    result += (
        "<h3>"
        + _t(_ui_text("comparison_insights.overview_title"))
        + "</h3><p>"
        + _t(_ui_text("comparison_insights.overview_note"))
        + "</p>"
    )
    metrics = measures([r for group in summaries for r in group])
    if any(key == "label:violation" for key, title in metrics):
        metrics.sort(key=lambda pair: pair[0] != "label:violation")
    result += (
        '<div class="insight-controls"><label>'
        + _t(_ui_text("comparison_insights.metric"))
        + "<select data-insight-metric>"
    )
    result += "".join(
        '<option value="' + html.escape(key, quote=True) + '">' + html.escape(title) + "</option>"
        for key, title in metrics
    )
    result += "</select></label></div>"
    result += '<div class="insight-legend"><span><i class="insight-dot"></i>' + _t(
        _ui_text("comparison_insights.left_higher")
    )
    result += (
        '</span><span><i class="insight-dot right"></i>'
        + _t(_ui_text("comparison_insights.right_higher"))
        + "</span></div>"
    )
    for index, (key, caption) in enumerate(metrics):
        result += (
            '<div class="insight-panel" data-insight-panel="'
            + html.escape(key, quote=True)
            + '"'
            + (" hidden" if index else "")
            + "><p>"
            + _t(denominator(key))
            + "</p>"
        )
        result += (
            '<div class="insight-scroll" tabindex="0" role="region" aria-label="'
            + html.escape(caption, quote=True)
            + '"><table class="insight-heatmap"><thead><tr><th scope="col">'
            + _t(_ui_text("comparison_insights.source"))
            + "</th>"
        )
        for pair in pairs:
            result += (
                '<th scope="col" title="'
                + html.escape(pair["title"], quote=True)
                + '">'
                + html.escape(pair.get("short_title", pair["title"]))
                + "</th>"
            )
        result += "</tr></thead><tbody>"
        for source in sources:
            result += '<tr><th scope="row">' + html.escape(_name(source)) + "</th>"
            for lookup in lookups:
                row = lookup.get(source)
                a, b, n = metric(row, key) if row else (0, 0, 0)
                gap = 100 * (b - a) / n if n else None
                direction = (
                    "unknown"
                    if gap is None
                    else "right"
                    if gap > 0
                    else "left"
                    if gap < 0
                    else "equal"
                )
                title = (
                    _t(_ui_text("comparison_insights.yield_detail", left=a, right=b, n=n))
                    if n
                    else _t(_ui_text("comparison_insights.no_match"))
                )
                result += f'<td data-direction="{direction}" data-left="{a}" data-right="{b}" data-n="{n}" style="--shade:{12 + min(abs(gap or 0), 100) * 0.35:.1f}%" title="{title}">'
                result += (
                    "<strong>"
                    + (
                        _t(_ui_text("comparison_insights.gap", value=f"{gap:+.1f}"))
                        if n
                        else _t(_ui_text("comparison_insights.not_available"))
                    )
                    + "</strong>"
                )
                result += (
                    "<small>"
                    + (
                        _t(_ui_text("comparison_insights.matched_n", n=f"{n:,}"))
                        if n
                        else _t(_ui_text("comparison_insights.no_match"))
                    )
                    + "</small></td>"
                )
            result += "</tr>"
        result += "</tbody></table></div></div>"
    return (
        result
        + '<p class="note">'
        + _t(_ui_text("comparison_insights.overview_scope"))
        + "</p></section>"
    )


def measures(groups):
    labels = sorted(
        {label for row in groups for side in ("left", "right") for label in row["labels"][side]}
    )
    return [
        ("usable", _ui_text("comparison_insights.usable_title")),
        ("missing", _ui_text("comparison_insights.missing_title")),
        ("policy", _ui_text("comparison_insights.policy_title")),
        ("truncated", _ui_text("comparison_insights.truncation_title")),
    ] + [
        ("label:" + label, _ui_text("comparison_insights.label_title", label=label))
        for label in labels
    ]


def denominator(key):
    if key == "truncated":
        return _ui_text("comparison_insights.truncation_denominator")
    if key.startswith("label:"):
        return _ui_text("comparison_insights.label_denominator")
    return _ui_text("comparison_insights.outcome_denominator")


def plot_svg(rows, key, *, title, left_name, right_name, context=None):
    """Readable, standalone vector figure with paired rates and exact counts."""
    description = (
        _ui_text("comparison_insights.figure_scope", left=left_name, right=right_name)
        + " "
        + denominator(key)
    )
    notes = textwrap.wrap(description, width=140)
    shift = 18 * len(notes)
    width, height = 1120, 165 + shift + len(rows) * 74
    x0, span = 385, 375
    esc = html.escape
    marks = []

    def text(x, y, value, **attrs):
        attr = " ".join(
            k.replace("_", "-") + '="' + esc(str(v), quote=True) + '"' for k, v in attrs.items()
        )
        return f'<text x="{x}" y="{y}" {attr}>{esc(str(value))}</text>'

    marks.append(text(20, 27, title, font_size=19, font_weight=600))
    # Exact identities live in the accessible description; wrapped HTML captions
    # above the figure remain readable at every viewport width.
    desc = description
    for i, line in enumerate(notes):
        marks.append(text(20, 74 + 18 * i, line, font_size=12))
    marks.append(text(20, 52, _ui_text("comparison_insights.figure_hint")))
    marks.append(text(20, 86 + shift, _ui_text("comparison_insights.source")))
    marks.append(text(795, 86 + shift, _ui_text("comparison_insights.counts_header")))
    for tick in (0, 25, 50, 75, 100):
        x = x0 + span * tick / 100
        marks.append(
            f'<line x1="{x}" y1="{102 + shift}" x2="{x}" y2="{height - 42}" stroke="#d5dbe4"/>'
        )
        marks.append(text(x, 86 + shift, f"{tick}%", text_anchor="middle"))
    for i, row in enumerate(rows):
        y = 131 + shift + i * 74
        source = _name(row["source"])
        a, b, n = metric(row, key)
        marks.append(
            f'<g data-source="{esc(source, quote=True)}" data-left="{a}" data-right="{b}" data-n="{n}"><title>{esc(source)}</title>'
        )
        corpus, framework, modality = row["source"]
        marks.append(text(20, y - 4, corpus[:43] + ("..." if len(corpus) > 43 else "")))
        task = framework + " / " + modality
        marks.append(
            text(
                20,
                y + 16,
                task[:46] + ("..." if len(task) > 46 else ""),
                fill="#526176",
                font_size=12,
            )
        )
        if n:
            ax, bx = x0 + span * a / n, x0 + span * b / n
            marks.append(
                f'<line x1="{ax:.3f}" y1="{y}" x2="{bx:.3f}" y2="{y}" stroke="#8090a8" stroke-width="3"/>'
            )
            marks.append(f'<circle cx="{ax:.3f}" cy="{y}" r="6" fill="#087e8b"/>')
            marks.append(
                f'<rect x="{bx - 5:.3f}" y="{y - 5}" width="10" height="10" fill="#ad4c16"/>'
            )
            counts = _ui_text("comparison_insights.counts", left=f"{a}/{n}", right=f"{b}/{n}")
            marks.append(text(795, y - 4, counts))
            marks.append(
                text(
                    795,
                    y + 16,
                    _ui_text(
                        "comparison_insights.rates",
                        left=f"{100 * a / n:.1f}",
                        right=f"{100 * b / n:.1f}",
                        gap=f"{100 * (b - a) / n:+.1f}",
                    ),
                    font_size=12,
                )
            )
        else:
            marks.append(
                text(x0, y + 4, _ui_text("comparison_insights.not_estimable"), fill="#526176")
            )
        marks.append("</g>")
    marks.append(text(20, height - 13, _ui_text("comparison_insights.figure_footer"), font_size=12))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" class="insight-plot" role="img" aria-label="{esc(title, quote=True)}" viewBox="0 0 {width} {height}">'
        + "<title>"
        + esc(title)
        + "</title><desc>"
        + esc(desc)
        + "</desc>"
        + "<metadata>"
        + esc(json.dumps(dict(measure=key, selection=context or {}), sort_keys=True))
        + "</metadata>"
        + '<rect width="100%" height="100%" fill="#ffffff"/>'
        + '<g fill="#192c40" font-family="system-ui,sans-serif" font-size="14">'
        + "".join(marks)
        + "</g></svg>"
    )


def detail(rows, *, left_name="", right_name="", context=None):
    groups = summarize(rows)
    if not groups:
        return ""
    matched = sum(r["matched"] for r in groups)
    valid = sum(r["valid"] for r in groups)
    different = sum(r["different"] for r in groups)
    result = (
        STYLE
        + '<section class="comparison-insights" data-insight-detail data-insight-root><h3>'
        + _t(_ui_text("comparison_insights.detail_title"))
        + "</h3>"
    )
    result += '<div class="insight-kpis">'
    for value, label in (
        (matched, _ui_text("comparison_insights.matched_tasks")),
        (valid, _ui_text("comparison_insights.paired_labels")),
        (different, _ui_text("comparison_insights.different_labels")),
        (matched - valid, _ui_text("comparison_insights.unscored_pairs")),
    ):
        result += (
            '<div class="insight-kpi"><strong>'
            + f"{value:,}"
            + "</strong><span>"
            + _t(label)
            + "</span></div>"
        )
    result += (
        "</div><details><summary>"
        + _t(_ui_text("comparison_insights.method"))
        + "</summary><p>"
        + _t(_ui_text("comparison_insights.detail_note"))
        + "</p></details>"
    )
    metrics = measures(groups)
    result += (
        '<div class="insight-controls"><label>'
        + _t(_ui_text("comparison_insights.metric"))
        + "<select data-insight-metric>"
    )
    result += "".join(
        '<option value="' + html.escape(key, quote=True) + '">' + html.escape(title) + "</option>"
        for key, title in metrics
    )
    result += (
        '</select></label><button type="button" class="ghost" data-insight-download>'
        + _t(_ui_text("comparison_insights.download_svg"))
        + "</button></div>"
    )
    result += (
        '<div class="insight-legend"><span><i class="insight-dot"></i>'
        + _t(_ui_text("comparison_insights.left_named", name=left_name))
        + '</span><span><i class="insight-dot right"></i>'
        + _t(_ui_text("comparison_insights.right_named", name=right_name))
        + "</span></div>"
    )
    for index, (key, title) in enumerate(metrics):
        note = (
            _ui_text("comparison_insights.usable_note")
            if key in {"usable", "missing", "policy"}
            else _ui_text("comparison_insights.truncation_note")
            if key == "truncated"
            else _ui_text("comparison_insights.label_note")
        )
        result += (
            '<div class="insight-panel" data-insight-panel="'
            + html.escape(key, quote=True)
            + '"'
            + (" hidden" if index else "")
            + "><p>"
            + _t(denominator(key))
            + "</p>"
        )
        result += (
            '<div class="insight-scroll" tabindex="0" role="region" aria-label="'
            + html.escape(title, quote=True)
            + '">'
        )
        result += (
            plot_svg(
                groups,
                key,
                title=title,
                left_name=left_name,
                right_name=right_name,
                context=context,
            )
            + "</div><details><summary>"
            + _t(_ui_text("comparison_insights.measure_note"))
            + "</summary><p>"
            + _t(note)
            + "</p></details></div>"
        )
    return result + '<p role="status" data-insight-status></p></section>'


SCRIPT = _ui_template("""<script>(()=>{
if(window.uraComparisonInsightsBound)return;window.uraComparisonInsightsBound=true;
document.addEventListener('change',event=>{
if(!event.target.matches('[data-insight-metric]'))return;
const root=event.target.closest('[data-insight-root]');
root.querySelectorAll('[data-insight-panel]').forEach(p=>p.hidden=p.dataset.insightPanel!==event.target.value);
});
document.addEventListener('click',event=>{
const button=event.target.closest('[data-insight-download]');if(!button)return;
const root=button.closest('[data-insight-detail]'),status=root.querySelector('[data-insight-status]');
try{
const svg=root.querySelector('[data-insight-panel]:not([hidden]) svg').cloneNode(true);
svg.removeAttribute('class');svg.setAttribute('width',svg.viewBox.baseVal.width);svg.setAttribute('height',svg.viewBox.baseVal.height);
const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(svg)],{type:'image/svg+xml;charset=utf-8'}));
const a=document.createElement('a');a.href=url;a.download='paired-comparison.svg';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
status.textContent=[[js:comparison_insights.download_ready]];
}catch(error){status.textContent=[[js:comparison_insights.download_failed]];}
});})();</script>""")
