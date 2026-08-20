"""URA-Bench reporting layer - the one-page risk card (thesis III.2.4, V.1).

Turns aggregated :class:`~ura.data_models.EvalResult` records into a compact,
human-readable *risk card*: a per-model, per-risk-category roll-up that pairs
the safety axis (ASR / StrongREJECT severity) against the utility axis
(over-refusal), so a reviewer can read the safety-utility trade-off at a glance
and follow an informational standards crosswalk (OWASP / NIST / MLCommons).
The crosswalk is not a certification or compliance determination.

Pure Python + standard library only. ``risk_card`` emits GitHub-flavoured
Markdown; ``to_html`` renders a list of cards into a single self-contained HTML
page (no external CSS/JS/fonts), suitable for archival next to a RunManifest.
"""
from __future__ import annotations

import datetime as _dt
import html as _html
import re as _re

from .data_models import EvalResult, RiskCategory
from .taxonomy import EU_AI_ACT_SYSTEMIC_RISKS, TAXONOMY_MAP

# --------------------------------------------------------------------------- #
# Grouping / classification helpers
# --------------------------------------------------------------------------- #

# group_by keys under which the risk category may be recorded (most specific
# first). Kept liberal so the card survives minor producer variations.
_RISK_KEYS = ("risk", "risk_category", "category", "risk_cat")
_MODEL_KEYS = ("model", "model_id", "target")

# Substrings that identify the two axes of the safety-utility pair.
_SAFETY_METRICS = ("asr", "attack_success", "strongreject", "isr", "injection")
_UTILITY_METRICS = ("frr", "over_refusal", "over-refusal", "overrefusal")

# A metric name containing this marks a live, response-conditioned (multi-turn)
# estimand, whose population differs from the static single-turn safety metrics.
_LIVE_MARK = "conversation"

# Sentinel rendered when a value or CI is absent (an em dash, escaped).
_ABSENT = "\u2014"

_UNGROUPED = "overall"


def _risk_of(result: EvalResult) -> str:
    """Extract the risk-category label for a result, or ``"overall"``."""
    for key in _RISK_KEYS:
        val = result.group_by.get(key)
        if val:
            return str(val)
    return _UNGROUPED


def _as_category(label: str) -> RiskCategory | None:
    """Best-effort map a group label back to a :class:`RiskCategory`."""
    try:
        return RiskCategory(label)
    except ValueError:
        for cat in RiskCategory:
            if cat.name.lower() == label.lower():
                return cat
        return None


def _is_metric(metric: str, needles: tuple[str, ...]) -> bool:
    m = metric.lower()
    return any(n in m for n in needles)


def _fmt_num(value: float | None) -> str:
    """Render a metric value with three decimals, or an em dash if absent."""
    if value is None:
        return "\u2014"
    return f"{value:.3f}"


def _fmt_ci(result: EvalResult) -> str:
    """Render a ``lo..hi`` confidence interval, or an em dash if absent."""
    if result.ci_low is None or result.ci_high is None:
        return "\u2014"
    return f"{result.ci_low:.3f}..{result.ci_high:.3f}"


def _approximate_provenance(result: EvalResult) -> dict | None:
    value = result.provenance.get("approximate_security")
    return value if isinstance(value, dict) else None


def _is_synthetic(result: EvalResult) -> bool:
    return result.provenance.get("evidence_class") == "synthetic"


def _evidence_tag(result: EvalResult) -> str:
    proxy = _approximate_provenance(result)
    if proxy is not None:
        if proxy.get("warning_tag") == "warning_synthetic_approximate":
            return "**⚠ synthetic + approximate**"
        return "**⚠ approximate**"
    if _is_synthetic(result):
        return "**⚠ synthetic (offline smoke, not measured)**"
    return "authoritative/source-native"


def _reliability_label(result: EvalResult) -> str:
    proxy = _approximate_provenance(result)
    if proxy is None:
        return _ABSENT
    value = proxy.get("reliability_score")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{float(value):.3f} heuristic (not probability)"
    return _ABSENT


def _taxonomy_line(category: RiskCategory) -> str:
    """Flatten the standards mapping for one category into a compact string."""
    parts: list[str] = []
    for standard, ids in TAXONOMY_MAP.get(category, {}).items():
        if ids:
            parts.append(f"{standard}: {', '.join(ids)}")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Markdown risk card
# --------------------------------------------------------------------------- #

def risk_card(
    results: list[EvalResult], model_id: str, *, include_untagged: bool | None = None
) -> str:
    """Render a one-page Markdown risk card for ``model_id``.

    Results are grouped by risk category (via ``EvalResult.group_by``); each
    group lists its metrics with value, 95% CI (``ci_low..ci_high``) and ``n``,
    then the safety axes (kept separate for static single-turn vs live multi-turn
    estimands) and the utility axis, each metric rendered under its own name, and
    finally the external-standard taxonomy references.

    Model scoping is explicit: a result carrying a model tag contributes only to
    the matching model's card. Untagged results are treated as this model's only
    when the whole ``results`` set carries no model tag (a single-model run whose
    aggregate grouping omits the model key); when any result is model-tagged,
    untagged results are ambiguous and excluded, so one model's numbers can never
    be silently attributed to every model. Pass ``include_untagged`` to override.
    """
    tagged_models = {tag for tag in (_model_tag(r) for r in results) if tag is not None}
    if include_untagged is None:
        include_untagged = not tagged_models
    scoped: list[EvalResult] = []
    for r in results:
        tag = _model_tag(r)
        if tag is None:
            if include_untagged:
                scoped.append(r)
        elif tag == model_id:
            scoped.append(r)
    generated = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append(f"# Risk Card \u2014 {model_id}")
    lines.append("")
    lines.append(f"_Generated {generated} \u00b7 {len(scoped)} aggregated metric(s)_")
    lines.append("")

    if not scoped:
        lines.append("> No evaluation results available for this model.")
        lines.append("")
        return "\n".join(lines)

    if any(_is_synthetic(result) for result in scoped):
        lines.append(
            "> ⚠ This card includes synthetic offline-smoke results (MockTarget "
            "and/or mock judge). They exercise the pipeline only and are NOT "
            "measured evidence; do not read them as a model's real safety profile."
        )
        lines.append("")

    if any(_approximate_provenance(result) is not None for result in scoped):
        lines.append(
            "> ⚠ Approximate metrics are supplementary response-proxy estimates, "
            "not authoritative or source-native verdicts. Their reliability "
            "indicator is an uncalibrated heuristic, not probability or accuracy."
        )
        lines.append("")

    # Deterministic category order: known taxonomy order first, then extras.
    groups = _group_by_risk(scoped)
    for label in _ordered_labels(groups):
        group = groups[label]
        category = _as_category(label)
        heading = category.value if category else label
        lines.append(f"## {heading}")
        lines.append("")

        # Metric table.
        lines.append("| Metric | Evidence | Reliability | Value | 95% CI | n |")
        lines.append("| --- | --- | --- | ---: | :---: | ---: |")
        for r in sorted(group, key=lambda x: x.metric.lower()):
            lines.append(
                f"| {r.metric} | {_evidence_tag(r)} | {_reliability_label(r)} | "
                f"{_fmt_num(r.value)} | {_fmt_ci(r)} | {r.n} |"
            )
        lines.append("")

        # Safety and utility axes: render every estimand under its own metric
        # name (no first-substring collapse), keeping static single-turn and live
        # multi-turn safety estimands separate because their populations differ.
        safety = _axis_metrics(group, _SAFETY_METRICS)
        static_safety = [r for r in safety if _LIVE_MARK not in r.metric.lower()]
        live_safety = [r for r in safety if _LIVE_MARK in r.metric.lower()]
        utility = _axis_metrics(group, _UTILITY_METRICS)
        if static_safety:
            lines.append(
                "**Safety (static, single-turn):** "
                + "; ".join(_metric_span(r) for r in static_safety)
            )
            lines.append("")
        if live_safety:
            lines.append(
                "**Safety (live, multi-turn):** "
                + "; ".join(_metric_span(r) for r in live_safety)
            )
            lines.append("")
        if utility:
            lines.append(
                "**Utility (over-refusal):** "
                + "; ".join(_metric_span(r) for r in utility)
            )
            lines.append("")

        # Informational standards crosswalk (not a compliance determination).
        if category:
            tax = _taxonomy_line(category)
            if tax:
                lines.append(f"_Informational standards crosswalk (not compliance):_ {tax}")
                lines.append("")

    # Informational systemic-risk lenses footer.
    lines.append("---")
    lines.append("")
    lines.append(
        "_Informational EU AI Act systemic-risk lenses (not legal compliance): "
        + ", ".join(EU_AI_ACT_SYSTEMIC_RISKS)
        + "._"
    )
    lines.append("")
    return "\n".join(lines)


def _model_tag(result: EvalResult) -> str | None:
    """The model this result is scoped to, or ``None`` if it carries no model tag."""
    for key in _MODEL_KEYS:
        val = result.group_by.get(key)
        if val:
            return str(val)
    return None


def _metric_span(result: EvalResult) -> str:
    """Render one metric under its real name with CI and, where known, population."""
    ci = _fmt_ci(result)
    ci_part = f" (CI {ci})" if ci != _ABSENT else ""
    pop = result.provenance.get("population") or result.provenance.get("estimand")
    pop_part = f" [{pop}]" if pop else ""
    return f"{result.metric} `{_fmt_num(result.value)}`{ci_part}{pop_part}"


def _group_by_risk(results: list[EvalResult]) -> dict[str, list[EvalResult]]:
    groups: dict[str, list[EvalResult]] = {}
    for r in results:
        groups.setdefault(_risk_of(r), []).append(r)
    return groups


def _ordered_labels(groups: dict[str, list[EvalResult]]) -> list[str]:
    """Order categories by the canonical taxonomy, appending unknown labels."""
    canonical = [c.value for c in RiskCategory]
    known = [lbl for lbl in canonical if lbl in groups]
    extra = sorted(lbl for lbl in groups if lbl not in canonical)
    return known + extra


def _axis_metrics(
    group: list[EvalResult], needles: tuple[str, ...]
) -> list[EvalResult]:
    """All results in ``group`` whose metric name matches ``needles`` (name-sorted)."""
    return [
        r for r in sorted(group, key=lambda x: x.metric.lower())
        if _is_metric(r.metric, needles)
    ]


# --------------------------------------------------------------------------- #
# HTML rendering (self-contained, no external assets)
# --------------------------------------------------------------------------- #

_HTML_STYLE = """
:root { color-scheme: light dark; }
body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
       Helvetica, Arial, sans-serif; margin: 0; padding: 2rem;
       background: #ffffff; color: #14181f; }
main { max-width: 60rem; margin: 0 auto; }
.card { border: 1px solid #d8dee6; border-radius: 10px; padding: 1.25rem 1.5rem;
        margin: 0 0 1.75rem; background: #fbfcfe; }
h1 { font-size: 1.5rem; margin: 0 0 .5rem; }
h2 { font-size: 1.1rem; margin: 1.25rem 0 .5rem; border-bottom: 1px solid #e6eaef;
     padding-bottom: .2rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem;
        font-variant-numeric: tabular-nums; }
th, td { border: 1px solid #d8dee6; padding: .35rem .6rem; text-align: left; }
th { background: #eef2f7; }
td.num, th.num { text-align: right; }
code { background: #eef2f7; padding: .05rem .35rem; border-radius: 4px;
       font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
hr { border: 0; border-top: 1px solid #e6eaef; margin: 1rem 0; }
em { color: #4a5566; }
@media (prefers-color-scheme: dark) {
  body { background: #0f1216; color: #e6eaef; }
  .card { border-color: #2b323c; background: #161a20; }
  h2 { border-color: #2b323c; }
  th, td { border-color: #2b323c; }
  th { background: #1d232b; }
  code, hr { background: #1d232b; }
  hr { border-top-color: #2b323c; }
  em { color: #9aa6b2; }
}
""".strip()


def to_html(cards: list[str]) -> str:
    """Wrap Markdown risk ``cards`` in one self-contained HTML page.

    The generated page embeds its own stylesheet and references no external
    assets, so it renders identically offline and can be archived alongside the
    run manifest. Each card is rendered from the Markdown subset that
    :func:`risk_card` produces (headings, tables, rules, emphasis).
    """
    body = "\n".join(
        f'<section class="card">\n{_markdown_to_html(card)}\n</section>'
        for card in cards
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>URA-Bench Risk Cards</title>\n"
        f"<style>\n{_HTML_STYLE}\n</style>\n"
        "</head>\n<body>\n<main>\n"
        f"{body}\n"
        "</main>\n</body>\n</html>\n"
    )


# --------------------------------------------------------------------------- #
# Minimal Markdown -> HTML converter (only the subset risk_card emits)
# --------------------------------------------------------------------------- #

_BOLD = _re.compile(r"\*\*(.+?)\*\*")
_ITALIC = _re.compile(r"(?<!\w)_(.+?)_(?!\w)")
_CODE = _re.compile(r"`([^`]+?)`")
_HEADING = _re.compile(r"^(#{1,6})\s+(.*)$")


def _inline(text: str) -> str:
    """Escape then apply inline code/bold/italic spans."""
    # Protect inline code first so its contents are not further formatted.
    tokens: list[str] = []

    def _stash(match: _re.Match[str]) -> str:
        tokens.append(match.group(1))
        return f"\x00{len(tokens) - 1}\x00"

    staged = _CODE.sub(_stash, text)
    staged = _html.escape(staged, quote=False)
    staged = _BOLD.sub(r"<strong>\1</strong>", staged)
    staged = _ITALIC.sub(r"<em>\1</em>", staged)

    def _restore(match: _re.Match[str]) -> str:
        code = _html.escape(tokens[int(match.group(1))], quote=False)
        return f"<code>{code}</code>"

    return _re.sub(r"\x00(\d+)\x00", _restore, staged)


def _render_table(rows: list[str]) -> str:
    """Render a GitHub pipe-table (header row, separator row, body rows)."""
    def _cells(line: str) -> list[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header = _cells(rows[0])
    aligns = _cells(rows[1])

    def _css(spec: str) -> str:
        spec = spec.strip()
        if spec.endswith(":") and spec.startswith(":"):
            return ' style="text-align:center"'
        if spec.endswith(":"):
            return ' style="text-align:right"'
        return ""

    css = [_css(a) for a in aligns] + [""] * (len(header) - len(aligns))
    out = ["<table>", "<thead>", "<tr>"]
    out += [f"<th{css[i]}>{_inline(h)}</th>" for i, h in enumerate(header)]
    out += ["</tr>", "</thead>", "<tbody>"]
    for line in rows[2:]:
        cells = _cells(line)
        out.append("<tr>")
        out += [
            f"<td{css[i] if i < len(css) else ''}>{_inline(c)}</td>"
            for i, c in enumerate(cells)
        ]
        out.append("</tr>")
    out += ["</tbody>", "</table>"]
    return "\n".join(out)


def _markdown_to_html(md: str) -> str:
    """Convert the Markdown subset emitted by :func:`risk_card` to HTML."""
    lines = md.splitlines()
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "---":
            out.append("<hr>")
            i += 1
            continue

        heading = _HEADING.match(stripped)
        if heading:
            level = len(heading.group(1))
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            i += 1
            continue

        # Table: a pipe line followed by a separator line of dashes/colons.
        if (
            stripped.startswith("|")
            and i + 1 < n
            and _re.fullmatch(r"\|[\s:\-|]+\|", lines[i + 1].strip())
        ):
            block = [lines[i], lines[i + 1]]
            j = i + 2
            while j < n and lines[j].strip().startswith("|"):
                block.append(lines[j])
                j += 1
            out.append(_render_table(block))
            i = j
            continue

        if stripped.startswith(">"):
            out.append(f"<blockquote>{_inline(stripped[1:].strip())}</blockquote>")
            i += 1
            continue

        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    return "\n".join(out)


__all__ = ["risk_card", "to_html"]
