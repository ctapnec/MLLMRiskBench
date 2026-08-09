"""URA-Bench reporting layer — the one-page risk card (thesis III.2.4, V.1).

Turns aggregated :class:`~ura.data_models.EvalResult` records into a compact,
human-readable *risk card*: a per-model, per-risk-category roll-up that pairs
the safety axis (ASR / StrongREJECT severity) against the utility axis
(over-refusal), so a reviewer can read the safety–utility trade-off at a glance
and follow the standards taxonomy (OWASP / NIST / MLCommons) roll-up.

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

# Substrings that identify the two axes of the safety–utility pair.
_SAFETY_METRICS = ("asr", "attack_success", "strongreject", "isr", "injection")
_UTILITY_METRICS = ("frr", "over_refusal", "over-refusal", "overrefusal")

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

def risk_card(results: list[EvalResult], model_id: str) -> str:
    """Render a one-page Markdown risk card for ``model_id``.

    Results are grouped by risk category (via ``EvalResult.group_by``); each
    group lists its metrics with value, 95% CI (``ci_low..ci_high``) and ``n``,
    followed by the safety–utility pair (ASR vs over-refusal) and, where known,
    the external-standard taxonomy references. Results whose group targets a
    different model are ignored so a shared result list can hold many models.
    """
    scoped = [r for r in results if _belongs_to_model(r, model_id)]
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

    # Deterministic category order: known taxonomy order first, then extras.
    groups = _group_by_risk(scoped)
    for label in _ordered_labels(groups):
        group = groups[label]
        category = _as_category(label)
        heading = category.value if category else label
        lines.append(f"## {heading}")
        lines.append("")

        # Metric table.
        lines.append("| Metric | Value | 95% CI | n |")
        lines.append("| --- | ---: | :---: | ---: |")
        for r in sorted(group, key=lambda x: x.metric.lower()):
            lines.append(
                f"| {r.metric} | {_fmt_num(r.value)} | {_fmt_ci(r)} | {r.n} |"
            )
        lines.append("")

        # Safety–utility pair.
        safety = _pick(group, _SAFETY_METRICS)
        utility = _pick(group, _UTILITY_METRICS)
        lines.append(
            "**Safety \u2013 utility:** "
            f"attack success `{_fmt_num(safety.value if safety else None)}` "
            "vs. over-refusal "
            f"`{_fmt_num(utility.value if utility else None)}`"
        )
        lines.append("")

        # Standards roll-up.
        if category:
            tax = _taxonomy_line(category)
            if tax:
                lines.append(f"_Standards:_ {tax}")
                lines.append("")

    # Frontier / systemic-risk footer.
    lines.append("---")
    lines.append("")
    lines.append(
        "_EU AI Act systemic-risk lenses: "
        + ", ".join(EU_AI_ACT_SYSTEMIC_RISKS)
        + "._"
    )
    lines.append("")
    return "\n".join(lines)


def _belongs_to_model(result: EvalResult, model_id: str) -> bool:
    """True if the result targets ``model_id`` (or carries no model tag)."""
    for key in _MODEL_KEYS:
        val = result.group_by.get(key)
        if val:
            return str(val) == model_id
    return True


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


def _pick(group: list[EvalResult], needles: tuple[str, ...]) -> EvalResult | None:
    """First result in ``group`` whose metric name matches one of ``needles``."""
    for r in group:
        if _is_metric(r.metric, needles):
            return r
    return None


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
