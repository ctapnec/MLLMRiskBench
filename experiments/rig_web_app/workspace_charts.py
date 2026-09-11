"""Directly labeled campaign figures and the exact numeric table behind them."""

from __future__ import annotations

import csv
import html
import io
from collections.abc import Mapping, Sequence


OUTCOMES = (("usable", "Usable", "U"), ("policy", "Policy outcome", "P"),
            ("missing", "Missing", "M"), ("retry_pending", "Retry pending", "R"),
            ("pending", "No retained outcome", "N"))
SERIES = tuple(f"var(--viz-series-{i},var(--{token}))" for i, token in enumerate(
    ("m-image", "m-text", "m-audio", "m-video", "muted"), 1))
CHART_STYLE = """
.campaign-figure { width:100%; height:auto; color:var(--ink); font-family:system-ui,sans-serif; }
.campaign-figure text { fill:currentColor; font-size:var(--font-size-base,14px); font-weight:400; }
.campaign-figure .chart-grid { stroke:var(--line); stroke-width:1; }
.campaign-figure .chart-track { fill:var(--soft); }
.campaign-figure .chart-value { font-weight:500; }
"""


def _count(row: Mapping, key: str) -> int:
    value = row[key]
    if value is None and key != "assigned":
        return 0  # SQL SUM over an empty matching outcome category
    if type(value) is not int or value < 0:
        raise ValueError("Chart counts must be nonnegative integers")
    return value


def coverage_svg(rows: Sequence[Mapping], *, title: str, scope: str) -> str:
    """Shared 0-100% scale; count and denominator stay visible for every model."""
    width, left, span = 920, 24, 700
    height = 144 + 90 * len(rows)
    marks = []
    for index, row in enumerate(rows):
        n = _count(row, "assigned")
        counts = [_count(row, key) for key, _label, _code in OUTCOMES]
        if sum(counts) != n:
            raise ValueError("Coverage categories do not reconcile to assigned inputs")
        model = str(row["model"])
        display = model.partition(";")[0]
        y = 72 + index * 90
        # Long exact identities remain in the accessible description and table;
        # this display abbreviation never changes grouping or identity.
        display = display if len(display) <= 78 else display[:75] + "..."
        marks.append(
            f"<text x='{left}' y='{y}'>{html.escape(display)} / {html.escape(str(row['evidence_class']))}</text>"
            f"<text class='chart-value' x='896' y='{y}' text-anchor='end'>n={n:,}</text>"
            f"<rect class='chart-track' x='{left}' y='{y + 12}' width='{span}' height='20'/>"
        )
        start = 0
        for value, (key, label, code), color in zip(counts, OUTCOMES, SERIES, strict=True):
            part = span * value / n if n else 0
            if value:
                description = f"{model}: {label}, {value} of {n} ({100 * value / n:.1f}%)"
                marks.append(
                    f"<rect data-category='{key}' data-count='{value}' x='{left + start:.3f}' y='{y + 12}' "
                    f"width='{part:.3f}' height='20' style='fill:{color}'><title>{html.escape(description)}</title></rect>"
                )
                if part >= 42:
                    marks.append(f"<text x='{left + start + part / 2:.3f}' y='{y + 49}' text-anchor='middle'>{code}: {value:,}</text>")
            start += part
        marks.append(f"<text x='750' y='{y + 28}'>retained {n - counts[-1]:,}/{n:,}</text>")
    axis_y = height - 43
    ticks = "".join(
        f"<line class='chart-grid' x1='{left + span * fraction / 100}' y1='{axis_y - 8}' "
        f"x2='{left + span * fraction / 100}' y2='{axis_y - 3}'/>"
        f"<text x='{left + span * fraction / 100}' y='{axis_y + 12}' text-anchor='middle'>{fraction}%</text>"
        for fraction in (0, 25, 50, 75, 100)
    )
    legend = "".join(
        f"<rect x='{24 + index * 180}' y='22' width='10' height='10' style='fill:{color}'/>"
        f"<text x='{40 + index * 180}' y='32'>{code}: {html.escape(label)}</text>"
        for index, ((_key, label, code), color) in enumerate(zip(OUTCOMES, SERIES, strict=True))
    )
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' class='campaign-figure' role='img' viewBox='0 0 {width} {height}' "
        f"aria-label='{html.escape(title, quote=True)}'><title>{html.escape(title)}</title>"
        "<desc>Each bar uses all assigned inputs for that model and evidence class as its denominator. "
        "A policy outcome is not generated answer text. Truncation overlaps outcomes and is shown separately. "
        + html.escape(scope) + "</desc><style>" + CHART_STYLE + "</style>" + legend + "".join(marks) + ticks
        + f"<text x='24' y='{height - 5}'>{html.escape(scope)}</text></svg>"
    )


def quality_svg(rows: Sequence[Mapping], *, scope: str) -> str:
    """Separate missing-response and observed truncation proportions, not a sum."""
    height = 84 + len(rows) * 86
    marks = []
    for i, row in enumerate(rows):
        n = _count(row, "assigned")
        observed = n - _count(row, "pending") - _count(row, "retry_pending")
        known_truncation = observed - _count(row, "truncation_unknown")
        y = 42 + i * 86
        name = str(row["model"]).partition(";")[0]
        name = name if len(name) <= 66 else name[:63] + "..."
        marks.append(f"<text x='24' y='{y}'>{html.escape(name)} / {html.escape(str(row['evidence_class']))}</text>")
        for x, key, denominator, label, color in (
            (24, "missing", observed, "Missing", SERIES[2]),
            (480, "truncated", known_truncation, "Truncated", SERIES[3]),
        ):
            count = _count(row, key)
            if count > denominator or denominator < 0:
                raise ValueError("Quality count exceeds its declared denominator")
            fraction = count / denominator if denominator else 0
            value = f"{label}: {count}/{denominator} ({fraction:.1%})" if denominator else label + ": unknown"
            marks.append(
                f"<rect class='chart-track' x='{x}' y='{y + 12}' width='400' height='12'/>"
                f"<rect x='{x}' y='{y + 12}' width='{400 * fraction:.3f}' height='12' style='fill:{color}'/>"
                f"<text x='{x}' y='{y + 44}'>{html.escape(value)}</text>"
            )
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' class='campaign-figure' role='img' viewBox='0 0 920 {height}' "
        "aria-label='Missing responses and observed truncation'><title>Missing responses and observed truncation</title>"
        "<desc>Independent 0-100 percent scales. Missing response uses terminal retained outcomes; truncation uses outcomes "
        "with a known truncation flag. Unknown flags and pending responses are not treated as untruncated.</desc>"
        "<style>" + CHART_STYLE + "</style>" + "".join(marks)
        + f"<text x='24' y='{height - 23}'>Missing: terminal outcomes. Truncated: known flags only. Pending retries are excluded.</text>"
        + f"<text x='24' y='{height - 3}'>{html.escape(scope)}</text></svg>"
    )


def model_counts_csv(rows: Sequence[Mapping]) -> bytes:
    fields = ("model", "evidence_class", "conditions", "assigned", "usable", "policy", "missing",
              "retry_pending", "pending", "truncated", "truncation_unknown", "updated_at")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(fields)
    for row in rows:
        values = []
        for key in fields:
            value = row[key]
            if key not in {"model", "evidence_class", "updated_at"}:
                value = _count(row, key)
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
    return stream.getvalue().encode("utf-8-sig")


def coverage_html(rows: Sequence[Mapping]) -> str:
    """Responsive on-screen counterpart of the vector export.

    Labels/counts use normal HTML so shrinking the viewport never shrinks the
    text inside a scaled SVG. Only the proportion bar is spatially scaled.
    """
    blocks = []
    for row in rows:
        n = _count(row, "assigned")
        counts = [_count(row, key) for key, _label, _code in OUTCOMES]
        if sum(counts) != n:
            raise ValueError("Coverage categories do not reconcile to assigned inputs")
        start, segments = 0.0, []
        labels = []
        for count, (key, label, _code), color in zip(counts, OUTCOMES, SERIES, strict=True):
            percent = 100 * count / n if n else 0
            segments.append(
                f"<rect x='{start:.5f}' width='{percent:.5f}' height='8' style='fill:{color}' "
                f"data-category='{key}'><title>{html.escape(label)}: {count}/{n}</title></rect>"
            )
            start += percent
            labels.append(
                "<span><span aria-hidden='true' style='display:inline-block;width:.7em;height:.7em;"
                f"background:{color}'></span> {html.escape(label)}: {count:,} ({percent:.1f}%)</span>"
            )
        missing = _count(row, "missing")
        observed = n - _count(row, "pending") - _count(row, "retry_pending")
        truncated = _count(row, "truncated")
        known = observed - _count(row, "truncation_unknown")
        if missing > observed or truncated > known or known < 0:
            raise ValueError("Quality count exceeds its declared denominator")
        quality = (f"Missing: {missing}/{observed} terminal outcomes. " if observed else "Missing rate: unknown. ")
        quality += (f"Truncated: {truncated}/{known} known flags. " if known else "Truncation rate: unknown. ")
        quality += f"Unknown truncation: {_count(row, 'truncation_unknown')}."
        blocks.append(
            "<figure style='margin:1rem 0'>"
            "<figcaption style='overflow-wrap:anywhere'>" + html.escape(str(row["model"]))
            + " / " + html.escape(str(row["evidence_class"])) + f" - n={n:,}</figcaption>"
            "<svg xmlns='http://www.w3.org/2000/svg' role='img' preserveAspectRatio='none' "
            "viewBox='0 0 100 8' style='width:100%;height:1.5rem' "
            f"aria-label='Outcome composition across {n} assignments'><title>Outcome composition</title>"
            + "".join(segments) + "</svg>"
            "<div style='display:flex;flex-wrap:wrap;gap:.35rem 1rem'>" + "".join(labels) + "</div>"
            "<p class='note'>" + html.escape(quality) + "</p></figure>"
        )
    return "".join(blocks)
