"""Source- and condition-specific distributions of retained judge labels."""
from __future__ import annotations

import csv
import html
import io
import json
from itertools import groupby

from .workspace_charts import CHART_STYLE, SERIES

GROUP_FIELDS = ("model", "evidence_class", "condition_id", "modality", "framework", "corpus", "judge_id")


def judgment_groups(rows):
    return [list(values) for _key, values in groupby(rows, key=lambda row: tuple(row[key] for key in GROUP_FIELDS))]


def _label(row):
    return str(row["label"] if row["status"] == "valid" else {
        "missing": "Missing output", "invalid": "Invalid verdict"}.get(row["status"], row["status"]))


def _judge_name(identity):
    if identity.startswith("local-cascade-"):
        return "Local judge"
    name, _, suffix = identity.rpartition(":")
    return name if len(suffix) == 24 and all(c in "0123456789abcdef" for c in suffix) else identity


def _segments(group):
    if any(type(row["count"]) is not int or row["count"] <= 0 for row in group):
        raise ValueError("Judgment counts must be positive integers")
    total = sum(row["count"] for row in group)
    result, start = [], 0.0
    colors = {"violation": SERIES[2], "unsafe": SERIES[2], "compliant": SERIES[0],
              "safe": SERIES[0], "over_refusal": SERIES[1]}
    for row in group:
        width = 100 * row["count"] / total
        color = colors.get(str(row["label"]), SERIES[3]) if row["status"] == "valid" else SERIES[4]
        result.append((row, _label(row), start, width, color))
        start += width
    return total, result


def judgment_breakdown_html(rows):
    blocks = []
    for group in judgment_groups(rows):
        first = group[0]
        total, segments = _segments(group)
        description = " / ".join(str(first[key]) for key in ("model", "corpus", "framework", "modality", "evidence_class"))
        marks = "".join(
            f"<rect x='{start:.5f}' width='{width:.5f}' height='8' style='fill:{color}' "
            f"data-status='{html.escape(row['status'], quote=True)}' data-count='{row['count']}'>"
            f"<title>{html.escape(label)}: {row['count']}/{total}</title></rect>"
            for row, label, start, width, color in segments)
        counts = "; ".join(f"{label}: {row['count']:,}/{total:,}" for row, label, *_rest in segments)
        judge = _judge_name(first["judge_id"])
        blocks.append(
            "<figure class='card' style='margin:1rem 0;overflow-wrap:anywhere'>"
            f"<figcaption>{html.escape(description)}</figcaption><p>{html.escape(judge)}; {total:,} retained assessments</p>"
            "<svg xmlns='http://www.w3.org/2000/svg' role='img' viewBox='0 0 100 8' "
            "preserveAspectRatio='none' style='width:100%;height:1.5rem' aria-label='Retained judgment label distribution'>"
            + marks + "</svg><p>" + html.escape(counts) + "</p>"
            "<details><summary>Exact generation and judging conditions</summary><p>Generation: "
            + html.escape(first["condition_id"]) + "</p><p>Judge: " + html.escape(first["judge_id"]) + "</p></details></figure>")
    return "".join(blocks)


def judgment_counts_csv(rows):
    stream = io.StringIO(newline="")
    fields = (*GROUP_FIELDS, "status", "label", "count")
    writer = csv.writer(stream)
    writer.writerow(fields)
    for row in rows:
        values = [row[key] for key in fields]
        writer.writerow(["'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value
                         for value in values])
    return stream.getvalue().encode("utf-8-sig")


def judgment_breakdown_svg(rows, *, scope):
    groups = judgment_groups(rows)
    height = 80 + 120 * len(groups)
    marks = []
    for index, group in enumerate(groups):
        first = group[0]
        total, segments = _segments(group)
        y = 36 + index * 120
        title = " / ".join(str(first[key]) for key in ("model", "corpus", "modality"))
        display = title if len(title) <= 95 else title[:92] + "..."
        marks.append(f"<text x='24' y='{y}'>{html.escape(display)}</text>")
        detail = f"Condition {index + 1}; {_judge_name(first['judge_id'])}; {first['framework']}; {first['evidence_class']}; n={total:,}"
        marks.append(f"<text x='24' y='{y + 21}'>{html.escape(detail)}</text>")
        for row, label, start, width, color in segments:
            marks.append(f"<rect x='{24 + 8.5 * start:.5f}' y='{y + 31}' width='{8.5 * width:.5f}' height='18' "
                f"data-count='{row['count']}' data-status='{html.escape(row['status'], quote=True)}' style='fill:{color}'>"
                f"<title>{html.escape(label)}: {row['count']}/{total}</title></rect>")
        counts = "; ".join(f"{label}: {row['count']:,}" for row, label, *_rest in segments)
        marks.append(f"<text x='24' y='{y + 73}'>{html.escape(counts)}</text>")
    return (f"<svg xmlns='http://www.w3.org/2000/svg' class='campaign-figure' role='img' viewBox='0 0 940 {height}'>"
        "<title>Retained judgment labels by model and source</title>"
        "<desc>Each bar is a separate generation, source and judging condition. Denominators include retained "
        "invalid and missing-output assessments; pending judgments are not shown. These are label counts, not pooled security rates.</desc>"
        "<metadata>" + html.escape(json.dumps([{key: group[0][key] for key in GROUP_FIELDS} for group in groups]))
        + "</metadata><style>" + CHART_STYLE + "</style>" + "".join(marks)
        + f"<text x='24' y='{height - 25}'>{html.escape(scope)}</text></svg>")
