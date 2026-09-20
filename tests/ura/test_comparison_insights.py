"""Comparison figures must expose evidence, not a favourable pooled score."""

import xml.etree.ElementTree as ET

import pytest

from experiments.rig_web_app.comparison_insights import (
    summarize,
    metric,
    overview,
    detail,
    plot_svg,
)
from test_workspace_comparison import study, put, pair, comparison_rows  # noqa: F401


def row(**kw):
    return dict(
        dict(
            corpus="source",
            framework="replay",
            modality="text",
            count=1,
            match_status="matched",
            left_outcome="usable",
            right_outcome="usable",
            left_status="valid",
            right_status="valid",
            left_label="safe",
            right_label="violation",
            left_truncated=0,
            right_truncated=0,
        ),
        **kw,
    )


def test_common_denominators_exclude_unmatched_ambiguous_and_one_sided_judgments():
    data = summarize(
        [
            row(count=3),
            row(count=2, left_outcome="missing", left_status="missing", left_label=None),
            row(
                count=4, left_truncated=None, right_truncated=1, right_status=None, right_label=None
            ),
            row(count=9, match_status="left_only"),
            row(count=7, match_status="ambiguous"),
        ]
    )[0]
    assert data["matched"] == 9 and data["union"] == 25 and data["valid"] == 3
    assert data["different"] == 3
    assert metric(data, "usable") == (7, 9, 9)
    assert metric(data, "missing") == (2, 0, 9)
    assert metric(data, "label:violation") == (0, 3, 3)
    assert metric(data, "truncated") == (0, 0, 5)  # the four unknown-left flags exclude BOTH sides


def test_no_label_aliasing_or_silent_exclusion_of_not_applicable():
    data = summarize(
        [
            row(left_label="not_applicable"),
            row(left_label="unsafe"),
            row(left_label="violation", right_label="over_refusal"),
        ]
    )[0]
    assert metric(data, "label:violation") == (1, 2, 3)
    assert metric(data, "label:not_applicable") == (1, 0, 3)
    assert metric(data, "label:unsafe") == (1, 0, 3)


def test_svg_exact_counts_and_zero_denominator_are_not_zero_rates():
    data = summarize([row(count=2), row(corpus="unknown", left_status=None, left_label=None)])
    svg = ET.fromstring(
        plot_svg(
            data,
            "label:violation",
            title="Recorded label",
            left_name="Left model",
            right_name="Right model",
        )
    )
    points = [n for n in svg.iter() if n.get("data-source")]
    assert [(n.get("data-left"), n.get("data-right"), n.get("data-n")) for n in points] == [
        ("0", "2", "2"),
        ("0", "0", "0"),
    ]
    assert "not estimable" in "".join(svg.itertext())
    assert "Left model" in "".join(svg.itertext())
    assert "Right model" in "".join(svg.itertext())


def test_heatmap_keeps_pair_source_counts_and_direction_separate():
    html = overview(
        [
            dict(title="Pair A", rows=[row(count=2, left_outcome="missing")]),
            dict(title="Pair B", rows=[row(count=3, right_outcome="missing")]),
            dict(title="No overlap", rows=[row(count=20, match_status="right_only")]),
        ]
    )
    assert 'data-direction="right" data-left="0" data-right="2" data-n="2"' in html
    assert 'data-direction="left" data-left="3" data-right="0" data-n="3"' in html
    assert 'data-direction="unknown"' in html and ">N/A<" in html
    assert "+100.0 pp" in html and "-100.0 pp" in html


def test_dynamic_labels_escaped_in_select_svg_heatmap_and_captions():
    source = "<img src=x onerror=alert(1)>"
    rows = [row(corpus=source, left_label=source)]
    output = detail(rows, left_name=source, right_name=source) + overview(
        [dict(title=source, rows=rows)]
    )
    assert "<img" not in output and "&lt;img" in output
    assert 'data-insight-panel="label:&lt;img' in output


def test_real_sql_selection_flows_into_insights_without_historical_or_other_model_leak(study):  # noqa: F811
    app, left, right, query = study
    pair(study, "same", outcome="missing", status="missing", label=None)
    pair(study, "scored", label="violation")
    put(app, left, "old", "same", condition="old", label="safe")
    put(app, left, "other", "scored", model="other", label="safe")
    data = summarize(comparison_rows(app.db, left, query))[0]
    assert metric(data, "usable") == (1, 2, 2)
    assert metric(data, "label:violation") == (1, 0, 1)
    assert data["union"] == 2


def test_sources_and_frameworks_never_collapsed_into_overall_rate():
    data = summarize(
        [
            row(count=2, corpus="a"),
            row(count=8, corpus="b"),
            row(count=3, corpus="a", framework="live"),
        ]
    )
    assert len(data) == 3
    assert sorted(metric(d, "usable")[2] for d in data) == [2, 3, 8]


def test_pair_summary_agrees_with_figure_when_valid_status_has_no_label(study):  # noqa: F811
    from experiments.rig_web_app import workspace_comparison_many as many

    app, left, _, query = study
    pair(study, "null-label", label=None)
    query = dict(query, left_model="*")
    data = many.page_data(app.db, left, query)
    rendered = many.render(data, left, query)
    assert "jointly valid judgments: 0</summary>" in rendered


@pytest.mark.parametrize("key", ["usable", "missing", "policy", "truncated", "label:violation"])
def test_new_plots_present_and_descriptive_not_benchmark_asr(key):
    page = detail([row()])
    assert 'data-insight-panel="' + key + '"' in page
    assert "not benchmark attack-success rates" in page
