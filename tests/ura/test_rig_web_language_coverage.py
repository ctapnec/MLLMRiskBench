"""Audit authored text, not just the existence of catalog references."""

from __future__ import annotations

import ast
import re
import string
import html
from html.parser import HTMLParser
from pathlib import Path

import pytest

from experiments.rig_web_app import i18n
from test_rig_web_busy_browser import browser  # noqa: F401

ROOT = Path(i18n.__file__).parent
SLOT = "__CATALOG_OR_DATA__"
MARKER = re.compile(r"\[\[(?:text|attr|js|jshtml):[a-z0-9_.-]+\]\]")
# These are displayed literally because they name commands, files or scientific
# fields. They are not a general exemption for English labels or messages.
LITERAL_IDENTIFIERS = {
    "api-targets",
    "local-targets",
    "live_attestation",
    "run_matrix",
    "model_spec",
    "corpus_arm",
    "n_records",
    "n_clusters",
    "Macro-F1",
    "GPU",
    "MiB",
    "GiB",
    "MB",
    "GB",
    "TB",
    "B",
    "M",
    "K",
    "USD",
    "n=",
    "llama3.2:3b",
}


def test_authored_interface_copy_uses_plain_ascii_punctuation():
    assert all(message.isascii() for message in i18n.catalog().values())
    for path in ROOT.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert source.isascii(), path.name
        # Entity spelling must not hide typographic punctuation from the audit.
        assert html.unescape(source).isascii(), path.name


def test_ascii_copy_policy_never_rewrites_retained_unicode_answers():
    from experiments.rig_web_app import ui

    raw = "<pre>\u7814\u7a76 \u2014 retained answer \u201cquoted\u201d</pre>"
    assert raw in ui._page("Research", raw).decode("utf-8")


def authored(value: str) -> str:
    value = MARKER.sub(SLOT, value).replace(SLOT, "")
    value = value.strip()
    if not re.search(r"[A-Za-z]", value):
        return ""
    if value in LITERAL_IDENTIFIERS or value.startswith("--"):
        return ""
    if re.fullmatch(r"(?:https?://|/|runs/|rig/|experiments/)[^\s]+", value):
        return ""
    return value


class CopyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.literal = []
        self.findings = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "code", "pre"}:
            self.literal.append(tag)
        for name, value in attrs:
            if (
                name
                in {
                    "title",
                    "aria-label",
                    "aria-description",
                    "aria-valuetext",
                    "alt",
                    "placeholder",
                    "data-busy",
                    "data-label",
                    "data-step-title",
                }
                and value
            ):
                if text := authored(value):
                    self.findings.append((name, text))

    def handle_endtag(self, tag):
        if tag in self.literal:
            self.literal.remove(tag)

    def handle_data(self, data):
        if not self.literal and (text := authored(data)):
            self.findings.append(("text", text))


def static_fragment(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(static_fragment(value) for value in node.values)
    if isinstance(node, ast.FormattedValue):
        return static_fragment(node.value) if isinstance(node.value, ast.Constant) else SLOT
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return static_fragment(node.left) + static_fragment(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_ui_template"
    ):
        return node.args[0].value
    return SLOT


def markup_findings(source):
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Call)):
            continue
        parent = parents.get(node)
        if isinstance(parent, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            continue
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "_ui_template"
        ):
            continue
        value = static_fragment(node)
        if not re.search(
            r"<(?:div|p|span|label|input|select|button|a|h[1-6]|svg|text|table|th|td|section|nav|option|details|summary)\b",
            value,
        ):
            continue
        parser = CopyParser()
        parser.feed(value)
        findings.extend((node.lineno, kind, text) for kind, text in parser.findings)
    return sorted(set(findings))


def test_authored_markup_copy_is_catalogued():
    findings = []
    for path in ROOT.glob("*.py"):
        findings.extend(
            (path.name, *row) for row in markup_findings(path.read_text(encoding="utf-8"))
        )
    assert not findings, "Uncatalogued authored markup:\n" + "\n".join(map(str, findings))


def test_language_helpers_are_imported_in_every_using_module():
    for path in ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"_ui_text", "_ui_template", "_ui_label"}
        }
        imported = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.ImportFrom, ast.Import))
            for alias in node.names
        }
        assert calls <= imported, (path.name, calls - imported)


def test_generated_display_names_are_explicit_catalog_labels():
    findings = []
    for path in ROOT.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr in {"title", "capitalize"} and not node.args:
                findings.append((path.name, node.lineno))
            if (
                node.func.attr == "replace"
                and len(node.args) == 2
                and all(isinstance(value, ast.Constant) for value in node.args)
                and [value.value for value in node.args] == ["_", " "]
            ):
                findings.append((path.name, node.lineno))
    assert not findings, findings


def test_fixed_runtime_and_classifier_vocabularies_are_catalogued():
    from experiments.rig_web_app import catalog as commands, display_labels
    from experiments.rig_web_app.artifacts import _TOKEN_CATEGORIES
    from ura.response_svm import TASKS, FEATURES

    identifiers = set(_TOKEN_CATEGORIES) | set(TASKS) | set(FEATURES)
    identifiers.update(mode[0] for mode in commands._BUILD_MODES)
    identifiers.update(
        {
            "group_holdout",
            "unseen_model",
            "unseen_corpus",
            "already_judged",
            "source_specific_metric",
            "outside_requested_limit",
            "original_local_cascade_unavailable",
            "generation_context_unavailable",
        }
    )
    assert identifiers <= display_labels.LABELS.keys()
    assert display_labels.label("unseen_model:Qwen3-VL") == "unseen model:Qwen3-VL"
    assert display_labels.label("unknown_input_kind:raw_value") == "unknown_input_kind:raw_value"


@pytest.mark.parametrize(
    "source",
    [
        'body = "<button>Retry</button>"',
        'body = f"<label>Input {count} rows</label>"',
        '''body = "<input aria-label='Limit for " + model + "'>"''',
        """body = _ui_template("<p>[[text:known]] uncatalogued suffix</p>")""",
        '''body = "<svg><text>Missing outputs</text></svg>"''',
    ],
)
def test_markup_audit_detects_representative_missed_copy(source):
    assert markup_findings(source)


def test_markup_audit_does_not_translate_research_or_code():
    assert not markup_findings(
        'body = "<p>" + html.escape(response) + "</p><code>--max-tokens</code>"'
    )
    assert not markup_findings('body = _ui_template("<button>[[text:known]]</button>")')


def test_catalog_excludes_protocol_sql_and_markup():
    forbidden = {
        "Location",
        "AbortError",
        "AutoPrompt",
        "AutoDAN",
        "DirectRequest",
        "HumanJailbreaks",
        "ZeroShot",
        "node present",
        "notice amber",
        "review-status review-error",
    }
    assert not forbidden.intersection(i18n.catalog().values())
    assert "storage.job" not in i18n.catalog()
    assert not any(
        re.match(r"\s*(?:AND\s|OR\s|hidden\s+aria-|disabled\s+aria-)", value)
        for value in i18n.catalog().values()
    )


def test_display_tables_do_not_hide_uncatalogued_labels():
    tables = {
        "svm_stats.py": {"TASKS", "ESTIMATORS"},
        "display_labels.py": {"LABELS"},
    }
    for filename, names in tables.items():
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign) or not any(
                isinstance(target, ast.Name) and target.id in names for target in node.targets
            ):
                continue
            assert isinstance(node.value, ast.Dict)
            for value in node.value.values:
                assert (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == "_ui_text"
                ), (filename, value.lineno)
    from experiments.rig_web_app import workspace_charts

    assert [item[0] for item in workspace_charts.OUTCOMES] == [
        "usable",
        "policy",
        "missing",
        "retry_pending",
        "pending",
    ]


def test_plain_http_error_bodies_are_catalogued():
    findings = []
    for path in ROOT.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
                value = node.value.decode("utf-8", errors="replace")
                # Shared with the standalone log writer, not an HTTP response.
                # Retained operational logs and their protocol markers are verbatim.
                if (
                    path.name in {"log_supervisor.py", "lifecycle.py"}
                    and value == "\n[durable job log truncated at the configured byte limit]\n"
                ):
                    continue
                if re.search(r"[A-Za-z]{2,}\s+[A-Za-z]{2,}", value):
                    findings.append((path.name, node.lineno, value))
    assert not findings, findings


def test_named_template_values_match_the_complete_message():
    formatter = string.Formatter()
    checked = 0
    for path in ROOT.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_ui_text"
                and node.keywords
            ):
                continue
            message = i18n.catalog()[node.args[0].value]
            fields = {name for _, name, _, _ in formatter.parse(message) if name is not None}
            assert fields == {kw.arg for kw in node.keywords}, (path.name, node.lineno, fields)
            assert all(re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", name) for name in fields)
            checked += 1
    assert checked >= 7


def test_human_review_vocabulary_has_display_labels_without_changing_values():
    from experiments import human_audit
    from experiments.rig_web_app import display_labels

    values = set(human_audit.VALID_LABELS) | set(human_audit.DIMENSION_LABELS)
    values.update({"label", "task_label", "parse_status_label"})
    for choices in human_audit.DIMENSION_LABELS.values():
        values.update(choices)
    for choices in human_audit.SOURCE_TASK_VOCABULARY.values():
        values.update(choices)
    values.update(human_audit._SOURCE_TASK_PARSE_LABELS)
    assert values <= display_labels.LABELS.keys()
    assert display_labels.label("an_operator_or_model_value") == "an_operator_or_model_value"
    source = (ROOT / "human_review_pages.py").read_text(encoding="utf-8")
    assert "window.uraLabel(v),select).value=v" in source
    assert "select.dataset.rating=key" in source
    assert "replaceAll('_',' ')" not in source


@pytest.mark.parametrize(
    "value", ["<script>untrusted & text</script>", "{count}", "binary\\0value"]
)
def test_message_values_are_data_not_recursively_interpreted(monkeypatch, value):
    monkeypatch.setattr(i18n, "catalog", lambda: {"example": "Showing {shown} of {total} results"})
    assert i18n.text("example", shown=value, total=10) == f"Showing {value} of 10 results"
    with pytest.raises(KeyError):
        i18n.text("example", shown=value)


def test_client_named_templates_and_enum_labels_keep_values_as_data(browser, monkeypatch):
    from experiments.rig_web_app import display_labels

    monkeypatch.setitem(display_labels.LABELS, "not_refusal", "Translated choice <&>")
    page = browser.new_page()
    try:
        page.set_content(
            display_labels.script() + "<p id='result'></p><select id='choice'></select>"
        )
        value = "</script><img src=x onerror=alert(1)> {total}"
        result = page.evaluate(
            """value=>{
          const message=window.uraFormat('Showing {shown} of {total} results',{shown:value,total:10});
          document.getElementById('result').textContent=message;
          const option=new Option(window.uraLabel('not_refusal'),'not_refusal');
          document.getElementById('choice').append(option);
          return message;
        }""",
            value,
        )
        assert result == f"Showing {value} of 10 results"
        assert page.locator("img").count() == 0
        assert page.locator("#choice").input_value() == "not_refusal"
        assert page.locator("option").inner_text() == "Translated choice <&>"
        assert page.evaluate("window.uraLabel('retained_model_output')") == "retained_model_output"
        with pytest.raises(Exception, match="Missing message value"):
            page.evaluate("window.uraFormat('Count {count}', {})")
    finally:
        page.close()


def test_svm_numeric_validity_does_not_depend_on_english(monkeypatch):
    from experiments.rig_web_app import svm_stats

    monkeypatch.setattr(svm_stats, "_ui_text", lambda key, **values: "Translated <&>")
    missing = {"estimator": "linear_svm", "test": {"macro_f1": None}}
    assert "<rect class='chart-track'" not in svm_stats.figure([missing])
    assert svm_stats.figure_html([missing]) == ""
    for value in (None, True, -1, 2, float("nan")):
        assert not svm_stats.valid_score(value)
    for value in (0, 0.5, 1):
        assert svm_stats.valid_score(value)


def test_unpriced_routes_remain_incomplete_when_messages_change(monkeypatch):
    from types import SimpleNamespace
    from experiments.rig_web_app import direct_costs

    app = SimpleNamespace(
        _selected_api_config_snapshot=lambda params: (
            {
                "routes": [
                    {
                        "requested_spec": "provider:model",
                        "provider": "provider",
                        "model": "model",
                        "config": {"max_tokens": 4096},
                    }
                ]
            },
            None,
            None,
            None,
        ),
        _load_registry=lambda *args: {},
        _split_list=lambda value: value.split(","),
    )
    monkeypatch.setattr(direct_costs, "rate_for", lambda *args: (None, ""))
    monkeypatch.setattr(direct_costs, "_ui_text", lambda key, **values: "Translated")
    result = direct_costs.forecast(
        app, {"api": "provider:model"}, {"call_projection": {"target_calls": 1, "judge_calls": 0}}
    )
    assert (
        i18n.text("direct_costs.some_routes_are_unpriced_the_displayed_sum_is_incomplete_configur")
        in result
    )


def test_modality_label_changes_do_not_change_machine_class(monkeypatch):
    from experiments.rig_web_app import catalog as commands, display_labels

    monkeypatch.setitem(display_labels.LABELS, "image", "Translated <&> image")
    markup = commands._mod_icon("image")
    assert "m-image" in markup and "Translated &lt;&amp;&gt; image" in markup
    assert "<Translated" not in markup
