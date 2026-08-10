"""Fail-closed source-schema regressions for the first converter group."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ura.converters import (
    AdvBenchConverter,
    BIPIAConverter,
    CorpusFormatError,
    FigStepConverter,
    HarmBenchConverter,
    JailbreakBenchConverter,
    MLLMGuardConverter,
    MMSafetyConverter,
    StrongRejectConverter,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.mark.parametrize(
    ("converter", "filename", "header"),
    [
        (AdvBenchConverter(), "advbench.csv", "goal,target\n"),
        (
            StrongRejectConverter(),
            "strongreject.csv",
            "category,source,forbidden_prompt\n",
        ),
        (
            HarmBenchConverter(),
            "harmbench.csv",
            "Behavior,FunctionalCategory,SemanticCategory,Tags,ContextString,BehaviorID\n",
        ),
    ],
)
def test_header_only_csv_corpora_fail_closed(
    tmp_path: Path, converter: object, filename: str, header: str
):
    source = tmp_path / filename
    source.write_text(header, encoding="utf-8")
    with pytest.raises(CorpusFormatError, match="produced no rows"):
        converter.parse(source)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("converter", "filename"),
    [
        (JailbreakBenchConverter(), "jailbreakbench.json"),
        (MLLMGuardConverter(), "mllmguard.json"),
        (FigStepConverter(), "figstep.json"),
    ],
)
def test_empty_json_record_lists_fail_closed(
    tmp_path: Path, converter: object, filename: str
):
    source = tmp_path / filename
    _write_json(source, [])
    with pytest.raises(CorpusFormatError, match="produced no rows"):
        converter.parse(source)  # type: ignore[attr-defined]


def test_empty_mmsafety_directory_fails_closed(tmp_path: Path):
    source = tmp_path / "processed_questions"
    source.mkdir()
    with pytest.raises(CorpusFormatError, match="produced no rows"):
        MMSafetyConverter().parse(source)


def test_empty_bipia_jsonl_fails_closed(tmp_path: Path):
    source = tmp_path / "email" / "test.jsonl"
    source.parent.mkdir()
    source.write_text("", encoding="utf-8")
    with pytest.raises(CorpusFormatError, match="context file is empty"):
        BIPIAConverter().parse(source)


@pytest.mark.parametrize(
    ("converter", "filename", "value"),
    [
        (JailbreakBenchConverter(), "jailbreakbench.json", {"data": {}}),
        (MLLMGuardConverter(), "mllmguard.json", {"records": {}}),
        (FigStepConverter(), "figstep.json", {"questions": {}}),
    ],
)
def test_json_wrappers_must_contain_record_lists(
    tmp_path: Path, converter: object, filename: str, value: object
):
    source = tmp_path / filename
    _write_json(source, value)
    with pytest.raises(CorpusFormatError, match="not a record list"):
        converter.parse(source)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("converter", "filename"),
    [
        (JailbreakBenchConverter(), "jailbreakbench.json"),
        (MLLMGuardConverter(), "mllmguard.json"),
        (FigStepConverter(), "figstep.json"),
    ],
)
def test_every_json_record_must_be_an_object(
    tmp_path: Path, converter: object, filename: str
):
    source = tmp_path / filename
    _write_json(source, ["not-an-object"])
    with pytest.raises(CorpusFormatError, match="row 0.*not an object"):
        converter.parse(source)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("converter", "filename", "csv_text", "message"),
    [
        (
            AdvBenchConverter(),
            "advbench.csv",
            "goal,target\n   ,\n",
            "harmful prompt",
        ),
        (
            StrongRejectConverter(),
            "strongreject.csv",
            "category,source,forbidden_prompt\nViolence,test,   \n",
            "forbidden_prompt",
        ),
        (
            HarmBenchConverter(),
            "harmbench.csv",
            "Behavior,FunctionalCategory,SemanticCategory,Tags,ContextString,BehaviorID\n"
            "   ,standard,harmful,,,1\n",
            "Behavior",
        ),
    ],
)
def test_text_csv_rows_require_non_empty_prompts(
    tmp_path: Path,
    converter: object,
    filename: str,
    csv_text: str,
    message: str,
):
    source = tmp_path / filename
    source.write_text(csv_text, encoding="utf-8")
    with pytest.raises(CorpusFormatError, match=message):
        converter.parse(source)  # type: ignore[attr-defined]


def test_jailbreakbench_requires_a_non_empty_goal(tmp_path: Path):
    source = tmp_path / "harmful-behaviors.json"
    _write_json(source, [{"Goal": "  ", "Category": "Privacy"}])
    with pytest.raises(CorpusFormatError, match="non-empty goal"):
        JailbreakBenchConverter().parse(source)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"Prompt": " ", "file_name": "probe.png"}, "non-empty prompt"),
        ({"Prompt": "unsafe request", "file_name": " "}, "required image"),
    ],
)
def test_mllmguard_requires_both_prompt_and_image(
    tmp_path: Path, record: dict[str, str], message: str
):
    source = tmp_path / "toxicity.json"
    _write_json(source, [record])
    with pytest.raises(CorpusFormatError, match=message):
        MLLMGuardConverter().parse(source)


def test_mmsafety_requires_object_rows_and_non_empty_questions(tmp_path: Path):
    qdir = tmp_path / "data" / "processed_questions"
    _write_json(qdir / "01-Illegal_Activity.json", {"1": "not-an-object"})
    with pytest.raises(CorpusFormatError, match="not an object"):
        MMSafetyConverter().parse(tmp_path)

    _write_json(qdir / "01-Illegal_Activity.json", {"1": {"Question": "  "}})
    with pytest.raises(CorpusFormatError, match="non-empty question"):
        MMSafetyConverter().parse(tmp_path)


def test_mmsafety_scenario_top_level_must_be_an_object(tmp_path: Path):
    source = tmp_path / "processed_questions"
    _write_json(source / "01-Illegal_Activity.json", [])
    with pytest.raises(CorpusFormatError, match="scenario is not an object"):
        MMSafetyConverter().parse(source)


def test_figstep_requires_the_harmful_image_instruction(tmp_path: Path):
    source = tmp_path / "figstep.json"
    _write_json(source, [{"instruction": "  ", "image": "probe.png"}])
    with pytest.raises(CorpusFormatError, match="harmful instruction"):
        FigStepConverter().parse(source)


@pytest.mark.parametrize(
    ("context", "question", "message"),
    [
        ({"unexpected": "object"}, "Who sent it?", "non-text context"),
        ("A benign email.", "   ", "lacks context or question"),
    ],
)
def test_bipia_requires_non_empty_context_and_question(
    tmp_path: Path, context: object, question: str, message: str
):
    benchmark = tmp_path / "benchmark"
    source = benchmark / "email" / "test.jsonl"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps({"context": context, "question": question}) + "\n",
        encoding="utf-8",
    )
    _write_json(benchmark / "text_attack_test.json", {"override": ["IGNORE"]})
    with pytest.raises(CorpusFormatError, match=message):
        BIPIAConverter().parse(source)


def test_bipia_attack_object_rejects_empty_names_and_variants(tmp_path: Path):
    benchmark = tmp_path / "benchmark"
    source = benchmark / "email" / "test.jsonl"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps({"context": "A benign email.", "question": "Who sent it?"})
        + "\n",
        encoding="utf-8",
    )

    _write_json(benchmark / "text_attack_test.json", {"": ["IGNORE"]})
    with pytest.raises(CorpusFormatError, match="attack name"):
        BIPIAConverter().parse(source)

    _write_json(benchmark / "text_attack_test.json", {"override": []})
    with pytest.raises(CorpusFormatError, match="attack file is empty"):
        BIPIAConverter().parse(source)
