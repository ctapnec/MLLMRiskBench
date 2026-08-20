"""Fail-closed source-schema regressions for the first converter group."""
from __future__ import annotations

import csv
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
from ura.converters.release_specs import (
    STRONGREJECT_CATEGORIES,
    STRONGREJECT_DATASET_SHA256,
    STRONGREJECT_REVISION,
)
from ura.data_models import RiskCategory


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_strongreject_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["category", "source", "forbidden_prompt"],
        )
        writer.writeheader()
        writer.writerows(rows)


def _strongreject_fixture_rows(count: int = 313) -> list[dict[str, str]]:
    return [
        {
            "category": STRONGREJECT_CATEGORIES[index % len(STRONGREJECT_CATEGORIES)],
            "source": "release-contract-fixture",
            "forbidden_prompt": f"unique fixture prompt {index}",
        }
        for index in range(count)
    ]


@pytest.mark.parametrize(
    ("converter", "filename", "header"),
    [
        (AdvBenchConverter(), "advbench.csv", "goal,target\n"),
        (
            StrongRejectConverter(require_complete_release=False),
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


def test_strongreject_partial_release_fails_closed(tmp_path: Path):
    source = tmp_path / "strongreject_dataset.csv"
    _write_strongreject_csv(source, _strongreject_fixture_rows(1))

    with pytest.raises(CorpusFormatError, match="pinned release requires 313"):
        StrongRejectConverter().parse(source)


def test_strongreject_complete_but_modified_release_fails_hash_gate(tmp_path: Path):
    source = tmp_path / "strongreject_dataset.csv"
    _write_strongreject_csv(source, _strongreject_fixture_rows())

    with pytest.raises(CorpusFormatError, match="dataset SHA-256 mismatch"):
        StrongRejectConverter().parse(source)


def test_strongreject_requires_exact_official_csv_schema(tmp_path: Path):
    source = tmp_path / "strongreject_dataset.csv"
    source.write_text(
        "category,source,forbidden_prompt,unexpected\n"
        "Violence,fixture,unique prompt,value\n",
        encoding="utf-8",
    )

    with pytest.raises(CorpusFormatError, match="must contain exactly"):
        StrongRejectConverter(require_complete_release=False).parse(source)


def test_strongreject_accepts_pinned_layout_and_contract_without_corpus_copy(
    tmp_path: Path,
):
    source = (
        tmp_path
        / "strongreject_dataset"
        / "strongreject_dataset.csv"
    )
    _write_strongreject_csv(source, _strongreject_fixture_rows())

    points = StrongRejectConverter(verify_manifest_hash=False).parse(tmp_path)

    assert len(points) == 313
    assert len({point.id for point in points}) == 313
    assert {point.risk_subtype for point in points} == set(STRONGREJECT_CATEGORIES)
    assert points[1].risk_category is RiskCategory.TOXICITY
    assert points[0].meta["release_revision"] == STRONGREJECT_REVISION
    assert points[0].meta["release_manifest_sha256"] == STRONGREJECT_DATASET_SHA256
    assert points[0].meta["official_evaluator_executed"] is False
    assert points[0].meta["evaluator_scope"] == (
        "strongreject_style_not_official_runtime"
    )


def test_strongreject_requires_exact_six_category_inventory(tmp_path: Path):
    source = tmp_path / "strongreject_dataset.csv"
    rows = _strongreject_fixture_rows()
    for row in rows:
        row["category"] = "Violence"
    _write_strongreject_csv(source, rows)

    with pytest.raises(CorpusFormatError, match="six-category inventory"):
        StrongRejectConverter(verify_manifest_hash=False).parse(source)


def test_strongreject_violence_maps_to_toxicity_without_nonviolent_ref(
    tmp_path: Path,
) -> None:
    # "Violence" maps to TOXICITY (dangerous/violent content), not LEGALITY, so a
    # violent-crime row no longer inherits the factually wrong MLCommons
    # "Non-Violent Crimes" crosswalk id.
    source = tmp_path / "strongreject_dataset.csv"
    _write_strongreject_csv(source, [{
        "category": "Violence",
        "source": "fixture",
        "forbidden_prompt": "a violent-crime prompt",
    }])

    point = StrongRejectConverter(
        require_complete_release=False, verify_manifest_hash=False
    ).parse(source)[0]
    assert point.risk_category is RiskCategory.TOXICITY
    assert point.risk_subtype == "Violence"
    assert "MLCOMMONS:Non-Violent Crimes" not in point.taxonomy_refs


def test_strongreject_rejects_duplicate_prompts(tmp_path: Path):
    source = tmp_path / "strongreject_dataset.csv"
    rows = _strongreject_fixture_rows(2)
    rows[1]["forbidden_prompt"] = rows[0]["forbidden_prompt"]
    _write_strongreject_csv(source, rows)

    with pytest.raises(CorpusFormatError, match="duplicate forbidden_prompt"):
        StrongRejectConverter(require_complete_release=False).parse(source)


@pytest.mark.parametrize("field", ["category", "source"])
def test_strongreject_rejects_blank_required_fields(tmp_path: Path, field: str):
    source = tmp_path / "strongreject_dataset.csv"
    rows = _strongreject_fixture_rows(1)
    rows[0][field] = "   "
    _write_strongreject_csv(source, rows)

    with pytest.raises(CorpusFormatError, match=f"non-empty {field}"):
        StrongRejectConverter(require_complete_release=False).parse(source)


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


def test_mmsafety_resolves_images_under_official_data_imgs(tmp_path: Path):
    # Official release: <root>/data/processed_questions/<Scenario>.json with
    # images at <root>/data/imgs/<Scenario>/<variant>/<id>.jpg.
    root = tmp_path
    _write_json(
        root / "data" / "processed_questions" / "01-Illegal_Activity.json",
        {"1": {
            "Question": "q", "Rephrased Question": "rq",
            "Rephrased Question(SD)": "rq sd", "Key Phrase": "kp",
        }},
    )
    for variant in ("SD", "SD_TYPO", "TYPO"):
        imgdir = root / "data" / "imgs" / "01-Illegal_Activity" / variant
        imgdir.mkdir(parents=True)
        (imgdir / "1.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    points = MMSafetyConverter(require_complete_release=False).parse(root)
    assert len(points) == 3
    assert {point.meta["official_variant"] for point in points} == {
        "SD", "SD_TYPO", "TYPO",
    }
    for point in points:
        media_path = Path(point.media[0].path)
        assert media_path.parts[-4] == "imgs"
        assert media_path.is_file()


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
            StrongRejectConverter(require_complete_release=False),
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
        MMSafetyConverter(require_complete_release=False).parse(tmp_path)

    _write_json(qdir / "01-Illegal_Activity.json", {"1": {"Question": "  "}})
    with pytest.raises(CorpusFormatError, match="non-empty question"):
        MMSafetyConverter(require_complete_release=False).parse(tmp_path)


def test_mmsafety_scenario_top_level_must_be_an_object(tmp_path: Path):
    source = tmp_path / "processed_questions"
    _write_json(source / "01-Illegal_Activity.json", [])
    with pytest.raises(CorpusFormatError, match="scenario is not an object"):
        MMSafetyConverter(require_complete_release=False).parse(source)


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
