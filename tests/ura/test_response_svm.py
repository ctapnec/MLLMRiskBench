"""Retained-response analysis: real text shapes, grouping and label boundaries."""
import json
import sqlite3

import pytest

from experiments.response_svm_dataset import export_dataset, visible_turns
from ura.response_svm import (connected_groups, evaluate_study, feature_matrices,
                              split_groups, target_label)


def row(i=0, **changes):
    value = dict(id=f"response-{i}", input_id=f"input-{i}", source="source",
        source_cluster_id=f"cluster-{i}", prompt=f"Question {i} with context",
        response="A retained assistant answer", model="model-a", corpus="corpus-a",
        generation_condition="generation", judge_condition="haiku-condition",
        expected_behavior="refuse", label="violation", local_label="refusal",
        local_condition="local-condition", modality="text", framework="replay", truncated=False)
    return dict(value, **changes)


def test_transitive_grouping_covers_inputs_clusters_duplicates_and_prior_groups():
    rows = [row(0), row(1, input_id="input-0"),
            row(2, source_cluster_id="cluster-1"),
            row(3, source="another", prompt="  Question  2 with context  "), row(4),
            row(5, group="retained-bridge"), row(6, group="retained-bridge")]
    groups = connected_groups(rows)
    assert len(set(groups[:4])) == 1
    assert groups[4] != groups[0]
    assert groups[5] == groups[6]


def test_split_stable_under_row_order_and_no_cross_partition_groups():
    rows = [row(i, group=f"g{i // 2}") for i in range(40)]
    split = split_groups(rows, 0)
    assert split == split_groups(list(reversed(rows)), 0)
    assert set(split.values()) == {"train", "validation", "test"}


def test_task_labels_do_not_turn_missing_native_decisions_into_agreement():
    assert target_label(row(), "harmful_compliance") == 1
    assert target_label(row(), "judge_disagreement") == 1
    assert target_label(row(local_label=None), "judge_disagreement") is None
    assert target_label(row(label="safe", local_label="refusal"), "judge_disagreement") == 0
    assert target_label(row(expected_behavior="safe_answer", label="over_refusal"), "over_refusal") == 1
    assert target_label(row(expected_behavior="safe_answer"), "harmful_compliance") is None
    assert target_label(row(label="invalid"), "harmful_compliance") is None


def test_only_visible_assistant_text_not_reasoning_or_user_turns():
    turns = [dict(role="user", content="not an answer"),
             dict(role="assistant", content="visible", provider_thinking="secret reasoning")]
    assert visible_turns(turns, assistant_only=True) == "visible"


def test_text_features_exclude_labels_ids_and_holdout_vocabulary():
    pytest.importorskip("sklearn")
    parts = dict(train=[row(), row(1)], validation=[row(2, response="zzyxvalidationonly")],
                 test=[row(3, response="zzyxtestonly")])
    a, vocabulary = feature_matrices(parts, "prompt_response", 1000)
    assert "response:zzyxvalidationonly" not in vocabulary
    assert "response:zzyxtestonly" not in vocabulary
    changed = {k: [dict(r, id="FORBIDDEN_ID", label="FORBIDDEN_LABEL",
                         local_label="FORBIDDEN_NATIVE", model="FORBIDDEN_MODEL",
                         judge_reason="FORBIDDEN_RATIONALE") for r in values] for k, values in parts.items()}
    b, renamed = feature_matrices(changed, "prompt_response", 1000)
    assert vocabulary == renamed
    for part in a:
        assert (a[part] != b[part]).nnz == 0


def dataset_fixture(tmp_path):
    database = tmp_path / "console.db"
    c = sqlite3.connect(database)
    c.executescript("""
      CREATE TABLE campaign_assignments(campaign_id,assignment_id,model,input_id,condition_id,
          modality,framework,corpus,response_id,evidence_class);
      CREATE TABLE campaign_responses(campaign_id,response_id,assignment_id,condition_id,outcome,truncated,details);
      CREATE TABLE campaign_judgments(campaign_id,response_id,judge_id,status,label,source_ref);
    """)
    response = tmp_path / "responses.jsonl"
    response.write_text(json.dumps(dict(run_id="run-1", attempt_id="attempt-1",
        output_turns=[dict(role="assistant", content="Visible retained text", provider_thinking="EXCLUDED")])) + "\n")
    c.execute("INSERT INTO campaign_assignments VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("campaign", "assignment", "model", "input", "condition", "text", "replay", "corpus", "run-1:attempt-1", "measured"))
    c.execute("INSERT INTO campaign_responses VALUES (?,?,?,?,?,?,?)",
        ("campaign", "run-1:attempt-1", "assignment", "condition", "usable", 1,
         json.dumps(dict(source_ref=str(response) + ":1", output_allowance=4096))))
    c.executemany("INSERT INTO campaign_judgments VALUES (?,?,?,?,?,?)", [
        ("campaign", "run-1:attempt-1", "haiku", "valid", "violation", "haiku.json:1"),
        ("campaign", "run-1:attempt-1", "local-cascade-1", "valid", "safe", "local.json:1")])
    c.commit(); c.close()
    candidates = tmp_path / "candidates.json"
    candidates.write_text(json.dumps([dict(input_identity_sha256="input", modality="text", framework="replay",
        corpus="corpus", source="source", source_cluster_id="cluster", source_policy=None,
        expected_behavior="refuse", risk="legality", rendered_input=[dict(role="user", content="Prompt")])]))
    return dict(database=database, candidates=candidates, campaigns=["campaign"], judge="haiku", matched_campaign="campaign")


def test_real_index_export_preserves_text_truncation_and_read_only_source(tmp_path):
    args = dataset_fixture(tmp_path)
    before = args["database"].read_bytes()
    rows, report = export_dataset(**args)
    assert len(rows) == 1 and rows[0]["response"] == "Visible retained text"
    assert rows[0]["truncated"] is True and rows[0]["output_allowance"] == 4096
    assert target_label(rows[0], "judge_disagreement") == 1
    assert report["target_calls"] == report["judge_calls"] == 0
    assert args["database"].read_bytes() == before


def test_multiple_native_conditions_do_not_duplicate_or_fabricate_disagreement(tmp_path):
    args = dataset_fixture(tmp_path)
    with sqlite3.connect(args["database"]) as c:
        c.execute("INSERT INTO campaign_judgments VALUES (?,?,?,?,?,?)",
            ("campaign", "run-1:attempt-1", "local-cascade-2", "valid", "violation", "other.json:1"))
    rows, report = export_dataset(**args)
    assert len(rows) == 1 and rows[0]["local_label"] is None
    assert target_label(rows[0], "harmful_compliance") == 1
    assert target_label(rows[0], "judge_disagreement") is None
    assert report["dispositions"]["ambiguous_local_judge_excluded_from_disagreement"] == 1


def test_export_detects_wrong_retained_line_identity(tmp_path):
    args = dataset_fixture(tmp_path)
    p = tmp_path / "responses.jsonl"
    p.write_text(p.read_text().replace('"attempt-1"', '"different-attempt"'))
    with pytest.raises(ValueError, match="retained response line"):
        export_dataset(**args)


def test_real_fitting_three_tasks_with_locked_group_split():
    pytest.importorskip("sklearn")
    rows = []
    for i in range(30):
        for benign in (False, True):
            for positive in (False, True):
                n = len(rows)
                rows.append(row(n, input_id=f"input-{i}", source_cluster_id=f"cluster-{i}",
                    prompt=f"Question group {i}", expected_behavior="safe_answer" if benign else "refuse",
                    label=("over_refusal" if benign else "violation") if positive else "safe",
                    local_label="safe", response="rejected inappropriate" if positive else "helpful permitted"))
    report, predictions = evaluate_study(rows, bootstrap=100, max_chars=1000)
    assert report["status"] == "analysis_complete" and report["human_validated"] is False
    assert len(report["experiments"]) == 15 and predictions
    assert {r["task"] for r in report["experiments"]} == {
        "harmful_compliance", "over_refusal", "judge_disagreement"}
    memberships = {r["id"]: r for r in report["split_membership"]}
    assert all(memberships[r["id"]]["split"] == "test" for r in predictions)
    for g in {r["group"] for r in memberships.values()}:
        assert len({r["split"] for r in memberships.values() if r["group"] == g}) == 1


def test_unsupported_class_support_is_reported_without_seed_search():
    pytest.importorskip("sklearn")
    report, predictions = evaluate_study([row(i) for i in range(10)], bootstrap=100)
    assert not predictions
    assert all(r["status"] == "insufficient_class_group_support" for r in report["experiments"])
