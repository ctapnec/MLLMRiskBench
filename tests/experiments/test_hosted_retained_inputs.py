from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments import hosted_retained_inputs as subject


HEX_A = "a" * 64
HEX_B = "b" * 64
TARGET = "example:model"
API = {TARGET: {"modalities": ["text", "image"], "max_tokens": 2048}}
DESCRIPTOR = {"file": "api.json", "sha256": HEX_A, "bytes": 123}


def _cell(tmp_path: Path, *, count: int = 8, model: str = "ollama:retained-model") -> dict:
    # Exact _load_cells export shape; outcomes are never a selection input.
    artifact = tmp_path / "retained.attempts.jsonl"
    artifact.write_text("retained artifact bytes\n", encoding="utf-8")
    attempts, judgments = {}, []
    for index in range(count):
        ident = f"attempt-{index}"
        attempts[ident] = {
            "id": ident, "run_id": "local-run", "target": model,
            "datapoint_id": f"data-{index}", "attacker": "replay", "seed": 0,
            "turn_index": 0,
            "rendered_input": [{"role": "user", "content": f"Exact question {index}", "media": []}],
            "params": {"source_cluster_id": f"cluster-{index}",
                       "planning_source": "arm-" + str(index % 2),
                       "planning_expected_behavior": "refuse", "planning_source_policy": None,
                       "prepared_attack": {"artifact_sha256": HEX_A}},
        }
        judgments.append({"attempt_id": ident, "label": "violation", "score": 1.0,
                          "raw": {"risk_category": "risk-" + str(index % 2),
                                  "source": "arm-" + str(index % 2),
                                  "expected_behavior": "refuse"}})
    return {"source_identity_validated": True, "run_id": "local-run", "model": model,
            "manifest": {"dataset_hashes": {"corpus": HEX_B}, "config": {"run": {
                "corpus": "retained-corpus", "project_revision": {"sha256": HEX_A}}}},
            "artifacts": {"attempts": artifact}, "attempts": attempts,
            "judgments": judgments, "responses": {ident: {"output_turns": []} for ident in attempts}}


def test_separate_scoring_completion_reuses_source_descriptors(tmp_path, monkeypatch):
    cell = _cell(tmp_path, count=2)
    expected = subject.candidates_from_cells([cell])
    artifact = cell['artifacts']['attempts']
    cell['artifact_descriptors'] = {'attempts': {
        'file': artifact.name, 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
        'bytes': artifact.stat().st_size}}
    marker = tmp_path / 'completion.json'
    marker.write_text(json.dumps({'schema': 'ura-rr-retained-judging-completion/2',
                                  'retained_responses': 2}))
    cell['complete_path'] = marker
    original_read = Path.read_bytes

    def no_artifact_reread(path):
        assert path != artifact, 'unchanged retained artifact was rehashed'
        return original_read(path)

    monkeypatch.setattr(Path, 'read_bytes', no_artifact_reread)
    assert subject.candidates_from_cells([cell]) == expected


def _budget() -> dict:
    value = {"schema": subject.BUDGET_SCHEMA, "status": "budget_fit",
             "sources": {"api_config": DESCRIPTOR}, "routes": [{
                 "target_spec": TARGET, "paid_call_cap": 20,
                 "answer_retries": 0, "transport_retries": 3,
                 "maximum_output_tokens_per_call": 2048, "maximum_cost_microusd": 1000000,
                 "maximum_http_attempts": 80,
                 "paid_call_cap_includes_readiness_and_canaries": True}]}
    value["projection_id"] = "hosted-budget-" + subject._sha(value)[:24]
    return value


def _bindings(**updates) -> dict:
    result = {"budget": _budget(), "budget_descriptor": DESCRIPTOR,
              "api_config": API, "api_descriptor": DESCRIPTOR,
              "media_index": {}, "local_inventory_descriptor": DESCRIPTOR}
    result.update(updates)
    return result


def _plan(candidates: list[dict], cap: int = 4, **updates) -> dict:
    return subject.build_plan(candidates=candidates, target=TARGET, call_cap=cap,
                              **_bindings(**updates))


def test_missing_outputs_and_judgments_do_not_control_selection(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    first = subject.candidates_from_cells([cell])
    # All rows initially have missing answers. Changing answer content, outcome,
    # score, or finish reason must not change their input population or ordering.
    cell["responses"] = {"never_read": "arbitrary answer and length-stop metadata"}
    for judgment in cell["judgments"]:
        judgment.update(label="safe", score=0.0, rationale="changed answer assessment")
    second = subject.candidates_from_cells([cell])
    assert len(first) == 8
    assert first == second
    assert _plan(first) == _plan(list(reversed(second)))
    assert _plan(first)["authority"]["paid_execution_authorized"] is False


def test_cap_is_global_nested_and_keeps_whole_clusters(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    for index, attempt in enumerate(cell["attempts"].values()):
        attempt["params"]["source_cluster_id"] = f"cluster-{index // 4}"
        attempt["params"]["planning_source"] = "one-arm"
    candidates = subject.candidates_from_cells([cell])
    first = _plan(candidates, 5)
    assert len(first["selected"]) == 4
    assert first["population"]["unused_call_capacity"] == 1
    assert first["population"]["next_whole_cluster_size"] == 4
    assert len({row["source_cluster_id"] for row in first["selected"]}) == 1
    larger = _plan(candidates, 8)
    assert first["selected"] == larger["selected"][:4]


@pytest.mark.parametrize("change", [None, "missing", "extra", "invalid", "risk", "source", "expected_behavior"])
def test_source_input_metadata_keeps_unjudged_inputs_without_inventing_verdicts(tmp_path, change):
    cell = _cell(tmp_path, count=2)
    expected = subject.candidates_from_cells([cell])
    cell["input_metadata"] = {row["attempt_id"]: copy.deepcopy(row["raw"]) for row in cell["judgments"]}
    cell["judgments"].pop()
    if change == "missing":
        cell["input_metadata"].pop("attempt-1")
    elif change == "extra":
        cell["input_metadata"]["foreign"] = cell["input_metadata"]["attempt-0"]
    elif change == "invalid":
        cell["input_metadata"]["attempt-0"] = None
    elif change:
        key = "risk_category" if change == "risk" else change
        cell["input_metadata"]["attempt-0"][key] = "changed"
    if change:
        with pytest.raises(ValueError, match="metadata"):
            subject.candidates_from_cells([cell])
    else:
        assert subject.candidates_from_cells([cell]) == expected
        assert len(cell["judgments"]) == 1


def test_exact_adaptive_dialogue_and_source_parameters_survive_resolution(tmp_path: Path) -> None:
    cell = _cell(tmp_path, count=1)
    attempt = cell["attempts"]["attempt-0"]
    attempt["attacker"] = "crescendo"
    attempt["turn_index"] = 3
    attempt["rendered_input"] = [
        {"role": "user", "content": "First input", "media": []},
        {"role": "assistant", "content": "Retained LOCAL answer", "media": []},
        {"role": "user", "content": "Exact follow-up", "media": [],
         "tool_calls": [{"name": "fixture_tool", "arguments": {"x": 1}}]},
    ]
    candidates = subject.candidates_from_cells([cell])
    plan = _plan(candidates, 1)
    resolved = subject.resolve_inputs(plan, candidates=candidates, **_bindings())
    assert resolved[0]["rendered_input"] == attempt["rendered_input"]
    assert resolved[0]["local_sources"][0]["attempt_params_sha256"] == subject._sha(attempt["params"])
    assert "Retained LOCAL answer" not in json.dumps(plan)
    assert plan["selected"][0]["framework"] == "crescendo"
    assert plan["selected"][0]["converted_corpus_sha256"] == HEX_B


def test_selected_media_bytes_are_required_and_rechecked(tmp_path: Path) -> None:
    cell = _cell(tmp_path, count=1)
    asset = tmp_path / "asset.png"
    asset.write_bytes(b"exact retained image bytes")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    cell["attempts"]["attempt-0"]["rendered_input"][0]["media"] = [
        {"modality": "image", "mime": "image/png", "sha256": digest,
         "path": "sha256:" + digest, "uri": None}]
    candidates = subject.candidates_from_cells([cell])
    with pytest.raises(ValueError, match="explicit local content index"):
        _plan(candidates, 1)
    plan = _plan(candidates, 1, media_index={digest: str(asset)})
    assert plan["selected"][0]["media_bindings"][0]["sha256"] == digest
    asset.write_bytes(b"different image bytes")
    from ura.artifact_checks import artifact_verification
    with artifact_verification(verify_sha256=True), pytest.raises(ValueError, match="bytes changed"):
        subject.resolve_inputs(plan, candidates=candidates,
                               **_bindings(media_index={digest: str(asset)}))


def test_modality_incompatibility_is_na_not_a_caption(tmp_path: Path) -> None:
    cell = _cell(tmp_path, count=1)
    cell["attempts"]["attempt-0"]["rendered_input"][0]["media"] = [
        {"modality": "image", "mime": "image/png", "sha256": HEX_A,
         "path": "sha256:" + HEX_A}]
    candidates = subject.candidates_from_cells([cell])
    plan = _plan(candidates, 1, api_config={TARGET: {"modalities": ["text"]}})
    assert plan["selected"] == []
    assert plan["population"]["incompatible_modality_inputs"] == 1


def test_multiple_local_sources_do_not_multiply_paid_inputs(tmp_path: Path) -> None:
    first = _cell(tmp_path, count=2)
    second = copy.deepcopy(first)
    second["model"] = "vllm:another-model"
    second["run_id"] = "different-local-run"
    for attempt in second["attempts"].values():
        attempt["target"] = second["model"]
        attempt["run_id"] = second["run_id"]
    candidates = subject.candidates_from_cells([first, second])
    assert len(candidates) == 2
    assert all(len(row["local_sources"]) == 2 for row in candidates)
    assert len(_plan(candidates)["selected"]) == 2


def test_distinct_provider_requests_collapse_subset_aliases_before_the_cap(tmp_path):
    first = _cell(tmp_path, count=2)
    for attempt in first["attempts"].values():
        attempt["params"].update(source_cluster_id="one", planning_source="one-arm")
    second = copy.deepcopy(first)
    second["run_id"] = "recovered"
    second["manifest"]["dataset_hashes"]["corpus"] = "c" * 64
    candidates = subject.candidates_from_cells([first, second])
    assert len(candidates) == 4
    def builder(row):
        return {"model": "fixed-target", "messages": row["rendered_input"], "seed": 0}

    selection = subject.select_distinct_requests(candidates, modalities=["text"], cap=2, request_builder=builder)
    assert selection["population"]["selected_requests"] == 2
    assert selection["population"]["selected_source_inputs"] == 4
    assert all(len(group["source_inputs"]) == 2 for group in selection["selected"])
    assert selection == subject.select_distinct_requests(list(reversed(candidates)), modalities=["text"], cap=2, request_builder=builder)
    assert selection["paid_execution_authorized"] is False
    assert len(subject._select(candidates, modalities=["text"], cap=2)[0]) == 0
    too_small = subject.select_distinct_requests(candidates, modalities=["text"], cap=1, request_builder=builder)
    assert too_small["population"]["selected_requests"] == 0
    assert too_small["population"]["next_whole_cluster_new_requests"] == 2
    previous = selection["selected"][0]["request_sha256"]
    tail = subject.select_distinct_requests(candidates, modalities=["text"], cap=1,
        request_builder=builder, previous_request_sha256=[previous])
    assert tail["population"]["selected_requests"] == 1
    assert tail["population"]["previous_request_source_inputs"] == 2
    assert tail["selected"][0]["request_sha256"] != previous


def test_distinct_request_identity_keeps_generation_controls_and_rejects_changed_source(tmp_path):
    candidates = subject.candidates_from_cells([_cell(tmp_path, count=1)])
    def build(limit):
        return subject.select_distinct_requests(candidates, modalities=["text"], cap=1,
            request_builder=lambda row: {"messages": row["rendered_input"], "max_tokens": limit})
    assert build(512)["selected"][0]["request_sha256"] != build(4096)["selected"][0]["request_sha256"]
    candidates[0]["rendered_input"][0]["content"] = "Changed prompt"
    with pytest.raises(ValueError, match="source input identity"):
        build(512)


def test_distinct_continuation_rebuilds_full_prefix_and_keeps_aliases(tmp_path):
    first = _cell(tmp_path, count=8)
    second = copy.deepcopy(first)
    second["run_id"] = "recovered"
    second["manifest"]["dataset_hashes"]["corpus"] = "c" * 64
    candidates = subject.candidates_from_cells([first, second])
    predecessor = _plan(candidates, cap=2)
    path = tmp_path / "predecessor.json"
    subject._write_new(path, predecessor)
    previous_bytes = path.read_bytes()
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    old_questions = {by_id[row["input_identity_sha256"]]["rendered_input"][0]["content"]
                     for row in predecessor["selected"]}
    old_question = sorted(old_questions)[0]
    alias_question = next(row["rendered_input"][0]["content"] for row in candidates
                          if row["rendered_input"][0]["content"] not in old_questions)
    def builder(row):
        messages = copy.deepcopy(row["rendered_input"])
        # A later source condition can produce an already-issued API request.
        # Corpus-subset aliases alone would all be inside the previous prefix
        # and would not exercise exclusion across old and new selections.
        if messages[0]["content"] == alias_question:
            messages[0]["content"] = old_question
        return {"model": TARGET, "messages": messages, "max_tokens": 2048}

    plan = subject.build_distinct_plan(
        candidates=candidates, predecessor=predecessor,
        predecessor_descriptor=subject._descriptor(path), source_prefix_cap=len(candidates),
        call_cap=20, request_builder=builder, **_bindings(),
    )
    assert plan["schema"] == subject.DISTINCT_SCHEMA
    groups = plan["selection"]["request_groups"]
    assert len({row["request_sha256"] for row in groups}) == len(groups) == len(plan["selected"])
    assert not {row["request_sha256"] for row in groups} & set(plan["selection"]["previous_request_sha256"])
    assert any(len(group["source_input_ids"]) > 1 for group in groups)
    resolved = subject.resolve_inputs(plan, candidates=candidates, request_builder=builder, **_bindings())
    assert {row["input_identity_sha256"] for row in resolved} == {row["representative_input_sha256"] for row in groups}
    assert path.read_bytes() == previous_bytes
    assert _plan(candidates, cap=2) == predecessor
    changed = copy.deepcopy(plan)
    changed["selection"]["request_groups"][0]["source_input_ids"].pop()
    changed["plan_id"] = "hosted-inputs-" + subject._sha({key: value for key, value in changed.items() if key != "plan_id"})[:24]
    with pytest.raises(ValueError, match="membership changed"):
        subject.resolve_inputs(changed, candidates=candidates, request_builder=builder, **_bindings())
    with pytest.raises(ValueError, match="offline provider request builder"):
        subject.resolve_inputs(plan, candidates=candidates, **_bindings())


def test_distinct_continuation_refuses_changed_predecessor_and_nonextension(tmp_path):
    candidates = subject.candidates_from_cells([_cell(tmp_path, count=8)])
    predecessor = _plan(candidates, cap=2)
    path = tmp_path / "predecessor.json"
    subject._write_new(path, predecessor)
    descriptor = subject._descriptor(path)
    kwargs = dict(candidates=candidates, predecessor=predecessor,
                  predecessor_descriptor=descriptor, call_cap=4,
                  request_builder=lambda row: {"messages": row["rendered_input"]}, **_bindings())
    with pytest.raises(ValueError, match="larger whole-source prefix"):
        subject.build_distinct_plan(source_prefix_cap=2, **kwargs)
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="predecessor artifact changed"):
        subject.build_distinct_plan(source_prefix_cap=8, **kwargs)


@pytest.mark.parametrize("cap", [0, -1, True, 21])
def test_budget_cap_cannot_expand(tmp_path: Path, cap) -> None:
    with pytest.raises(ValueError, match="global input cap"):
        _plan(subject.candidates_from_cells([_cell(tmp_path)]), cap)


def test_retries_and_changed_input_never_silently_pass(tmp_path: Path) -> None:
    candidates = subject.candidates_from_cells([_cell(tmp_path)])
    budget = _budget()
    budget["routes"][0]["answer_retries"] = 1
    material = {key: value for key, value in budget.items() if key != "projection_id"}
    budget["projection_id"] = "hosted-budget-" + subject._sha(material)[:24]
    with pytest.raises(ValueError, match="retries differ"):
        _plan(candidates, budget=budget)
    plan = _plan(candidates)
    candidates[0]["rendered_input"][0]["content"] = "Changed input"
    with pytest.raises(ValueError, match="input identity changed"):
        subject.resolve_inputs(plan, candidates=candidates, **_bindings())


def test_resigned_selection_changes_still_fail_source_rebuild(tmp_path: Path) -> None:
    candidates = subject.candidates_from_cells([_cell(tmp_path)])
    plan = _plan(candidates)
    plan["selected"][0]["local_sources"][0]["attempt_id"] = "another-input"
    material = {key: value for key, value in plan.items() if key != "plan_id"}
    plan["plan_id"] = "hosted-inputs-" + subject._sha(material)[:24]
    with pytest.raises(ValueError, match="membership changed"):
        subject.resolve_inputs(plan, candidates=candidates, **_bindings())


def test_write_is_create_only(tmp_path: Path) -> None:
    path = tmp_path / "plan.json"
    subject._write_new(path, {"retained": "original"})
    with pytest.raises(ValueError, match="create-only"):
        subject._write_new(path, {"replacement": "must not overwrite"})
    assert json.loads(path.read_text())["retained"] == "original"


def test_resolver_rechecks_retained_artifact_bytes(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    candidates = subject.candidates_from_cells([cell])
    plan = _plan(candidates)
    cell["artifacts"]["attempts"].write_text("changed source bytes", encoding="utf-8")
    from ura.artifact_checks import artifact_verification
    with artifact_verification(verify_sha256=True), pytest.raises(ValueError, match="bytes changed"):
        subject.resolve_inputs(plan, candidates=candidates, **_bindings())
