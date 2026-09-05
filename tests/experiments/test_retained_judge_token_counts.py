"""A provider estimate funds the exact Haiku request without a byte-count floor."""
import copy
import json
from types import SimpleNamespace

import pytest

from experiments import hosted_request_tokens as counts
from experiments import retained_response_judge_execute as subject
from test_retained_judge_shared_budget import HookHaiku, JUDGE, prepared_shared
from ura.judges.llm import LLMJudge


def _counted(tmp_path, monkeypatch):
    prepared, kwargs, budget, config, items = prepared_shared(tmp_path, monkeypatch, slot_bound=3000)
    target = subject._build_haiku_judge(JUDGE, config)
    judge = LLMJudge(target)
    observed = []

    def count_tokens(**body):
        observed.append(copy.deepcopy(body))
        return SimpleNamespace(input_tokens=70)

    client = SimpleNamespace(messages=SimpleNamespace(count_tokens=count_tokens))
    client.with_options = lambda **options: client
    monkeypatch.setattr(target, "_get_client", lambda: client)
    token_counts = {}
    for row, prompt, text in items:
        point, response = subject._judge_inputs(row, prompt, text)
        body = target.build_request(judge.build_judge_dialog(point, response), seed=judge._judge_seed(response))
        token_counts[row["retained_row_sha256"]] = counts.count_request(target, body, allow_network=True)
    ids = {key: value["call_id"] for key, value in kwargs["shared_requests"].items()}
    kwargs["shared_requests"] = subject.build_shared_request_receipts(
        items, judge_model=JUDGE, normalized_api=config, call_ids=ids, token_counts=token_counts)
    return prepared, kwargs, budget, config, observed


def test_provider_count_funds_full_rubric_without_recounting_on_resume(tmp_path, monkeypatch):
    prepared, kwargs, budget, config, observed = _counted(tmp_path, monkeypatch)
    assert len(observed) == 2
    assert all(value["input_tokens_estimate"] == 70 for value in kwargs["shared_requests"].values())
    assert all(value["token_count_receipt"]["method"] == "provider_estimate"
               for value in kwargs["shared_requests"].values())
    fake = HookHaiku(config)
    complete = subject.execute(**kwargs, judge_factory=lambda *_: fake)
    assert fake.http_calls == 2 and budget.snapshot()["pools"]["anthropic:judge"]["settled_cost_microusd"] == 320
    binding = json.loads((prepared["out"] / "shared-budget.json").read_text())
    assert binding["input_token_estimate_method"] == "per_request_token_count_receipt_v1"
    assert subject.execute(**kwargs, judge_factory=lambda *_: fake) == complete
    assert fake.http_calls == 2 and len(observed) == 2


@pytest.mark.parametrize("change", ["request", "model", "partial"])
def test_count_for_wrong_request_model_or_partial_selection_refuses_before_client(tmp_path, monkeypatch, change):
    _, kwargs, _, _, observed = _counted(tmp_path, monkeypatch)
    first = next(iter(kwargs["shared_requests"].values()))
    if change == "partial":
        first.pop("token_count_receipt")
    elif change == "request":
        first["token_count_receipt"]["request_sha256"] = "0" * 64
    else:
        first["token_count_receipt"]["requested_model"] = "another-model"
    with pytest.raises(ValueError):
        subject.execute(**kwargs, judge_factory=lambda *_: pytest.fail("client before count validation"))
    assert len(observed) == 2
