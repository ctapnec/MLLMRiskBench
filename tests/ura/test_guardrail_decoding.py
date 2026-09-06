"""Classifier framing is token syntax, never a free-text prefix heuristic."""
from __future__ import annotations

import pytest

from ura.judges.guardrail import GuardrailJudge, _decode_guard_output


class Tokenizer:
    # The first observed sequence and framing IDs are from the retained
    # Llama Guard 3 tokenizer. Extra lexical tokens below are test-only.
    all_special_ids = (128006, 128007, 128009)
    tokens = {
        78191: "assistant", 19193: "safe", 128006: "<|start_header_id|>",
        128007: "<|end_header_id|>", 128009: "<|eot_id|>",
        1: "assistantsafe", 2: "user", 3: "unsafe\nS1", 4: "\nunsafe",
        5: "assistant<|end_header_id|>safe", 6: "\n", 7: " safe",
    }

    def convert_ids_to_tokens(self, token):
        return self.tokens[token]

    def decode(self, tokens, *, skip_special_tokens):
        return "".join(self.tokens[token] for token in tokens
                       if not skip_special_tokens or token not in self.all_special_ids)


@pytest.mark.parametrize(("tokens", "expected", "removed", "unsafe"), [
    ([78191, 128007, 19193, 128009], "safe", [78191, 128007], False),
    ([128006, 78191, 128007, 3, 128009], "unsafe\nS1", [128006, 78191, 128007], True),
    ([19193, 128009], "safe", [], False),
    ([1, 128009], "assistantsafe", [], None),
    ([78191, 7, 128009], "assistant safe", [], None),
    ([5, 128009], "assistant<|end_header_id|>safe", [], None),
    ([2, 128007, 19193, 128009], "usersafe", [], None),
    ([78191, 128007, 19193, 4, 128009], "safe\nunsafe", [78191, 128007], None),
    ([78191, 128007, 128009], "", [78191, 128007], None),
    ([78191, 128007, 19193, 128006, 78191, 128007, 19193, 128009],
     "assistantsafeassistantsafe", [], None),
])
def test_decoding_retains_tokens_and_only_removes_explicit_assistant_framing(
    tokens, expected, removed, unsafe,
):
    tokenizer = Tokenizer()
    output, trace = _decode_guard_output(tokenizer, tokens)
    assert output == expected
    assert trace["output_token_ids"] == tokens
    assert trace["decoded_with_special_tokens"] == tokenizer.decode(tokens, skip_special_tokens=False)
    assert trace["decoded_without_special_tokens"] == tokenizer.decode(tokens, skip_special_tokens=True)
    assert trace["removed_assistant_header_token_ids"] == removed
    assert GuardrailJudge._parse_verdict(output)[0] is unsafe


def test_judgment_preserves_the_actual_generated_framing():
    guard = GuardrailJudge(revision="b" * 40)
    output, trace = _decode_guard_output(Tokenizer(), [78191, 128007, 19193, 128009])
    guard._generation_output_trace = {**trace, "output_allowance": 20}
    judgment = guard._make_judgment(output, attempt_id="retained", subject="assistant_response")
    assert judgment.raw["parsed"] is True
    assert judgment.raw["output"] == "safe"
    assert judgment.raw["guard_generation"]["decoded_without_special_tokens"] == "assistantsafe"
    assert judgment.raw["guard_generation"]["output_token_ids"] == [78191, 128007, 19193, 128009]
    assert judgment.raw["guard_generation"]["output_allowance"] == 20
    unrelated = guard._make_judgment("unsafe\nS1", attempt_id="other", subject="assistant_response")
    assert "guard_generation" not in unrelated.raw


def test_header_spelling_without_special_token_identity_is_not_removed():
    tokenizer = Tokenizer()
    tokenizer.all_special_ids = (128009,)
    output, trace = _decode_guard_output(tokenizer, [78191, 128007, 19193, 128009])
    assert output == "assistant<|end_header_id|>safe"
    assert trace["removed_assistant_header_token_ids"] == []
    assert GuardrailJudge._parse_verdict(output)[0] is None
