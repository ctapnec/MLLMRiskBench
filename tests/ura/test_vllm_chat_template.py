"""Real legacy LLaVA-Mistral template shapes, without model construction."""
from __future__ import annotations

import copy
import hashlib
import sys
from types import SimpleNamespace

import pytest

from ura.converters.gptgeochat import _system_prompt
from ura.data_models import DialogTurn
from ura.targets.local import (
    VLLMTarget, _LEGACY_MISTRAL_INST_TEMPLATES, _vllm_chat_template_messages,
)


# Verbatim sealed tokenizer_config chat_template strings. The RR variant's
# assistant output has a leading space; the base variant does not.
BASE_TEMPLATE = (
    "{{ bos_token }}{% for message in messages %}{% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}"
    "{{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}{% endif %}"
    "{% if message['role'] == 'user' %}{{ '[INST] ' + message['content'] + ' [/INST]' }}"
    "{% elif message['role'] == 'assistant' %}{{ message['content'] + eos_token}}{% else %}"
    "{{ raise_exception('Only user and assistant roles are supported!') }}{% endif %}{% endfor %}"
)
RR_TEMPLATE = BASE_TEMPLATE.replace("{{ message['content'] + eos_token}}", "{{ ' ' + message['content'] + eos_token}}")


def engine(template):
    return SimpleNamespace(get_tokenizer=lambda: SimpleNamespace(chat_template=template))


def render(template, messages):
    jinja = pytest.importorskip("jinja2")
    def reject(message):
        raise ValueError(message)
    return jinja.Environment().from_string(template).render(
        messages=messages, bos_token="<s>", eos_token="</s>", raise_exception=reject)


@pytest.mark.parametrize("template", [BASE_TEMPLATE, RR_TEMPLATE])
def test_exact_templates_fold_original_system_text_without_fabricating_turns(template):
    system = _system_prompt("country")
    user = " RECORDED CONVERSATION:\nUSER: Where is this?\nASSISTANT: Country A.\n\nMODERATION DECISION: "
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user},
                {"role": "assistant", "content": "LABEL: yes"}, {"role": "user", "content": "Explain."}]
    before = copy.deepcopy(messages)
    with pytest.raises(ValueError, match="alternate"):
        render(template, messages)
    mapped, policy = _vllm_chat_template_messages(messages, engine(template))
    digest = hashlib.sha256(template.encode()).hexdigest()
    assert digest in _LEGACY_MISTRAL_INST_TEMPLATES
    assert policy == {"policy": "leading_system_in_mistral_inst_v1", "template_sha256": digest}
    assert messages == before
    assert [message["role"] for message in mapped] == ["user", "assistant", "user"]
    assert mapped[0]["content"] == system + "\n\n" + user
    assert mapped[1:] == messages[2:]
    rendered = render(template, mapped)
    assert system in rendered and user in rendered


@pytest.mark.parametrize("template", [BASE_TEMPLATE, RR_TEMPLATE])
@pytest.mark.parametrize("image_first", [False, True])
def test_system_prefix_preserves_exact_multimodal_parts_and_image_order(template, image_first):
    images = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,first"}},
              {"type": "image_url", "image_url": {"url": "data:image/png;base64,second"}}]
    text = {"type": "text", "text": "\nOriginal transcript text.  "}
    parts = [images[0], text, images[1]] if image_first else [text, *images]
    messages = [{"role": "system", "content": " Original policy. "}, {"role": "user", "content": parts}]
    before = copy.deepcopy(messages)
    mapped, policy = _vllm_chat_template_messages(messages, engine(template))
    assert messages == before and len(mapped) == 1
    assert policy["policy"] == "leading_system_in_mistral_inst_v1"
    retained = mapped[0]["content"]
    assert [part for part in retained if part["type"] == "image_url"] == images
    assert "".join(part["text"] for part in retained if part["type"] == "text") == (
        " Original policy. \n\n" + text["text"])


@pytest.mark.parametrize("template", [BASE_TEMPLATE, RR_TEMPLATE])
@pytest.mark.parametrize("roles", [
    ["system", "assistant"], ["system", "user", "user"], ["system", "user", "system"],
    ["system", "system", "user"], ["user", "user"],
])
def test_invalid_role_sequences_are_still_refused_by_original_template(template, roles):
    messages = [{"role": role, "content": "original"} for role in roles]
    mapped, _policy = _vllm_chat_template_messages(messages, engine(template))
    with pytest.raises(ValueError, match="alternate|Only user"):
        render(template, mapped)


@pytest.mark.parametrize("template", [BASE_TEMPLATE + "\n", "{{ messages }}", None])
def test_supported_or_unrecognized_templates_remain_unchanged(template):
    messages = [{"role": "system", "content": "policy"}, {"role": "user", "content": "question"}]
    mapped, policy = _vllm_chat_template_messages(messages, engine(template))
    assert mapped is messages and policy == {"policy": "native"}


def test_already_native_conversation_does_not_even_query_tokenizer():
    messages = [{"role": "user", "content": "question"}]
    mapped, policy = _vllm_chat_template_messages(messages, object())
    assert mapped is messages and policy == {"policy": "native"}


def test_generation_records_rendering_policy_and_retains_original_input_fingerprint(monkeypatch):
    from ura.targets.api import _dialog_fingerprint
    dialog = [DialogTurn(role="system", content=_system_prompt("country")),
              DialogTurn(role="user", content="Recorded conversation. LABEL:")]
    before = [turn.model_dump() for turn in dialog]
    calls = []
    class Engine:
        get_tokenizer = staticmethod(lambda: SimpleNamespace(chat_template=RR_TEMPLATE))
        def chat(self, messages, sampling):
            calls.append((messages, sampling))
            assert render(RR_TEMPLATE, messages)
            return [SimpleNamespace(prompt_token_ids=[1, 2], outputs=[SimpleNamespace(
                text="LABEL: no", token_ids=[3], finish_reason="stop", stop_reason=None)])]
    runtime = SimpleNamespace(private_execution=lambda _role, callback: callback())
    target = VLLMTarget("fixture", revision="a" * 40, max_tokens=4096, model_runtime=runtime)
    monkeypatch.setattr(target, "_engine", lambda: Engine())
    monkeypatch.setitem(sys.modules, "vllm", SimpleNamespace(SamplingParams=lambda **kwargs: kwargs))
    response = target.generate(dialog, seed=0)
    assert [turn.model_dump() for turn in dialog] == before
    assert len(calls) == 1 and calls[0][1]["max_tokens"] == 4096 and calls[0][1]["seed"] == 0
    assert response.attempt_id == _dialog_fingerprint(dialog)
    assert response.output_turns[0].content == "LABEL: no"
    assert response.raw["chat_template_rendering"] == {
        "policy": "leading_system_in_mistral_inst_v1",
        "template_sha256": hashlib.sha256(RR_TEMPLATE.encode()).hexdigest()}
