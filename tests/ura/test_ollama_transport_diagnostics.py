"""Native transport errors must not masquerade as generation timeouts."""
import errno
import io
import json
import urllib.error

import pytest

from ura.targets.local import LocalTargetAnswerError, OllamaTarget


def target(monkeypatch, error):
    instance = OllamaTarget('fixture:latest', model_digest='a' * 64,
        num_ctx=8192, num_predict=512, timeout=120)

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(instance, '_open_request', fail)
    return instance


@pytest.mark.parametrize('code,body,detail', [
    (400, json.dumps({'error': 'invalid image format'}).encode(), 'invalid image format'),
    (500, b'not JSON', ''),
    (500, json.dumps({'error': 'x' * 6000}).encode(), ''),
])
def test_native_http_error_keeps_status_without_false_timeout(monkeypatch, code, body, detail):
    error = urllib.error.HTTPError('http://127.0.0.1:11434/api/chat', code,
        'native rejection', {}, io.BytesIO(body))
    instance = target(monkeypatch, error)
    with pytest.raises(LocalTargetAnswerError, match=f'HTTP {code}') as caught:
        instance._chat_http([{'role': 'user', 'content': 'probe'}])
    assert caught.value.category == 'transport_failure'
    assert 'deadline' not in str(caught.value)
    assert detail in str(caught.value)
    assert len(str(caught.value)) < 600
    assert error.closed


def test_connection_failure_is_not_reported_as_timeout(monkeypatch):
    instance = target(monkeypatch, urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, 'refused')))
    with pytest.raises(LocalTargetAnswerError, match='ConnectionRefusedError') as caught:
        instance._chat_http([{'role': 'user', 'content': 'probe'}])
    assert 'deadline' not in str(caught.value)
    assert caught.value.category == 'transport_failure'


@pytest.mark.parametrize('wrapped', [False, True])
def test_real_timeout_remains_a_timeout(monkeypatch, wrapped):
    error = TimeoutError('deadline')
    instance = target(monkeypatch, urllib.error.URLError(error) if wrapped else error)
    with pytest.raises(LocalTargetAnswerError, match='configured hard 120s deadline'):
        instance._chat_http([{'role': 'user', 'content': 'probe'}])
