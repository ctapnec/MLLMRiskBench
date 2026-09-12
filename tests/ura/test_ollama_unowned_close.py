"""Closing a read-only console must not contend with the active GPU owner."""
from types import SimpleNamespace

from experiments.rig_web_app import ollama_service as service_module


def test_unowned_close_does_not_acquire_inference_lock(tmp_path, monkeypatch):
    service = service_module.OllamaService(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("Unowned service attempted to acquire the inference lock")
    monkeypatch.setattr(service_module, "OllamaProcessLock", forbidden)
    monkeypatch.setattr(service, "_api_state", forbidden)
    monkeypatch.setattr(service, "_terminate_owned_locked", forbidden)
    service.close()


def test_owned_close_still_serializes_and_cleans_up_its_process(tmp_path, monkeypatch):
    service = service_module.OllamaService(tmp_path)
    service._owned_process = SimpleNamespace(poll=lambda: None)
    events = []
    class Lock:
        def __init__(self, **kwargs):
            assert kwargs["exclusive"] is True
        def __enter__(self):
            events.append("locked")
            return self
        def __exit__(self, *args):
            events.append("unlocked")
    monkeypatch.setattr(service_module, "OllamaProcessLock", Lock)
    monkeypatch.setattr(service, "_terminate_owned_locked", lambda **kwargs: events.append("stopped_owned"))
    service.close()
    assert events == ["locked", "stopped_owned", "unlocked"]
