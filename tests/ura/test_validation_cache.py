import multiprocessing
import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ura.validation_cache import ValidationCache, observe_validation_path


def test_unchanged_inputs_reuse_validation_and_results_are_not_mutable_aliases(tmp_path):
    path = tmp_path / "input"
    path.write_text("old")
    time.sleep(1.05)  # The cache deliberately rereads still-changing fresh files.
    calls = []
    cache = ValidationCache()

    def read():
        calls.append(1)
        return {"text": path.read_text()}

    first = cache.get("key", read, paths=(path,))
    first["text"] = "caller mutation"
    assert cache.get("key", read, paths=(path,)) == {"text": "old"}
    assert len(calls) == 1
    before = path.stat()
    time.sleep(0.01)  # Advance the filesystem tick before a same-size rewrite.
    path.write_text("new")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert cache.get("key", read, paths=(path,)) == {"text": "new"}
    assert len(calls) == 2
    cache.get("different configuration", read, paths=(path,))
    assert len(calls) == 3


def test_tree_additions_deletions_and_indirect_inputs_invalidate(tmp_path):
    root = tmp_path / "results"
    root.mkdir()
    outside = tmp_path / "config"
    outside.write_text("1")
    time.sleep(1.05)
    calls = []
    cache = ValidationCache()

    def read():
        observe_validation_path(outside)
        calls.append(1)
        return outside.read_text()

    cache.get("key", read, trees=(root,))
    cache.get("key", read, trees=(root,))
    assert len(calls) == 1
    (root / "new-result").write_text("result")
    cache.get("key", read, trees=(root,))
    (root / "new-result").unlink()
    cache.get("key", read, trees=(root,))
    outside.write_text("2")
    assert cache.get("key", read, trees=(root,)) == "2"
    assert len(calls) == 4


def test_parallel_requests_validate_once_and_failed_validation_is_not_cached(tmp_path):
    path = tmp_path / "input"
    path.write_text("input")
    time.sleep(1.05)
    cache = ValidationCache()
    calls = []

    def read():
        calls.append(1)
        return "valid"

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: cache.get("key", read, paths=(path,)), range(24))) == ["valid"] * 24
    assert len(calls) == 1
    for _ in range(2):
        with pytest.raises(ValueError):
            cache.get("failed", lambda: (_ for _ in ()).throw(ValueError("invalid")), paths=(path,))


def test_recent_same_tick_rewrite_is_not_hidden_by_reuse(tmp_path, monkeypatch):
    from ura import validation_cache as module
    path = tmp_path / "recent"
    path.write_text("old")
    shared_tick = module._metadata(path)
    monkeypatch.setattr(module, "_metadata", lambda *a, **kw: shared_tick)
    cache = ValidationCache()
    assert cache.get("key", path.read_text, paths=(path,)) == "old"
    path.write_text("new")
    assert cache.get("key", path.read_text, paths=(path,)) == "new"


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="rig fork behavior")
def test_controller_validation_is_reused_by_forked_workers(tmp_path):
    path = tmp_path / "source"
    path.write_text("retained")
    time.sleep(1.05)
    context = multiprocessing.get_context("fork")
    calls = context.Value("i", 0)
    cache = ValidationCache(copy_results=False)

    def read():
        with calls.get_lock():
            calls.value += 1
        return path.read_text()

    assert cache.get("source", read, paths=(path,)) == "retained"

    def worker():
        assert cache.get("source", read, paths=(path,)) == "retained"

    workers = [context.Process(target=worker) for _ in range(2)]
    for child in workers:
        child.start()
    for child in workers:
        child.join(timeout=10)
        assert child.exitcode == 0
    assert calls.value == 1


def test_stats_reuses_unchanged_accounting_but_explicit_hashing_bypasses(tmp_path, monkeypatch):
    from experiments.rig_web_app import artifacts

    calls = []
    monkeypatch.setattr(artifacts, "_USAGE_CACHE", ValidationCache())
    monkeypatch.setattr(artifacts, "_collect_usage", lambda *a, **kw: calls.append(kw) or ([], {"markers": 1}))
    path = tmp_path / "result"
    path.write_text("first")
    time.sleep(1.05)
    artifacts.collect_usage(tmp_path)
    artifacts.collect_usage(tmp_path)
    assert len(calls) == 1
    path.write_text("second")
    artifacts.collect_usage(tmp_path)
    artifacts.collect_usage(tmp_path, verify_sha=True)
    assert len(calls) == 3 and calls[-1]["verify_sha"] is True


def test_hosted_context_reuses_sources_not_route_budgets(tmp_path, monkeypatch):
    from experiments import hosted_retained_execute as execution
    from ura.artifact_checks import artifact_verification

    for name in ("view", "rr"):
        (tmp_path / name).mkdir()
    source = tmp_path / "historical-result"
    source.write_text("history")
    indirect = tmp_path / "original-response"
    indirect.write_text("answer")
    time.sleep(1.05)
    program = {"results_root": str(tmp_path), "runner_view": str(tmp_path / "view"),
               "rr_analysis_root": str(tmp_path / "rr"),
               "sources": {"historical_result": {"path": str(source), "sha256": "a" * 64}}}
    calls = []

    def load(program):
        observe_validation_path(indirect)
        calls.append(1)
        return [], {"inventory": "retained"}

    monkeypatch.setattr(execution, "_LOCAL_CONTEXT_CACHE", ValidationCache(entries=1, copy_results=False))
    monkeypatch.setattr(execution, "_load_local_cells", load)
    execution._validated_local_cells(program)
    execution._validated_local_cells({**program, "target": "another provider", "budget": "different live budget"})
    assert len(calls) == 1
    indirect.write_text("changed answer")
    execution._validated_local_cells(program)
    assert len(calls) == 2
    with artifact_verification(verify_sha256=True):
        execution._validated_local_cells(program)
    assert len(calls) == 3
