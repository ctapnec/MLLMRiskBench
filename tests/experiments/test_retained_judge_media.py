import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments import retained_judge_media as subject
from experiments.retained_native_judge_prepare import NoCalls
from ura.artifact_checks import artifact_verification
from ura.targets.api import _resolve_local_media_path


def indexed(tmp_path, entries=None):
    image = tmp_path/'media'/'image.png'
    image.parent.mkdir(exist_ok=True)
    image.write_bytes(b'fixture media - this test must not hash or decode it')
    path = tmp_path/'media-index.json'
    raw = json.dumps(entries if entries is not None else {'a'*64: str(image)}).encode()
    path.write_bytes(raw)
    return dict(sources=dict(media_index=dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw)))), image


def test_no_call_reader_resolves_selected_media_without_changing_live_target_or_environment(tmp_path, monkeypatch):
    program, image = indexed(tmp_path)
    monkeypatch.setenv('URA_MEDIA_ROOTS', 'unchanged-value')
    target = SimpleNamespace(name='google:saved', modality_support=('text', 'image'), media_roots=())
    reader = NoCalls(target, program=program)
    assert _resolve_local_media_path(str(image), reader.media_roots)[0] == image
    assert target.media_roots == ()
    import os
    assert os.environ['URA_MEDIA_ROOTS'] == 'unchanged-value'
    with pytest.raises(RuntimeError, match='cannot make a target call'):
        reader.generate([])


def test_existing_root_order_is_kept_and_contained_roots_are_not_added(tmp_path):
    program, _ = indexed(tmp_path)
    first, second = tmp_path/'first', tmp_path
    assert subject.reader_media_roots(program, (first, second)) == (first, second)
    assert subject.reader_media_roots({}, (first, second)) == (first, second)


@pytest.mark.parametrize('entries', [{'bad-id':'/tmp/image'}, {'a'*64:'https://example.test/image.png'},
    {'a'*64:'relative.png'}, {'a'*64:None}])
def test_invalid_or_remote_locator_is_not_authorized(tmp_path, entries):
    program, _ = indexed(tmp_path, entries)
    with pytest.raises(ValueError, match='explicit local files'):
        subject.reader_media_roots(program)


def test_index_is_read_once_until_metadata_or_checking_mode_changes(tmp_path, monkeypatch):
    program, _ = indexed(tmp_path)
    original = subject.load_bound_json
    calls = []
    def load(*args):
        calls.append(args)
        return original(*args)
    monkeypatch.setattr(subject, 'load_bound_json', load)
    first = subject.reader_media_roots(program)
    assert subject.reader_media_roots(program) == first and len(calls) == 1
    with artifact_verification(verify_sha256=True):
        assert subject.reader_media_roots(program) == first
    assert len(calls) == 2
    path = tmp_path/'media-index.json'
    path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError, match='differs'):
        subject.reader_media_roots(program)
    assert len(calls) == 3


def test_descriptor_size_and_file_type_are_checked(tmp_path):
    program, _ = indexed(tmp_path, {'a'*64:str(tmp_path)})
    with pytest.raises(ValueError, match='not a file'):
        subject.reader_media_roots(program)
    program, _ = indexed(tmp_path)
    program['sources']['media_index']['bytes'] += 1
    with pytest.raises(ValueError, match='differs'):
        subject.reader_media_roots(program)
