import json
import os
from types import SimpleNamespace

import pytest

from ura import guardrail_setup as subject


def installed(root, model=subject.DEFAULT_GUARDRAIL_MODEL, revision='a'*40, number=0):
    folder=root/f'hf-{number:032x}'
    (folder/'snapshot').mkdir(parents=True)
    path=folder/f'hf-manifest-{number:032x}.upstream-manifest.json'
    path.write_text(json.dumps(dict(repo_id=model,revision=revision)))
    return path


def test_installed_revision_is_resolved_without_reading_weights(tmp_path,monkeypatch):
    path=installed(tmp_path)
    (path.parent/'snapshot/config.json').write_text(json.dumps({'_name_or_path':'wrong-base-model'}))
    monkeypatch.setenv('URA_MODEL_STORE',str(tmp_path))
    assert subject.resolve_scoring_settings({}) == dict(guardrail_model=subject.DEFAULT_GUARDRAIL_MODEL,
                                                       guardrail_revision='a'*40)
    assert subject.installed_guardrail_revision(subject.DEFAULT_GUARDRAIL_MODEL,'b'*40,store=tmp_path)=='b'*40


def test_other_model_and_incomplete_install_cannot_supply_revision(tmp_path):
    installed(tmp_path,'different/model')
    with pytest.raises(subject.GuardrailSetupError,match='not installed'):
        subject.installed_guardrail_revision(subject.DEFAULT_GUARDRAIL_MODEL,store=tmp_path)


def test_latest_installed_copy_is_selected_but_saved_pin_remains_stable(tmp_path):
    older=installed(tmp_path,revision='a'*40,number=0)
    newer=installed(tmp_path,revision='b'*40,number=1)
    os.utime(older,ns=(100,100))
    os.utime(newer,ns=(200,200))
    assert subject.installed_guardrail_revision(subject.DEFAULT_GUARDRAIL_MODEL,store=tmp_path)=='b'*40
    assert subject.installed_guardrail_revision(subject.DEFAULT_GUARDRAIL_MODEL,'a'*40,store=tmp_path)=='a'*40


def fake_torch(free):
    return SimpleNamespace(cuda=SimpleNamespace(is_available=lambda:bool(free),device_count=lambda:len(free),
        mem_get_info=lambda index:(free[index],free[index])))


def test_automatic_placement_uses_visible_gpu_with_room(tmp_path):
    (tmp_path/'model.safetensors').write_bytes(b'0'*1024)
    gib=1024**3
    assert subject.automatic_guardrail_placement(fake_torch([gib,4*gib]),str(tmp_path))=={'device_map':{'':1}}


def test_automatic_placement_splits_only_if_needed_and_never_spills_to_cpu(tmp_path):
    # Sparse test weight metadata; no allocation or model loading.
    with (tmp_path/'model.safetensors').open('wb') as stream:
        stream.truncate(4*1024**3)
    gib=1024**3
    placement=subject.automatic_guardrail_placement(fake_torch([5*gib,5*gib]),str(tmp_path))
    assert placement=={'device_map':'auto','max_memory':{0:3*gib,1:3*gib,'cpu':0}}
    with pytest.raises(subject.GuardrailSetupError,match='will not offload'):
        subject.automatic_guardrail_placement(fake_torch([3*gib,3*gib]),str(tmp_path))


def test_cpu_only_host_remains_supported_without_manual_device(tmp_path):
    assert subject.automatic_guardrail_placement(fake_torch([]),str(tmp_path))=={'device_map':{'':'cpu'}}
