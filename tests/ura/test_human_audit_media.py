"""Prepared media is resolved once and unavailable rows remain in the sample."""
import csv
import json
from pathlib import Path

import pytest

from experiments import human_audit_media as media
from ura.data_models import DataPoint, MediaRef


def sample(path, digest):
    ref=dict(locator='@content-sha256/'+digest, sha256=digest, mime='image/png', modality='image')
    with path.open('w', encoding='utf-8-sig', newline='') as stream:
        writer=csv.DictWriter(stream, fieldnames=['run_id','media_references'])
        writer.writeheader();writer.writerow(dict(run_id='run-selected',media_references=json.dumps([ref])))


def test_native_source_media_connected_without_dropping_or_rewriting_sample(tmp_path, monkeypatch):
    digest='a'*64; asset=tmp_path/'original.png';asset.write_bytes(b'retained media')
    prepared=tmp_path/'sample.csv';sample(prepared,digest);original=prepared.read_bytes()
    (tmp_path/'cell__run-selected.manifest.json').write_text('{"test":"selected"}')
    (tmp_path/'cell__run-unselected.manifest.json').write_text('not selected or opened')
    point=DataPoint(id='original', source='fixture', modalities=['text','image'],
        media=[MediaRef(path=str(asset),mime='image/png',modality='image',sha256=digest)],
        risk_category='jailbreak',expected_behavior='refuse')
    calls=[]
    def populations(cells):
        calls.append(cells);return {'run-selected':[point]}
    monkeypatch.setattr(media,'source_populations',populations)
    result=media.prepare_media_index(tmp_path,prepared)
    assert calls==[[dict(run_id='run-selected',manifest={'test':'selected'})]]
    assert result['status']=='resolved' and result['resolved_references']==1
    assert json.loads(prepared.with_suffix('.MEDIA.json').read_text())=={digest:str(asset)}
    assert prepared.read_bytes()==original


def test_existing_index_avoids_source_scan_or_conversion(tmp_path, monkeypatch):
    digest='a'*64;asset=tmp_path/'original.png';asset.write_bytes(b'retained media')
    prepared=tmp_path/'sample.csv';sample(prepared,digest)
    supplied=tmp_path/'supplied.json';supplied.write_text(json.dumps({digest:str(asset)}))
    monkeypatch.setattr(Path,'rglob',lambda *a:pytest.fail('Already-resolved input rescanned'))
    monkeypatch.setattr(media,'source_populations',lambda *a:pytest.fail('Already-resolved input reconverted'))
    assert media.prepare_media_index(tmp_path,prepared,supplied)['status']=='resolved'


def test_unavailable_media_report_preserves_the_row(tmp_path):
    prepared=tmp_path/'sample.csv';sample(prepared,'a'*64);original=prepared.read_bytes()
    result=media.prepare_media_index(tmp_path,prepared)
    assert result['status']=='media_unavailable'
    assert result['outputs_with_unavailable_media']==1 and result['resolved_references']==0
    assert result['unresolved_content']==['a'*64] and result['errors']
    assert prepared.read_bytes()==original


def test_cli_preparation_always_connects_media_and_ui_catalog_passes_index(tmp_path, monkeypatch):
    from experiments import human_audit as audit
    from experiments.rig_web_app.catalog import build_argv
    called=[]
    monkeypatch.setattr(audit,'prepare_sample',lambda *a, **k:0)
    monkeypatch.setattr(media,'prepare_media_index',lambda *a:called.append(a))
    values={'--results':str(tmp_path),'--prepare':'1','--output':str(tmp_path/'sample.csv'),
            '--media-index':str(tmp_path/'index.json'),'--acknowledge-sensitive-content':'1'}
    argv=build_argv('human_audit',values)
    assert '--media-index' in argv
    assert audit.main(argv[argv.index('experiments.human_audit')+1:])==0
    assert called==[(tmp_path,tmp_path/'sample.csv',tmp_path/'index.json')]
