import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from experiments.campaign_spending import reserve, spending


def call(path,policy,amount):
    return reserve(path,policy,provider='anthropic',model='test',amount=amount,input_tokens=10,output_tokens=20)


def test_attempt_ceiling_counts_retries_and_survives_reopen(tmp_path):
    path=tmp_path/'spending.sqlite';policy={'max_microusd':100}
    call(path,policy,40);call(path,policy,40)
    with pytest.raises(ValueError,match='ceiling reached'):call(path,policy,40)
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT used FROM allowance').fetchone()==(80,)
        assert db.execute('SELECT COUNT(*) FROM attempts').fetchone()==(2,)
    with pytest.raises(ValueError,match='settings changed'):call(path,{'max_microusd':200},1)


def test_parallel_attempts_share_one_allowance(tmp_path):
    path=tmp_path/'spending.sqlite';policy={'max_microusd':100}
    call(path,policy,0)
    def attempt(_):
        try:call(path,policy,30);return True
        except ValueError:return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt,range(8)))==3


def test_context_checks_request_before_every_physical_attempt(tmp_path,monkeypatch):
    from ura.targets import api
    from experiments import hosted_request_tokens
    path=tmp_path/'policy.json'
    path.write_text(json.dumps(dict(max_microusd=100,routes=[dict(provider='anthropic',model='test',spec='anthropic:test',config={},input_price=1,output_price=5)])))
    monkeypatch.setattr(api,'build_api_target',lambda *a,**kw:object())
    monkeypatch.setattr(hosted_request_tokens,'cached_count_request',lambda *a,**kw:{'input_tokens':10})
    with spending(path):
        callback=api._PROVIDER_ATTEMPT_ADMISSION.get()
        callback('anthropic',{'model':'test','max_tokens':10},1)
        with pytest.raises(ValueError,match='ceiling reached'):
            callback('anthropic',{'model':'test','max_tokens':10},2)
        with pytest.raises(ValueError,match='outside'):
            callback('anthropic',{'model':'other','max_tokens':1},1)
    assert api._PROVIDER_ATTEMPT_ADMISSION.get() is None
