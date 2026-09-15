"""Operator documents must retain the shared menu, theme and backend-wait guard."""
import pytest
from html.parser import HTMLParser
from experiments.rig_web import RigWebApp
from experiments.rig_web_app.ui import _NAV_LINKS
from test_human_review_ui import review  # noqa: F401


class MenuParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.active=[]

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='a' and attrs.get('class')=='active':
            self.active.append(attrs['href'])


def assert_navigation(page,active):
    assert page.count('<nav>')==1
    menu=page.split('<nav>',1)[1].split('</nav>',1)[0]
    for href,_,label in _NAV_LINKS:
        assert "href='"+href+"'" in menu and label+'</a>' in menu
    parsed=MenuParser();parsed.feed(menu)
    assert parsed.active==[href for href,_,label in _NAV_LINKS if label==active]
    assert "id='theme-picker'" in menu
    assert "id='busy-overlay'" in page
    assert "<footer class='note'>" in page


@pytest.mark.parametrize('route,active',[
    ('/','Dashboard'),('/build','Build'),('/campaigns','Campaigns'),
    ('/commands','Tools'),('/commands?cmd=response_svm','Tools'),('/jobs','Jobs'),
    ('/stats','Stats'),('/config','Config'),('/config/secrets','Config'),
    ('/artifacts','Artifacts'),('/human-evaluation','Campaigns'),
])
def test_operator_pages_share_the_full_navigation(tmp_path,route,active):
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
        gpu_hardware={},system_hardware={})
    try:
        status,mime,body=app.handle('GET',route)
        assert status==200 and mime.startswith('text/html')
        assert_navigation(body.decode(),active)
    finally:app.close()


@pytest.mark.parametrize('role',['rater','adjudicator'])
def test_review_roles_keep_navigation_before_and_after_consent(tmp_path,review,monkeypatch,role):
    store,_,raters,adjudicator=review
    token=raters[0] if role=='rater' else adjudicator
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'console',repo_root=tmp_path,
        gpu_hardware={},system_hardware={})
    monkeypatch.setattr(app,'_human_store',lambda:store)
    try:
        for consented in (False,True):
            if consented:store.consent(token)
            status,mime,body=app.handle('GET','/review/'+token)
            assert status==200 and mime.startswith('text/html')
            assert_navigation(body.decode(),'Campaigns')
    finally:app.close()
