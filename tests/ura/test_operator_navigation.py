"""Operator documents must retain the shared menu, theme and backend-wait guard."""
import pytest
from experiments.rig_web import RigWebApp
from experiments.rig_web_app.ui import _NAV_LINKS


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
        page=body.decode()
        assert page.count('<nav>')==1
        menu=page.split('<nav>',1)[1].split('</nav>',1)[0]
        for href,_,label in _NAV_LINKS:
            assert "href='"+href+"'" in menu and label+'</a>' in menu
        assert "class='active'" in menu and active+'</a>' in menu
        assert "id='theme-picker'" in menu
        assert "id='busy-overlay'" in page
        assert "<footer class='note'>" in page
    finally:app.close()
