"""Provider credentials use a responsive, write-only editor without a wide table."""
from html.parser import HTMLParser

from experiments.rig_web_app.settings import SettingsMixin


def test_provider_key_cards_group_credentials_and_keep_editors_masked(monkeypatch):
    # Render only. No environment key or secrets file is read.
    class Page(SettingsMixin):
        pass

    page = Page()
    monkeypatch.setattr(page, 'secret_status', lambda: [
        {'name': name, 'label': label, 'funded': funded, 'present': name == 'GEMINI_API_KEY',
         'hint': 'set - ....1234' if name == 'GEMINI_API_KEY' else 'not set'}
        for name, label, funded in page._SECRET_ENV_VARS])
    rendered = page._secrets_page().decode()
    assert "<table>" not in rendered
    assert rendered.count("class='card provider-key-card'") == 8
    assert all(title in rendered for title in ['Campaign providers', 'Additional providers', 'Model and corpus downloads'])
    assert "grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))" in rendered
    assert "a saved key does not establish model access or available credit" in rendered
    assert "Update key" in rendered and "Add key" in rendered

    class Inputs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.passwords = []
            self.labels = set()

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'input' and attrs.get('type') == 'password':
                self.passwords.append(attrs)
            if tag == 'label':
                self.labels.add(attrs.get('for'))

    parsed = Inputs()
    parsed.feed(rendered)
    assert len(parsed.passwords) == 8
    assert all('value' not in row and row['id'] in parsed.labels and row['autocomplete'] == 'new-password'
               for row in parsed.passwords)
