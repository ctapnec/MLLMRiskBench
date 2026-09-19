"""The operator manual is a maintained interface, not a second historical flow."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
FILES = ['README.md', 'docs/README.md', 'docs/SMALL_CAMPAIGNS.md',
    'docs/SMALL_API_CAMPAIGN.md', 'docs/SMALL_LOCAL_CAMPAIGN.md',
    'docs/CAMPAIGN_RESULTS_AND_ANALYSIS.md', 'docs/UI_CAMPAIGN_WALKTHROUGH.md',
    'docs/CAMPAIGN_WORKSPACES.md', 'docs/UI_WORKFLOW_SIMPLIFICATION.md',
    'docs/OPERATOR_REGRESSION_AUDIT.md', 'docs/RESPONSE_SVM.md',
    'docs/HUMAN_REVIEW_UI.md', 'docs/ARCHITECTURE.md', 'experiments/RUN_AND_RETURN.md']


def prose(path):
    return re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', path.read_text(encoding='utf-8'),
                  flags=re.MULTILINE | re.DOTALL)


def anchors(path):
    seen = {}
    result = set()
    for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', prose(path), re.MULTILINE):
        heading = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', heading)
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug + ('-' + str(count) if count else ''))
    result.update(re.findall(r'<(?:a|span)\s+(?:id|name)=["\']([^"\']+)', prose(path)))
    return result


def test_operator_markdown_links_and_section_anchors_resolve():
    problems = []
    for relative in FILES:
        path = ROOT / relative
        for target in re.findall(r'\[[^]\n]+\]\(([^)\s]+)\)', prose(path)):
            url = urlsplit(target)
            if url.scheme or url.netloc or url.path.startswith('/'):
                continue
            linked = (path.parent / unquote(url.path)).resolve() if url.path else path
            if linked.suffix.lower() != '.md':
                continue
            if not linked.is_file():
                problems.append(f'{relative}: missing {target}')
            elif url.fragment and unquote(url.fragment) not in anchors(linked):
                problems.append(f'{relative}: absent section {target}')
    assert not problems, '\n'.join(problems)


def test_combined_guide_preserves_local_actions_and_reference_limits():
    text = (ROOT/'docs/SMALL_CAMPAIGNS.md').read_text(encoding='utf-8')
    required = ['Reference result, not a required outcome', '319-token answer',
        'three diagnostic records', 'not zero-cost computing',
        'Prepare assessment and review', 'Start or resume assessment',
        'Prepared assessments and progress', 'Transport evidence expired',
        'Download personal evaluations', 'Defer / opt out of this item',
        'Create study and assign reviewers', 'Submit independent',
        'Submit adjudication', 'Export and run human audit analysis',
        'Compare job outputs', 'Show SVM results', 'Matched local and hosted response classifiers',
        'Resume unfinished analysis', 'local campaign itself for its own input',
        '12-request cap', 'seven measured inputs', 'not prices for a new selection']
    normalized = re.sub(r'\s+', ' ', text)
    missing = [item for item in required if item not in normalized]
    assert not missing, missing
    assert re.findall(r'^## (\d+)\.', text, re.MULTILINE) == [str(i) for i in range(1, 11)]
    for obsolete in ('Prepare replay inputs', 'Prepare forecast', 'Prepare selected inputs'):
        assert f'**{obsolete}**' not in text


def test_old_guides_are_short_redirects_not_diverging_recipes():
    for name in ('SMALL_API_CAMPAIGN.md','SMALL_LOCAL_CAMPAIGN.md','CAMPAIGN_RESULTS_AND_ANALYSIS.md'):
        text = (ROOT/'docs'/name).read_text(encoding='utf-8')
        assert 'SMALL_CAMPAIGNS.md' in text
        assert len(text.splitlines()) <= 20
