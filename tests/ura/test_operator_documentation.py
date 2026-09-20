"""The operator manual is a maintained interface, not a second historical flow."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ['README.md', 'docs/README.md', 'docs/SMALL_CAMPAIGNS.md',
    'docs/SMALL_API_CAMPAIGN.md', 'docs/SMALL_LOCAL_CAMPAIGN.md',
    'docs/CAMPAIGN_RESULTS_AND_ANALYSIS.md', 'docs/UI_CAMPAIGN_WALKTHROUGH.md',
    'docs/CAMPAIGN_WORKSPACES.md', 'docs/UI_WORKFLOW_SIMPLIFICATION.md',
    'docs/OPERATOR_REGRESSION_AUDIT.md', 'docs/RESPONSE_SVM.md',
    'docs/HUMAN_REVIEW_UI.md', 'docs/ARCHITECTURE.md', 'docs/WORKSTATION_ARCHIVE_PLAN.md',
    'docs/DOCUMENTATION_MAINTENANCE.md', 'docs/UI_FLOW_ACCEPTANCE.md',
    'experiments/RUN_AND_RETURN.md']
FILES = sorted(set(FILES) | {
    str(path.relative_to(ROOT)).replace("\\", "/")
    for directory in (ROOT / "docs", ROOT / "distro")
    for path in directory.glob("*.md")
    if not path.name.startswith("HISTORICAL_")
})


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
        '12-request cap', 'seven measured inputs', 'not prices for a new selection',
        'releases the target before local scoring', 'No new responsiveness survey',
        'A failed connection check stops progression', 'Additional connection checks',
        'inline hosted scoring', '3.3 seconds', 'four target calls and no answer retries',
        'USD 0.189337', 'USD 0.757348', 'USD 0.027046', 'USD 0.007470',
        'four matched inputs and three jointly valid pairs',
        'text had three matched inputs and three valid pairs',
        'One new Haiku verdict had invalid format',
        'not independent research ratings', 'at least 16 correct per dimension',
        'recorded teacher labels, not independently established human truth',
        'locked at `0`', 'Paired judging outcomes', 'not all planned inputs',
        'rather than becoming an extra segment that double-counts an answer',
        'one measured image answer and three diagnostic answers',
        'Increasing the cap cannot add source answers that do not exist']
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


def test_instruction_sequences_have_no_missing_or_restarted_steps():
    text = prose(ROOT / 'docs/SMALL_CAMPAIGNS.md')
    for section in re.split(r'^#{1,6} ', text, flags=re.MULTILINE):
        # Splitting removes the heading marker, not its number. The heading
        # itself is not the first numbered action in the section.
        body = '\n'.join(section.splitlines()[1:])
        steps = [int(value) for value in re.findall(r'^(\d+)\.\s', body, re.MULTILINE)]
        assert steps == list(range(1, len(steps) + 1)), (section.splitlines()[0], steps)
    sections = re.findall(r'^### (\d+\.\d+)\.', text, re.MULTILINE)
    assert sections == [f'{chapter}.{step}' for chapter, count in ((8, 6), (9, 5), (10, 4))
                        for step in range(1, count + 1)]


def test_sequence_check_detects_the_previous_restarted_list_error(monkeypatch):
    test_instruction_sequences_have_no_missing_or_restarted_steps()
    original = Path.read_text
    guide = ROOT / 'docs/SMALL_CAMPAIGNS.md'

    def read(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        return text.replace('8. Return to **General**', '3. Return to **General**') if path == guide else text

    assert '8. Return to **General**' in original(guide, encoding='utf-8')
    monkeypatch.setattr(Path, 'read_text', read)
    with pytest.raises(AssertionError):
        test_instruction_sequences_have_no_missing_or_restarted_steps()


@pytest.mark.parametrize('omission', [
    '### Reference result, not a required outcome',
    '319-token answer', 'not zero-cost computing',
    'Start or resume assessment', 'Resume unfinished analysis',
    'USD 0.027046', 'One new Haiku verdict',
])
def test_preservation_check_detects_meaningful_omissions(monkeypatch, omission):
    test_combined_guide_preserves_local_actions_and_reference_limits()
    original = Path.read_text
    guide = ROOT / 'docs/SMALL_CAMPAIGNS.md'
    pattern = re.compile(r'\s+'.join(re.escape(word) for word in omission.split()))
    assert pattern.search(original(guide, encoding='utf-8'))

    def read(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        return pattern.sub('REMOVED', text) if path == guide else text

    monkeypatch.setattr(Path, 'read_text', read)
    with pytest.raises(AssertionError):
        test_combined_guide_preserves_local_actions_and_reference_limits()


def test_link_check_detects_a_missing_section(monkeypatch):
    test_operator_markdown_links_and_section_anchors_resolve()
    original = Path.read_text
    guide = ROOT / 'docs/SMALL_CAMPAIGNS.md'

    def read(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        return text + '\n[Missing section](#absent-section)\n' if path == guide else text

    monkeypatch.setattr(Path, 'read_text', read)
    with pytest.raises(AssertionError, match='absent section'):
        test_operator_markdown_links_and_section_anchors_resolve()
