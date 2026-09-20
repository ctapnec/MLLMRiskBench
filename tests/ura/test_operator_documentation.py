"""The operator manual is a maintained interface, not a second historical flow."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ['README.md', 'docs/README.md', 'docs/SMALL_CAMPAIGNS.md',
    'docs/SMALL_API_CAMPAIGN.md', 'docs/SMALL_LOCAL_CAMPAIGN.md',
    'docs/CAMPAIGN_RESULTS_AND_ANALYSIS.md', 'docs/UI_CAMPAIGN_WALKTHROUGH.md',
    'docs/CAMPAIGN_WORKSPACES.md', 'docs/RESPONSE_SVM.md',
    'docs/HUMAN_REVIEW_UI.md', 'docs/ARCHITECTURE.md', 'docs/WORKSTATION_ARCHIVE.md',
    'docs/UI_FLOW_ACCEPTANCE.md', 'docs/archive/README.md',
    'experiments/RUN_AND_RETURN.md', 'experiments/HOSTED_MATCHED_CLOSEOUT_PLAN.md']
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


def test_current_docs_do_not_reintroduce_removed_operator_restrictions():
    review = re.sub(r'\s+', ' ', prose(ROOT / 'docs/HUMAN_REVIEW_UI.md'))
    architecture = prose(ROOT / 'docs/ARCHITECTURE.md')
    assert 'All indexed measured campaign outputs' in review
    assert 'manual source registration is not required' in review
    assert 'answers and control-surface navigation' not in review
    assert "Every review screen retains the console's main navigation" in review
    assert 'overlaps are unavailable for Ollama' not in architecture
    assert 'Legacy overlap metadata does not exclude a live candidate' in architecture


def test_current_project_docs_use_plain_ascii_punctuation():
    problems = []
    for path in (ROOT / 'docs').glob('*.md'):
        if not path.name.startswith('HISTORICAL_') and re.search(r'[\u2010-\u2015\u2018\u2019\u201c\u201d]', prose(path)):
            problems.append(path.name)
    assert not problems, problems


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


ARCHIVED = (
    'HISTORICAL_CAMPAIGN_WORKSPACES.md', 'HISTORICAL_UI_CAMPAIGN_WALKTHROUGH.md',
    'OPERATOR_REGRESSION_AUDIT.md', 'UI_WORKFLOW_SIMPLIFICATION.md',
    'DOCUMENTATION_MAINTENANCE.md', 'UI_FLOW_ACCEPTANCE_20260920.md',
    'HUMAN_REVIEW_UI_20260920.md', 'CONVERSATIONAL_AI_REVIEW_20260920.md',
    'WORKSTATION_ARCHIVE_PLAN_20260920.md',
)


def test_archived_originals_remain_indexed_with_relocated_file_links():
    index = prose(ROOT / 'docs/archive/README.md')
    for name in ARCHIVED:
        path = ROOT / 'docs/archive' / name
        assert f']({name})' in index, name
        text = path.read_text(encoding='utf-8')
        assert '<!-- BEGIN PRESERVED DOCUMENT -->' in text, name
        # Archived headings describe historical controls. Their local file
        # destinations must still exist, even if the current headings changed.
        for target in re.findall(r'\[[^]\n]+\]\(([^)\s]+)\)', prose(path)):
            url = urlsplit(target)
            if url.scheme or url.netloc or url.path.startswith('/') or not url.path:
                continue
            linked = path.parent / unquote(url.path)
            if linked.suffix.lower() == '.md':
                assert linked.is_file(), f'{name}: missing {target}'


def test_schema_documents_current_database_and_accounting_boundaries():
    text = re.sub(r'\s+', ' ', prose(ROOT / 'docs/SCHEMA.md'))
    storage = (ROOT / 'experiments/rig_web_app/storage.py').read_text(encoding='utf-8')
    version = re.search(r'^    SCHEMA_VERSION = (\d+)$', storage, re.MULTILINE).group(1)
    assert f'in `experiments/rig_web_app/storage.py` is **{version}**' in text
    for required in (
        'Ratings and adjudications are primary observations',
        'it does not recreate campaign definitions or human ratings',
        'off by default (`reindex_all(verify_sha=False)`)',
        'on or before the recorded usage date, not the date the page is opened',
        'Backups must be transaction-consistent',
    ):
        assert required in text, required


def test_ai_review_retains_sampling_and_assessment_limits():
    text = re.sub(r'\s+', ' ', prose(ROOT / 'docs/CONVERSATIONAL_AI_REVIEW.md'))
    for required in (
        'rather than unweighted population safety estimates',
        'does not itself establish identical rendered conversations',
        'Only after saving initial judgments, reveal existing local and Haiku labels',
        'not experimental independence or full blinding',
    ):
        assert required in text, required


@pytest.mark.parametrize('old,new', [
    ('is **9**', 'is **4**'),
    ('primary observations', 'reconstructible indexes'),
    ('verify_sha=False', 'verify_sha=True'),
    ('recorded usage date, not the date', 'date'),
    ('Backups must be transaction-consistent', 'Copy the live database alone'),
])
def test_database_documentation_check_detects_reintroduced_errors(monkeypatch, old, new):
    test_schema_documents_current_database_and_accounting_boundaries()
    original = Path.read_text
    schema = ROOT / 'docs/SCHEMA.md'
    pattern = re.compile(r'\s+'.join(re.escape(word) for word in old.split()))
    assert pattern.search(original(schema, encoding='utf-8'))

    def read(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        return pattern.sub(new, text) if path == schema else text

    monkeypatch.setattr(Path, 'read_text', read)
    with pytest.raises(AssertionError):
        test_schema_documents_current_database_and_accounting_boundaries()
