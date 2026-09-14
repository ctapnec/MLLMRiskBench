"""Connect prepared review media to retained local files, once per preparation.

Only the selected result directory and its recorded source locations are read.
Page requests never scan corpora, fetch remote assets, or hash model weights.
"""
from collections import Counter
import csv
import json
from pathlib import Path

from experiments.retained_replay_sources import source_populations, source_media_index


def prepare_media_index(results: Path, sample: Path, supplied: Path | None = None, *, manifest_paths=None) -> dict:
    with sample.open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    original = json.loads(supplied.read_text(encoding='utf-8')) if supplied else {}
    if not isinstance(original, dict):
        raise ValueError('Retained media index must map content identities to local files')
    needed, by_run = {}, {}
    for row in rows:
        for ref in json.loads(row['media_references']):
            digest = ref['sha256']
            needed[digest] = ref
            by_run.setdefault(row['run_id'], {})[digest] = ref
    index = {digest: path for digest, path in original.items()
             if digest in needed and isinstance(path, str) and Path(path).is_absolute() and Path(path).is_file()}
    unresolved_runs = {run for run, refs in by_run.items() if refs.keys() - index.keys()}
    manifests = {}
    # These are only the result manifests in the explicitly selected scope,
    # not a recursive inventory of the data/model store.
    if unresolved_runs:
        paths = results.rglob('*.manifest.json') if manifest_paths is None else manifest_paths
        for path in paths:
            run = path.name.removesuffix('.manifest.json').rsplit('__', 1)[-1]
            if run in unresolved_runs:
                value = json.loads(path.read_text(encoding='utf-8'))
                if run in manifests and manifests[run] != value:
                    raise ValueError('Selected media run has conflicting source manifests')
                manifests[run] = value
    errors = {}
    cells = [dict(run_id=run, manifest=value) for run, value in manifests.items()]
    populations = {}
    if cells:
        try:
            populations = source_populations(cells)
        except (OSError, ValueError) as exc:
            # Keep the sample and expose unavailable assets. Never drop the
            # affected rows or claim that a reviewer saw an unavailable image.
            errors['source_lookup'] = str(exc)
    for run, refs in by_run.items():
        missing = {digest: ref for digest, ref in refs.items() if digest not in index}
        for digest, ref in missing.items():
            locator = ref['locator']
            media = dict(sha256=digest, mime=ref['mime'], modality=ref['modality'],
                         path=locator if locator.startswith('@media-root/') else 'sha256:'+digest)
            try:
                index.update(source_media_index([dict(rendered_input=[dict(role='user', content='', media=[media])])],
                    {run: populations[run]} if run in populations else {}))
            except (OSError, ValueError) as exc:
                errors[digest] = str(exc)
    unresolved = sorted(needed.keys() - index.keys())
    counts = Counter()
    for row in rows:
        refs = json.loads(row['media_references'])
        counts['outputs_with_media'] += bool(refs)
        counts['outputs_with_unavailable_media'] += any(ref['sha256'] not in index for ref in refs)
        counts['media_references'] += len(refs)
        counts['resolved_references'] += sum(ref['sha256'] in index for ref in refs)
    destination = sample.with_suffix('.MEDIA.json')
    destination.write_text(json.dumps(index, sort_keys=True)+'\n', encoding='utf-8')
    report = dict(status='resolved' if not unresolved else 'media_unavailable', **counts,
                  unresolved_content=unresolved, errors=errors, media_index=str(destination),
                  target_calls=0, judge_calls=0, remote_downloads=0)
    sample.with_suffix('.MEDIA-REPORT.json').write_text(json.dumps(report, sort_keys=True)+'\n', encoding='utf-8')
    return report
