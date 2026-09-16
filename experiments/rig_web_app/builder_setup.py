"""Campaign setup defaults and discovery of its already completed transport checks."""
from __future__ import annotations

import hashlib
import json
import os
import html
from datetime import datetime, timezone
from pathlib import Path

from ura.live_attestation import load_live_attestation_file


class BuilderSetupMixin:
    def _transport_check_form(self, campaign_id):
        options = "<option value=''>Choose a completed probe</option>"
        for row in self.db.completed_probe_jobs(campaign_id) or []:
            params = json.loads(row['builder_params'] or '{}')
            label = ' - '.join((row['campaign_name'] or 'Standalone',
                                params.get('local') or params.get('api') or 'Model',
                                params.get('corpora') or 'Input', row['job_id']))
            options += "<option value='" + html.escape(row['job_id']) + "'>" + html.escape(label) + "</option>"
        return (
            "<details class='cmd' data-name='live_attestation saved transport checks'><summary>"
            "<span class='name'>live_attestation</span><span class='desc'>Use a completed probe</span>"
            "</summary><div class='inner'><p>Select the probe by name. Its scope, output location and "
            "campaign are supplied automatically. Existing completed checks are reused.</p>"
            "<form class='cmd' method='post' action='/jobs'><input type='hidden' name='command' value='live_attestation'>"
            "<input type='hidden' name='campaign_id' value='" + html.escape(campaign_id) + "'>"
            "<label>Completed probe</label><select name='probe_job' required>" + options + "</select>"
            "<span></span><button type='submit' data-busy='Preparing the saved transport check...'>"
            "Prepare transport check</button></form></div></details>"
        )

    def _transport_check_from_job(self, job_id, campaign_id):
        rows = self.db.completed_probe_jobs(campaign_id) or []
        row = next((row for row in rows if row['job_id'] == job_id), None)
        if row is None:
            raise ValueError('Select a completed probe from this campaign')
        params = json.loads(row['builder_params'] or '{}')
        owner = row['campaign_id'] or ''
        scope = params.get('scope', '')
        root = Path(row['out_dir']).resolve(strict=True)
        if not scope or not root.is_relative_to(self.results_root.resolve()):
            raise ValueError('The completed probe has no usable scope or output')
        for prior in self.db.completed_workspace_transport_jobs(owner) or []:
            argv = json.loads(prior['argv'])
            if all(flag in argv for flag in ('--probe-root', '--execution-scope-id', '--out')):
                if (Path(argv[argv.index('--probe-root')+1]).resolve() == root
                        and argv[argv.index('--execution-scope-id')+1] == scope
                        and Path(argv[argv.index('--out')+1]).is_file()):
                    return owner, {}, prior['job_id']
        return owner, {'--probe-root':str(root), '--execution-scope-id':scope,
                       '--out':str(root.parent / ('transport-'+job_id+'.json'))}, ''

    def _campaign_transport_receipts(self, params):
        owner = params.get('campaign_id', '')
        targets = set(self._split_list(params.get('local', '')) + self._split_list(params.get('api', '')))
        scope = params.get('scope', '')
        if not targets or not scope:
            return [], 'Select models to match completed transport checks.'
        try:
            maximum_age = float(params.get('max_age') or '24')
            if not 0 < maximum_age <= 8760:
                raise ValueError('age')
            snapshot = self._project_revision_snapshot(params)
            if snapshot is None:
                return [], 'The Runner project receipt is not configured.'
            _, project_sha = snapshot
        except (OSError, ValueError):
            return [], 'The Runner project receipt or maximum age needs attention.'
        rows = self.db.completed_workspace_transport_jobs(owner)
        if rows is None:
            return [], 'The campaign job index is unavailable.'
        candidates = []
        now = datetime.now(timezone.utc)
        for row in rows:
            try:
                argv = json.loads(row['argv'])
                if '--out' not in argv:
                    continue
                path = Path(argv[argv.index('--out') + 1])
                if not path.is_absolute():
                    path = self.repo_root / path
                if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 4 * 1024 * 1024:
                    continue
                path = path.resolve(strict=True)
                if not path.is_relative_to(self.results_root.resolve()):
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                manifest, _ = load_live_attestation_file(path, digest)
                records = [record for record in manifest['records']
                           if record['requested_target_spec'] in targets
                           and record['execution_scope_id'] == scope]
                if not records:
                    continue
                observed = [datetime.fromisoformat(record['observed_at_utc'].replace('Z', '+00:00'))
                            for record in records]
                if any(record['probe']['project_revision']['sha256'] != project_sha for record in records):
                    continue
                if any(not 0 <= (now - stamp).total_seconds() / 3600 <= maximum_age for stamp in observed):
                    continue
                keys = {(record['requested_target_spec'], tuple(record['exact_input_modalities']))
                        for record in records}
                candidates.append((min(observed), str(path), digest, keys, row['job_id']))
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                continue
        selected, seen = [], set()
        for _, path, digest, keys, job_id in sorted(candidates, reverse=True):
            # Select whole existing files, never rewrite or splice their records.
            if keys & seen:
                continue
            selected.append({'path': path, 'sha256': digest, 'keys': sorted(keys), 'job_id': job_id})
            seen.update(keys)
            if len(selected) == self._MAX_ATT_ROWS:
                break
        if not selected:
            return [], 'No matching current transport checks found in this campaign. Complete the missing transport check before measured execution.'
        descriptions = [model + ': ' + '+'.join(modalities) for model, modalities in sorted(seen)]
        return selected, ('Found ' + str(len(selected)) + ' completed transport check(s): '
                          + '; '.join(descriptions) + '. Selected automatically on review. '
                          'Exact route and input coverage are checked before generation.')

    def _automatic_campaign_setup(self, params, *, refresh=False):
        """Resolve an editable form once; never rebind a confirmed snapshot."""
        if params.get('setup_mode') != 'automatic':
            return params
        if not refresh and params.get('_setup_resolved') == 'yes':
            return params
        params = dict(params)
        owner = params.get('campaign_id', '')
        if not owner and params.get('work_kind') == 'campaign':
            return params  # Assigned immediately after the campaign is created.
        saved = self.db.workspace_definition(owner) if owner else {}
        params['scope'] = saved.get('scope') or params.get('scope') or ('campaign-' + owner if owner else 'standalone')
        for field, variable in (
            ('project_revision', 'URA_PROJECT_REVISION_MANIFEST'),
            ('project_revision_sha', 'URA_PROJECT_REVISION_SHA256'),
            ('source_conformance', 'URA_SOURCE_CONFORMANCE_MANIFEST'),
            ('source_conformance_sha', 'URA_SOURCE_CONFORMANCE_SHA256'),
        ):
            if os.environ.get(variable):
                params[field] = os.environ[variable]
        # Stable per configuration, so save/review/preflight use the same output.
        # Existing manually named probe directories and historical jobs are untouched.
        output_keys = ('mode','local','api','corpora','attackers','judges','judge_model',
                       'limit','seeds','sample_seed','sampling_policy','max_queries','max_turns',
                       'target_answer_retries','dtype','quantization','defense')
        identity = {key:params.get(key,'') for key in output_keys}
        suffix = hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:12]
        mode = params.get('mode','measured')
        base = self.results_root.resolve() / 'campaigns' / owner if owner else self.results_root.resolve() / 'standalone'
        params['out'] = str(base / (mode+'-'+suffix))
        for i in range(1, self._MAX_ATT_ROWS + 1):
            params.pop(f'att_path{i}', None)
            params.pop(f'att_sha{i}', None)
        offline = mode == 'dry_run' or (mode == 'diagnostic_canary' and params.get('canary_dry') == 'on')
        if offline or mode == 'attestation_probe':
            params.pop('max_age', None)
            if offline:
                params.pop('scope', None)
        else:
            params['max_age'] = '24'
            selected, _ = self._campaign_transport_receipts(params)
            for i, receipt in enumerate(selected, 1):
                params[f'att_path{i}'] = receipt['path']
                params[f'att_sha{i}'] = receipt['sha256']
        params['_setup_resolved'] = 'yes'
        return params
