"""Resolve a local scorer from installed metadata, never by downloading it."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

DEFAULT_GUARDRAIL_MODEL = 'meta-llama/Llama-Guard-3-8B'


class GuardrailSetupError(ValueError):
    pass


def installed_guardrail_revision(model: str, revision: str = '', *, store=None) -> str:
    """Preserve explicit historical pins; otherwise select the latest installed copy."""
    if not isinstance(model,str) or not model.strip():
        raise GuardrailSetupError('The scoring guardrail model must not be blank.')
    if revision:
        if re.fullmatch(r'[0-9a-fA-F]{40,64}', revision) is None:
            raise GuardrailSetupError('Invalid explicit scoring guardrail revision; omit it to use the installed model.')
        return revision.lower()
    root = Path(store or os.environ.get('URA_MODEL_STORE','/nonexistent-model-store')).expanduser()
    candidates = []
    # This reads only small installation manifests and directory metadata.
    # Acquisition remains responsible for checking the selected snapshot.
    for path in root.glob('hf-*/hf-manifest-*.upstream-manifest.json'):
        try:
            value = json.loads(path.read_text())
            commit = value.get('revision','')
            if (value.get('repo_id') == model and re.fullmatch(r'[0-9a-f]{40,64}',commit)
                    and (path.parent/'snapshot').is_dir()):
                candidates.append((path.stat().st_mtime_ns,commit))
        except (OSError,ValueError,TypeError):
            continue
    if not candidates:
        raise GuardrailSetupError('The scoring guardrail '+model+' is not installed in the configured model store. '
            'Install that model first; its revision and device are configured automatically.')
    return max(candidates)[1]


def resolve_scoring_settings(params: dict[str,str], *, store=None) -> dict[str,str]:
    resolved = dict(params)
    model = resolved.get('guardrail_model','').strip() or DEFAULT_GUARDRAIL_MODEL
    resolved['guardrail_model'] = model
    resolved['guardrail_revision'] = installed_guardrail_revision(
        model, resolved.get('guardrail_revision',''), store=store)
    return resolved


def automatic_guardrail_placement(torch, snapshot: str) -> dict:
    """Fit on one visible GPU when possible, otherwise split without CPU spill."""
    if not torch.cuda.is_available():
        return {'device_map':{'':'cpu'}}
    root = Path(snapshot)
    weights = list(root.glob('*.safetensors')) or list(root.glob('pytorch_model*.bin'))
    if not weights:
        raise GuardrailSetupError('The installed scoring guardrail has no supported weight files.')
    weight_bytes = sum(path.stat().st_size for path in weights)
    reserve = 2*1024**3
    capacity = {index:max(0,int(torch.cuda.mem_get_info(index)[0])-reserve)
                for index in range(torch.cuda.device_count())}
    required = int(weight_bytes*1.15)
    fitting = [index for index,available in capacity.items() if available>=required]
    if fitting:
        selected = max(fitting,key=lambda index:(capacity[index],-index))
        return {'device_map':{'':selected}}
    if sum(capacity.values())<required:
        raise GuardrailSetupError('The scoring guardrail does not currently fit in available GPU memory. '
            'Release other GPU work before judging; automatic placement will not offload it to CPU.')
    return {'device_map':'auto','max_memory':{**capacity,'cpu':0}}
