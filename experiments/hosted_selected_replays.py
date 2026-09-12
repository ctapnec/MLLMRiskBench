"""Prepare every selected hosted route from saved local inputs, without calls.

This connects source selection and forecasting to the existing replay format.
It does not fund execution, probe a model, generate an attack, or judge answers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments import hosted_retained_inputs as inputs
from experiments.hosted_campaign_budget import load_bound_json, _write_new
from experiments.retained_local_sources import SCHEMA as SOURCE_SCHEMA, load_sources
from experiments.retained_replay_sources import source_populations, source_media_index
from ura.artifact_checks import artifact_verification_cli


def prepare(*, inventory, inventory_descriptor, budget, budget_descriptor,
            api_config, api_descriptor, out_root: Path) -> dict:
    if inventory.get("schema") != SOURCE_SCHEMA:
        raise ValueError("Select saved local source runs before preparing their replay inputs")
    root = Path(out_root)
    if not root.is_absolute() or root.exists() or root != root.resolve():
        raise ValueError("Replay preparation needs a new resolved output directory")
    cells = load_sources(inventory)
    candidates = inputs.candidates_from_cells(cells)
    targets = [row["target_spec"] for row in budget["routes"]]
    if not targets or len(targets) != len(set(targets)):
        raise ValueError("The forecast must contain distinct selected target routes")
    selections, union = {}, {}
    for target in targets:
        _, _, _, selected, population = inputs._plan_selection(
            candidates=candidates,budget=budget,api_config=api_config,api_descriptor=api_descriptor,
            target=target,call_cap=None)
        if not selected:
            raise ValueError(f"{target}: no complete compatible source cluster fits the request cap; "
                f"compatible inputs={population['compatible_inputs']}, "
                f"next cluster size={population['next_whole_cluster_size']}. Change the selection or cap.")
        selections[target] = selected
        union.update((row["input_identity_sha256"], row) for row in selected)
    needed = {row["local_sources"][0]["run_id"] for row in union.values()}
    # Convert the union once, not once for every model and corpus artifact.
    populations = source_populations([cell for cell in cells if cell["run_id"] in needed])
    media = source_media_index(list(union.values()),populations)
    bindings = dict(budget=budget,budget_descriptor=budget_descriptor,api_config=api_config,
                    api_descriptor=api_descriptor,local_inventory_descriptor=inventory_descriptor,media_index=media)
    root.mkdir(parents=True,mode=0o700)
    media_path = root/'media-index.json'
    _write_new(media_path,media)
    routes, summaries = [], []
    for number,target in enumerate(targets):
        plan = inputs.build_plan(candidates=candidates,target=target,call_cap=None,**bindings)
        assert [row['input_identity_sha256'] for row in plan['selected']] == [
            row['input_identity_sha256'] for row in selections[target]]
        folder = root/f'model-{number:03d}'
        folder.mkdir(mode=0o700)
        _write_new(folder/'input-plan.json',plan)
        corpora = sorted({row['corpus'] for row in plan['selected']})
        replays = inputs.materialize_replays(plan,cells=cells,source_corpora=populations,
                                             corpora=corpora,**bindings)
        artifacts = []
        for index,replay in enumerate(replays):
            path = folder/f'corpus-{index:03d}.json'
            _write_new(path,replay)
            artifacts.append(inputs._descriptor(path))
        routes.append(dict(target=target,replay_artifacts=artifacts))
        summaries.append(dict(target=target,selected_inputs=len(plan['selected']),
                              source_arms=corpora,population=plan['population']))
    local_memberships = {(source['run_id'],source['attempt_id'])
        for row in union.values() for source in row['local_sources']}
    value = dict(status='prepared_replay_inputs_only',routes=routes,route_summary=summaries,
        media_index=inputs._descriptor(media_path),unique_selected_inputs=len(union),
        selected_local_source_conditions=len(local_memberships),
        local_source_count_is_not_a_valid_judgment_count=True,
        target_calls=0,judge_calls=0,model_loads=0,paid_execution_authorized=False)
    _write_new(root/'prepared-replays.json',value)
    return value


@artifact_verification_cli
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('local-inventory','budget','api-config'):
        parser.add_argument('--'+name,type=Path,required=True)
        parser.add_argument('--'+name+'-sha256',required=True)
    parser.add_argument('--out-root',type=Path,required=True)
    parser.add_argument('--verify-artifact-sha256',action='store_true')
    args = parser.parse_args(argv)
    inventory,inventory_desc = load_bound_json(args.local_inventory,args.local_inventory_sha256)
    budget,budget_desc = load_bound_json(args.budget,args.budget_sha256)
    api,api_desc = load_bound_json(args.api_config,args.api_config_sha256)
    result = prepare(inventory=inventory,inventory_descriptor=inventory_desc,
        budget=budget,budget_descriptor=budget_desc,api_config=api,api_descriptor=api_desc,out_root=args.out_root)
    print(json.dumps({key:value for key,value in result.items() if key not in {'routes','media_index'}}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
