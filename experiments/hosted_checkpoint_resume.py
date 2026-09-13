"""Resume an inspected interrupted HTTP prefix without another logical input.

Controllers supply the input inventory read from the retained response files.
This is a post-inspection handoff, not an automatic retry of a missing answer.
The original admission still checks request bytes and reserves each HTTP call.
"""

from contextlib import contextmanager
import copy
from pathlib import Path
import time

from experiments.hosted_attempt_budget import _budget_lock

RENEWAL_SCHEMA = 'ura-hosted-interrupted-continuation/1'


def validated_renewal_jobs(program: dict, budget, *, local_context=None):
    """Validate the original program and derive its single inspected continuation."""
    from experiments import hosted_retained_execute as retained, run_matrix
    from experiments.rig_web_app.workspace_import import _responses
    from ura.adapters.replay import ReplayAttacker

    predecessor = program.get('interrupted_predecessor')
    if (program.get('schema') != RENEWAL_SCHEMA or not isinstance(predecessor, dict)
        or set(predecessor) != {'program', 'job', 'logical_budget', 'prior_http_attempts'}):
        raise ValueError('Interrupted continuation requires its original run evidence')
    previous, _ = retained._bound(predecessor['program'])
    if previous.get('schema') == RENEWAL_SCHEMA:
        raise ValueError('Interrupted continuation must name its original admitted program')
    changed = {'schema', 'jobs', 'requests', 'interrupted_predecessor'}
    if ({k: v for k, v in program.items() if k not in changed}
        != {k: v for k, v in previous.items() if k not in changed}
        or len(program.get('jobs', [])) != 1 or len(program.get('requests', {})) != 1):
        raise ValueError('Interrupted continuation changed original source or funding conditions')
    originals = retained._validated_jobs(previous, budget, local_context=local_context)
    matches = [row for row in originals if row.job['name'] == predecessor['job']]
    if len(matches) != 1:
        raise ValueError('Interrupted continuation original job is not unique')
    original = matches[0]
    found = set()
    for attempt, response, _locator in _responses(original.job):
        key = attempt['params']['retained_origin']['selection']['input_identity_sha256']
        if (key not in original.entries or response['target'] != original.program['target']
            or attempt['params']['retained_origin'] != original.entries[key]['origin']):
            raise ValueError('Original response inventory changed its admitted input')
        found.add(key)
    snapshot, _ = retained._bound(predecessor['logical_budget'])
    original_args = run_matrix.build_parser().parse_args(original.job['argv'])
    expected_budget = Path(original_args.out) / (str(snapshot.get('budget_id')) + '.budget.json')
    if Path(predecessor['logical_budget']['path']) != expected_budget:
        raise ValueError('Interrupted logical budget is not from the original output directory')
    job = program['jobs'][0]
    args = run_matrix.build_parser().parse_args(job['argv'])
    config, _ = run_matrix._load_attacker_config(args.attacker_config, ['replay'], args.attacker_config_sha256)
    resumed = retained._Admission(program=program, job=job, budget=budget,
        attacker=ReplayAttacker(**config['replay']), requests=program['requests'], prices=original.prices)
    resumed.validate_cli(job['argv'], args)
    key = next(iter(program['requests']))
    review = renew_interrupted_transport(original, resumed, input_id=key,
        retained_input_ids=found, held_snapshot=snapshot)
    if (type(predecessor['prior_http_attempts']) is not int
        or review['prior_http_attempts'] != predecessor['prior_http_attempts']):
        raise ValueError('Interrupted physical attempt prefix advanced after inspection')
    return [resumed]


def renew_interrupted_transport(original, resumed, *, input_id: str,
                                retained_input_ids: set[str], held_snapshot: dict) -> dict:
    """Move one abandoned HTTP prefix to a fresh run, preserving its paid history.

    The caller first establishes that the old worker is gone and reads its
    original response inventory and durable logical budget. Both admissions
    must come from validated source selection; no retained response is copied
    or invented. The old run window and files remain unchanged.
    """
    if (set(original.requests) != retained_input_ids | {input_id}
        or input_id in retained_input_ids or set(resumed.requests) != {input_id}
        or set(resumed.entries) != {input_id}
        or resumed.entries[input_id] != original.entries.get(input_id)
        or resumed.requests[input_id] != original.requests.get(input_id)
        or resumed.program != original.program or resumed.prices != original.prices
        or resumed.budget.root.resolve() != original.budget.root.resolve()
        or resumed.budget.expected_plan_sha256 != original.budget.expected_plan_sha256
        or resumed.job['purpose'] != original.job['purpose']):
        raise ValueError('Renewed interruption changed its exact input, request or paid owner')
    snapshot = copy.deepcopy(held_snapshot)
    deadline = snapshot.get('deadline_epoch')
    if (type(deadline) not in {int, float} or not deadline < time.time()
        or snapshot.get('target_calls') != len(original.requests)
        or snapshot.get('max_target_calls') != len(original.requests)
        or snapshot.get('http_attempts') != 4 * len(original.requests)
        or snapshot.get('max_http_attempts') != 4 * len(original.requests)
        or snapshot.get('accounting_semantics') != 'durable_pre_call_logical_reservation_v1'):
        raise ValueError('Renewed interruption needs the unchanged expired logical budget')

    def output(admission):
        argv = admission.job['argv']
        if argv.count('--out') != 1:
            raise ValueError('Interrupted run output is not explicit')
        path = Path(argv[argv.index('--out') + 1])
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('Interrupted run output must be canonical')
        return path

    previous, fresh = output(original), output(resumed)
    if (fresh == previous or fresh.is_relative_to(previous) or previous.is_relative_to(fresh)
        or any(fresh.glob('*.budget.json'))
        or any(path.stat().st_size for path in fresh.glob('*.responses*.jsonl'))):
        raise ValueError('Renewed interruption must use a separate unexecuted output directory')
    receipt = resumed.requests[input_id]
    with _budget_lock(resumed.budget.root):
        _plan, ledger, _calls = resumed.budget._load()
        attempts = ledger['attempts'].get(receipt['call_id'], {})
        prior = len(attempts)
        if (not 1 <= prior < 4
            or set(attempts) != {str(i) for i in range(1, prior + 1)}
            or any(row['state'] != 'unknown' or row['actual_cost_microusd'] is not None
                   for row in attempts.values())):
            raise ValueError('Renewed interruption needs a non-exhausted terminal unknown HTTP prefix')
    if resumed.transport_recoveries:
        raise ValueError('Renewed interruption already has a recovery owner')
    resumed.transport_recoveries[input_id] = prior
    population = original.funded_cluster_population
    if population is not None:
        resumed.funded_cluster_population = copy.deepcopy({
            key: value for key, value in population.items() if key not in retained_input_ids})
    return dict(input_id=input_id, call_id=receipt['call_id'], prior_http_attempts=prior,
        next_http_attempt=prior + 1, maximum_total_http_attempts=4,
        request_sha256=receipt['request_sha256'], new_campaign_inputs=0,
        prior_logical_budget=snapshot, previous_output=str(previous), output=str(fresh),
        previous_unknown_charges_preserved=True, original_run_window_unchanged=True)


def resume_interrupted_transport(admission, *, input_id: str, retained_input_ids: set[str],
                                 held_snapshot: dict) -> dict:
    held_snapshot = dict(held_snapshot)
    if not retained_input_ids <= admission.requests.keys() or input_id not in admission.requests:
        raise ValueError("Interrupted input is outside the admitted job")
    if input_id in retained_input_ids:
        raise ValueError("A retained answer or failed output is not an interrupted HTTP prefix")
    receipt = admission.requests[input_id]
    with _budget_lock(admission.budget.root):
        _plan, ledger, _calls = admission.budget._load()
        attempts = ledger["attempts"].get(receipt["call_id"], {})
        prior = len(attempts)
        if not 1 <= prior < 4 or set(attempts) != {str(i) for i in range(1, prior + 1)}:
            raise ValueError("Interrupted HTTP retry prefix is absent or exhausted")
        if any(row["state"] != "unknown" or row["actual_cost_microusd"] is not None for row in attempts.values()):
            raise ValueError("Interrupted prefix must have terminal unknown usage, not an active or settled answer")
    if (held_snapshot.get("target_calls") != len(retained_input_ids) + 1
        or held_snapshot.get("max_target_calls") != len(admission.requests)
        or held_snapshot.get("http_attempts", 0) < 4
        or held_snapshot.get("max_http_attempts") != 4 * len(admission.requests)
        or held_snapshot.get("accounting_semantics") != "durable_pre_call_logical_reservation_v1"):
        raise ValueError("Interrupted logical reservation differs from its admitted input inventory")
    if input_id in admission.transport_recoveries:
        raise ValueError("This input already has a different recovery handoff")
    original = admission.attempt
    used = False

    @contextmanager
    def attempt(runner, planned):
        nonlocal used
        key = planned.params["retained_origin"]["selection"]["input_identity_sha256"]
        if used:
            with original(runner, planned):
                yield
            return
        if key != input_id or admission._receipt(planned) != receipt:
            raise ValueError("Resume the interrupted input before issuing new inputs")
        logical = runner.call_budget
        if logical is None or logical.snapshot() != held_snapshot:
            raise ValueError("Held interrupted logical reservation changed")
        charge = logical.charge_target

        def reuse(*, http_exposure=1):
            nonlocal used
            if used or http_exposure != 4 or logical.snapshot() != held_snapshot:
                raise ValueError("Interrupted logical reservation can be consumed only once")
            logical.raise_if_deadline_reached()
            used = True

        logical.charge_target = reuse
        try:
            with original(runner, planned):
                yield
        finally:
            logical.charge_target = charge

    admission.transport_recoveries[input_id] = prior
    admission.attempt = attempt
    return {"input_id": input_id, "call_id": receipt["call_id"], "prior_http_attempts": prior,
            "next_http_attempt": prior + 1, "maximum_total_http_attempts": 4,
            "request_sha256": receipt["request_sha256"], "new_logical_inputs": 0,
            "previous_unknown_charges_preserved": True}
