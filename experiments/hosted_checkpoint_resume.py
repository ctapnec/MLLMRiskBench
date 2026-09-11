"""Resume an inspected interrupted HTTP prefix without another logical input.

Controllers supply the input inventory read from the retained response files.
This is a post-inspection handoff, not an automatic retry of a missing answer.
The original admission still checks request bytes and reserves each HTTP call.
"""

from contextlib import contextmanager

from experiments.hosted_attempt_budget import _budget_lock


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
