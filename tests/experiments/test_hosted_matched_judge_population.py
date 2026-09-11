"""A matched input may have several different local model answers to judge."""
from experiments.hosted_retained_execute import _matched_judge_call_cap


def test_explicit_local_output_population_exceeds_two_per_target_approximation():
    routes=[{"paid_call_cap":1200},{"paid_call_cap":2560}]
    inventory={"unjudged_rows":[{"retained_row_sha256":f"{n:064x}"} for n in range(5049)]}
    assert _matched_judge_call_cap(7520,routes,inventory)==8809
    assert 3719+5049 <= _matched_judge_call_cap(7520,routes,inventory)


def test_historical_projection_and_smaller_local_population_are_unchanged():
    routes=[{"paid_call_cap":5}]
    assert _matched_judge_call_cap(10,routes,None)==10
    assert _matched_judge_call_cap(10,routes,{"unjudged_rows":[{}]})==10
