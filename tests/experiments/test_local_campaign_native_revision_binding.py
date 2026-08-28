from pathlib import Path

import pytest


TEMPLATE = (
    Path(__file__).parents[2]
    / "experiments"
    / "local_campaign"
    / "templates"
    / "phase6_native_diagnostics.sh.in"
)
PHASE7 = TEMPLATE.with_name("phase7_analysis.py.in")
PHASE8 = TEMPLATE.with_name("phase8_human_audit.py.in")


def _current_revision_validator(source: str) -> str:
    return source.split("def validate_current_project_revision(", 1)[1].split(
        "\n\ndef safe_engine", 1
    )[0]


def _assert_current_revision_validator(block: str) -> None:
    for required in (
        "path = validate_descriptor_row(row, label)",
        "expected_path = Path(EXPECTED_PROJECT_REVISION_MANIFEST).resolve(strict=True)",
        "path != expected_path",
        'row.get("sha256") != EXPECTED_PROJECT_REVISION_SHA256',
        "load_project_revision_file(",
        "recheck_checkout=True",
        "if row != {",
        '"sha256": binding["sha256"]',
        '"bytes": binding["bytes"]',
        'repository.get("expected_commit") != expected_commit',
        'repository.get("observed_commit") != expected_commit',
        'repository.get("clean") is not True',
    ):
        assert required in block


def _assert_native_revision_stage_binding(source: str) -> None:
    assert source.count('"project_revision": project_revision,') == 1
    assert '"project_revision": launch["project_revision"],' not in source
    assert (
        'plan_content.get("code_identity", {}).get("project_revision")'
        in source
    )
    assert (
        'project_revision = (\n'
        '    plan_code.get("project_revision") if isinstance(plan_code, dict) else None\n'
        ')' in source
    )
    assert source.count("validate_current_project_revision(") == 4
    assert 'label="native plan project revision"' in source
    assert 'label="native summary project revision"' in source
    assert 'label="native completion project revision"' in source
    assert source.count('plan["code_identity"]["project_revision"]') == 2
    assert source.count("recheck_checkout=False") == 2
    assert 'promotion_plan.get("code_identity") != gate5_code_identity' in source
    assert (
        'promotion_plan.get("code_identity") != historical_code_identity'
        in source
    )
    assert (
        '"expected_commit": EXPECTED_COMMIT, "framework_lock_id": LOCK_ID'
        not in source
    )
    assert 'historical_code_identity.get("framework_lock_id") != LOCK_ID' not in source
    assert 'gate5_code_identity.get("framework_lock_id") != lock_id' not in source


def test_native_project_revision_is_bound_at_every_controller_boundary() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    validator = _current_revision_validator(source)
    _assert_current_revision_validator(validator)
    _assert_native_revision_stage_binding(source)

    for original, replacement in (
        ("path != expected_path", "False"),
        (
            'row.get("sha256") != EXPECTED_PROJECT_REVISION_SHA256',
            "False",
        ),
        ("if row != {", "if False and row != {"),
        (
            'repository.get("observed_commit") != expected_commit',
            "False",
        ),
    ):
        mutated = validator.replace(original, replacement, 1)
        assert mutated != validator
        with pytest.raises(AssertionError):
            _assert_current_revision_validator(mutated)

    for original, replacement in (
        (
            'plan_content.get("code_identity", {}).get("project_revision")',
            "None",
        ),
        (
            'label="native summary project revision"',
            'label="native changed summary"',
        ),
        (
            'label="native completion project revision"',
            'label="native changed completion"',
        ),
        (
            'promotion_plan.get("code_identity") != historical_code_identity',
            "False",
        ),
    ):
        mutated = source.replace(original, replacement, 1)
        assert mutated != source
        with pytest.raises(AssertionError):
            _assert_native_revision_stage_binding(mutated)


def test_native_execution_call_gate_matches_phase7_and_phase8_consumers() -> None:
    producer = TEMPLATE.read_text(encoding="utf-8")
    expected = (
        "per-engine literal-loopback proxy under one production exclusive "
        "inference lease with protected pre/post exact-roster checks, exact "
        "model allow-list, and hard request cap"
    )
    assert producer.count(expected) == 2
    assert PHASE7.read_text(encoding="utf-8").count(expected) == 1
    assert PHASE8.read_text(encoding="utf-8").count(expected) == 1


def test_native_contract_self_test_inventory_matches_all_consumers() -> None:
    labels = (
        "missing-lane",
        "duplicate-lane",
        "runnable-family",
        "rr-current-runnable",
        "native-terminal",
        "defense-na-v2-cross-mix",
        "defense-na-shape",
        "hosted-http-policy",
        "promotion-inventory",
        "promotion-download",
        "promotion-authorization",
        "promotion-basis-launched",
        "promotion-basis-manifest",
    )
    for path in (TEMPLATE, PHASE7, PHASE8):
        source = path.read_text(encoding="utf-8")
        assert 'get("mutations_rejected") != 13' in source
        positions = [source.index(f'"{label}"') for label in labels]
        assert positions == sorted(positions)
