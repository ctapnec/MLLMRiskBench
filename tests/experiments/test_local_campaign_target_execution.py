from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from experiments.local_campaign.target_execution import (
    aggregate_target_execution,
    completed_target_execution,
    target_execution_counts,
)


def test_completed_target_execution_ignores_a_larger_reservation() -> None:
    summary = {
        "call_accounting": {"reserved": {"target_logical_calls": 999}},
        "role_reachability": {
            "execution_roles": {"target": {"observed_records": 2}}
        },
    }

    assert completed_target_execution(summary) == (2, 2)


@pytest.mark.parametrize("pair", ((-1, 0), (1, 2), (True, 0), (1_000_001, 0)))
def test_target_execution_counts_reject_invalid_pairs(pair: tuple[object, object]) -> None:
    with pytest.raises(ValueError, match="invalid"):
        target_execution_counts(*pair)


def test_live_attestation_cli_reports_exact_receipt_digest_and_target_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from experiments import live_attestation

    monkeypatch.setattr(
        live_attestation,
        "_build_from_probe_root_with_target_execution",
        lambda root, *, execution_scope_id: (
            {"attestation_id": "live-attestation-" + "a" * 24, "records": [{}]},
            (3, 3),
        ),
    )
    receipt_path = tmp_path / "receipt.json"

    assert live_attestation.main([
        "--probe-root", str(tmp_path / "probe"),
        "--execution-scope-id", "fixture-scope",
        "--out", str(receipt_path),
    ]) == 0

    row = json.loads(capsys.readouterr().out)
    assert row["target_attempts"] == 3
    assert row["successful_target_generations"] == 3
    written = receipt_path.read_bytes()
    assert row["sha256"] == hashlib.sha256(written).hexdigest()

    receipt_path.write_bytes(written + b"\n")
    assert row["sha256"] != hashlib.sha256(receipt_path.read_bytes()).hexdigest()


def test_defense_terminal_zero_and_failed_output_attempt_are_distinct() -> None:
    rows = [
        {"target_attempts": "0", "successful_target_generations": "0"},
        {"target_attempts": "1", "successful_target_generations": "0"},
    ]

    assert aggregate_target_execution(rows) == (1, 0)


def test_ollama_terminal_retains_attempted_and_completed_counts() -> None:
    rows = [
        {"target_attempts": "9", "successful_target_generations": "8"},
    ]

    assert aggregate_target_execution(rows) == (9, 8)


def test_post_execution_failure_keeps_retry_accounting_unavailable() -> None:
    successful_retry = [
        {"target_attempts": "1", "successful_target_generations": "1"},
    ]

    assert (
        aggregate_target_execution(
            successful_retry,
            accounting_unavailable=True,
        )
        is None
    )


@pytest.mark.parametrize(
    "line",
    (
        "\t\n",
        "1\t\n",
        "\t0\n",
    ),
)
def test_blank_tsv_execution_fields_are_not_silently_zero(line: str) -> None:
    rows = list(
        csv.DictReader(
            io.StringIO(
                "target_attempts\tsuccessful_target_generations\n" + line
            ),
            delimiter="\t",
        )
    )

    with pytest.raises(ValueError, match="not an integer"):
        aggregate_target_execution(rows)
