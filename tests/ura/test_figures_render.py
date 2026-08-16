"""Headless render checks for the paired Chapter V figure renderer."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("matplotlib")

from experiments.figures import main, render_all, synth_matrix  # noqa: E402

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def test_synth_matrix_is_marked_illustrative():
    data = synth_matrix()
    assert data["illustrative"] is True
    assert data["analysis"]["labels"] == "neutral Condition A-I labels"
    assert set(data["figures"]) == {
        "fig-v-asr-by-model.png",
        "fig-v-policy-proxies.png",
        "fig-v-adaptivity.png",
    }
    assert [
        data["figures"][name]["figure_role"]
        for name in (
            "fig-v-asr-by-model.png",
            "fig-v-policy-proxies.png",
            "fig-v-adaptivity.png",
        )
    ] == ["primary_model", "secondary_policy_proxies", "h4_adaptivity"]
    labels = [
        point["label"]
        for figure in data["figures"].values()
        for point in figure["points"]
    ]
    assert labels and all("Condition " in label for label in labels)
    assert "anthropic" not in json.dumps(data).lower()
    assert "openai" not in json.dumps(data).lower()


def test_render_all_writes_three_pngs(tmp_path):
    data = synth_matrix()
    paths = render_all(data, tmp_path)
    assert len(paths) == 3
    for path in paths:
        assert path.is_file()
        head = path.read_bytes()[:8]
        assert head == _PNG_MAGIC and path.stat().st_size > 1000
    sidecar = tmp_path / "fig-v-provenance.json"
    assert sidecar.is_file()
    provenance = json.loads(sidecar.read_text(encoding="utf-8"))
    assert provenance == data
    assert provenance["illustrative"] is True


def test_synth_cli_emits_exactly_three_figures_plus_sidecar(tmp_path):
    assert main(["--synth", "--out", str(tmp_path)]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "fig-v-adaptivity.png",
        "fig-v-asr-by-model.png",
        "fig-v-policy-proxies.png",
        "fig-v-provenance.json",
    ]
