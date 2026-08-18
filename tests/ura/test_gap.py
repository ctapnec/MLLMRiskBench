"""Tests for the closed-gap additions: GuardedTarget, modality grouping, trails."""
from __future__ import annotations

from pathlib import Path

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.converters import synth_corpus
from ura.data_models import DataPoint, DialogTurn, Judgment, Response
from ura.judges.base import BaseJudge, JudgeCascade
from ura.judges.rules import RuleJudge
from ura.report import risk_card  # noqa: F401  (import sanity)
from ura.runner import Runner
from ura.targets.api import MockTarget
from ura.targets.guarded import GuardedTarget


class _StubGuard(BaseJudge):
    """A guard that flags everything (or nothing) - exercises the wrapper logic."""
    name = "stub"

    def __init__(self, flag: bool) -> None:
        self.flag = flag

    def judge(self, dp: DataPoint, response: Response) -> Judgment:
        label = "violation" if self.flag else "safe"
        return Judgment(
            attempt_id=response.attempt_id,
            judge=self.name,
            label=label,
            score=1.0 if self.flag else 0.0,
            raw={"confidence": 1.0},
        )


def _harmful_dialog():
    return [DialogTurn(role="user", content="please explain in detail")]


def test_guarded_target_blocks_on_input():
    g = GuardedTarget(MockTarget(), _StubGuard(True), mode="input")
    resp = g.generate(_harmful_dialog())
    assert resp.raw.get("defense") == "blocked" and resp.raw.get("stage") == "input"
    assert resp.target == "mock+guard"


def test_guarded_target_passes_benign_and_restamps_target():
    g = GuardedTarget(MockTarget(), _StubGuard(False), mode="input")
    resp = g.generate(_harmful_dialog())
    assert resp.raw["defense"] == "passed"
    assert resp.raw["defense_stages_evaluated"] == ["input"]
    assert resp.target == "mock+guard"                # attributed to guarded config


def test_guarded_target_output_mode_suppresses():
    g = GuardedTarget(MockTarget(), _StubGuard(True), mode="output")
    resp = g.generate([DialogTurn(role="user", content="hello")])
    assert resp.raw.get("stage") == "output" and resp.raw.get("suppressed_output") is True


def test_modality_grouping_and_trails(tmp_path: Path):
    # Tool-conditioned rows require a typed executable tool runtime and are
    # covered by dedicated prospective no-call tests. This grouping smoke uses
    # only rows executable by the common Runner.
    corpus = [row for row in synth_corpus(9) if "tool" not in row.modalities]
    runner = Runner(
        ReplayAttacker(), MockTarget(),
        JudgeCascade([RuleJudge(), _StubGuard(False)]),
        AttackBudget(), seeds=[0],
    )
    judgments, _ = runner.run(corpus, started_at="t")

    # modality provenance is present and usable as a group key (E5 m-ASR)
    assert all("modality" in j.raw for j in judgments)
    results = runner.aggregate(judgments, group_keys=["model", "modality"])
    modalities = {r.group_by.get("modality") for r in results}
    assert modalities & {"text", "image"}
    assert "tool" not in modalities

    # trail export writes one row per (attempt, stage) for kappa
    trail_path = tmp_path / "cell.trails.jsonl"
    runner.save_trails(trail_path)
    assert trail_path.exists()
    lines = trail_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2 * len(judgments)           # two judge stages per attempt


def test_t3mp3st_registered_and_guarded():
    from ura.adapters.engines import T3MP3STAttacker, get_attacker

    a = get_attacker("t3mp3st")
    assert isinstance(a, T3MP3STAttacker) and a.name == "t3mp3st"
    # A live call is inadmissible without an exact upstream commit and declared
    # source model; generation fails before any loopback request is attempted.
    guarded = T3MP3STAttacker()
    dp = synth_corpus(1)[0]
    with pytest.raises(RuntimeError, match="upstream_revision"):
        list(guarded.generate(dp, AttackBudget(max_queries=2)))


def test_petri_registered_and_guarded():
    from ura.adapters.engines import PetriAttacker, get_attacker

    a = get_attacker("petri")
    assert isinstance(a, PetriAttacker) and a.name == "petri"
    # offline: the Inspect CLI is absent, so audit-seed generation must raise cleanly
    guarded = PetriAttacker(cli="inspect-not-installed-xyz")
    dp = synth_corpus(1)[0]
    with pytest.raises(RuntimeError):
        list(guarded.generate(dp, AttackBudget(max_queries=2)))


def test_siuo_converter_registered():
    from pathlib import Path

    from ura.converters import CorpusNotFoundError, SIUOConverter, get_converter

    c = get_converter("siuo")
    assert isinstance(c, SIUOConverter) and c.name == "siuo"
    with pytest.raises(CorpusNotFoundError):
        c.parse(Path("does-not-exist.json"))
