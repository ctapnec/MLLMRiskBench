"""Pricing-page fetcher contracts (experiments/pricing_fetch.py).

The fetcher reads published per-model prices from each provider's own pricing
page and merges them into the effective-dated pricing table.  It must:

* extract the right numbers from each machine-readable provider (Anthropic HTML
  table, OpenAI embedded JSON, DeepSeek positional block, z.ai/GLM table),
* never confuse a shorter model id for a longer one (glm-5 vs glm-5.2),
* never fabricate a price - a model it cannot read stays absent, a provider it
  cannot read (Qwen card layout) yields nothing,
* stamp every fetched rate with source_url/fetched_at/auto_fetched provenance,
* never overwrite an operator-entered rate, and append a fetched rate only when
  it actually differs from the current effective figure,
* survive a transport or parser fault by recording it, never aborting the run.

Extractor tests run against saved page slices under fixtures/pricing/ so they
are deterministic and never touch the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import pricing_fetch as pf

_FIXTURES = Path(__file__).parent / "fixtures" / "pricing"


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


# -- per-provider extractors -------------------------------------------------


def test_extract_anthropic_reads_named_rows() -> None:
    found = pf.extract_anthropic(
        _fixture("anthropic.html"),
        [
            "anthropic:claude-haiku-4-5-20251001",
            "anthropic:claude-opus-5",
            "anthropic:claude-fable-5",
            "anthropic:claude-sonnet-5",
        ],
    )
    assert found["anthropic:claude-haiku-4-5-20251001"] == {
        "input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25,
    }
    assert found["anthropic:claude-opus-5"]["input"] == 5.0
    assert found["anthropic:claude-opus-5"]["output"] == 25.0
    assert found["anthropic:claude-fable-5"]["input"] == 10.0
    assert found["anthropic:claude-fable-5"]["output"] == 50.0
    # A date-snapshot suffix on the id still matches the display-name row.
    assert "cache_read" in found["anthropic:claude-sonnet-5"]


def test_extract_openai_reads_embedded_json() -> None:
    found = pf.extract_openai(
        _fixture("openai.html"),
        ["openai:gpt-5.6-sol", "openai:gpt-5.2", "openai:gpt-4o"],
    )
    assert found["openai:gpt-5.6-sol"] == {
        "input": 5.0, "output": 30.0, "cache_read": 0.5,
    }
    # 3-tuple row (no cached column) still yields input+output.
    assert found["openai:gpt-5.2"]["input"] == 1.75
    assert found["openai:gpt-5.2"]["output"] == 14.0
    assert found["openai:gpt-4o"]["input"] == 2.5
    assert found["openai:gpt-4o"]["output"] == 10.0


def test_extract_openai_handles_null_cache_tier() -> None:
    # gpt-5-pro's cached tier is a bare JSON null (tier unavailable); input and
    # output are still present, so the model is read with no cache_read rather
    # than skipped or mis-aligned.
    found = pf.extract_openai(_fixture("openai.html"), ["openai:gpt-5-pro"])
    assert found["openai:gpt-5-pro"] == {"input": 15.0, "output": 120.0}


def test_extract_openai_skips_truncated_row() -> None:
    # A row cut after a cache tier but before the output tier (an 8MB-cap
    # truncation) must NOT promote the cache rate to output: the row array is
    # unclosed, so the straddling model is left absent rather than mis-priced.
    complete = '[[0,"gpt-good"],[0,1.25],[0,0.125],[0,10]],'
    truncated = '[[0,"gpt-cut"],[0,5],[0,0.5]'  # no closing ] and no output tier
    found = pf.extract_openai(complete + truncated, ["openai:gpt-good", "openai:gpt-cut"])
    assert found["openai:gpt-good"]["output"] == 10.0
    assert "openai:gpt-cut" not in found  # truncated row not mis-priced


def test_extract_openai_exact_id_never_captures_sibling() -> None:
    # The bare base id 'gpt-5' must bind ONLY to the real gpt-5 row, never to an
    # earlier-listed longer sibling (gpt-5.6-sol, gpt-5-mini, gpt-5-pro, ...).
    found = pf.extract_openai(_fixture("openai.html"), ["openai:gpt-5"])
    assert found["openai:gpt-5"] == {"input": 1.25, "output": 10.0, "cache_read": 0.125}
    # And the longer siblings still read as themselves.
    sib = pf.extract_openai(
        _fixture("openai.html"), ["openai:gpt-5-mini", "openai:gpt-5.6-sol"],
    )
    assert sib["openai:gpt-5-mini"]["input"] == 0.25
    assert sib["openai:gpt-5.6-sol"]["input"] == 5.0


def test_extract_anthropic_exact_name_never_captures_newer_minor() -> None:
    # A bare-version id (retired 'claude-opus-4') must bind to the 'Claude Opus
    # 4' row ($15/$75), never to a newer, cheaper 'Claude Opus 4.8' whose label
    # merely contains 'Opus 4'.
    found = pf.extract_anthropic(
        _fixture("anthropic.html"), ["anthropic:claude-opus-4-20250514"],
    )
    assert found["anthropic:claude-opus-4-20250514"]["input"] == 15.0
    assert found["anthropic:claude-opus-4-20250514"]["output"] == 75.0


def test_extract_deepseek_dash_cell_does_not_shift_neighbours() -> None:
    # If one model's price cell is '-'/'Free', it must blank only that model,
    # never shift the other model's price into it (positional, not compacted).
    page = (
        "<table>"
        "<tr><td colspan='2'>MODEL</td><td>deepseek-v4-flash</td>"
        "<td>deepseek-v4-pro</td></tr>"
        "<tr><td rowspan='3'>PRICING</td><td>1M INPUT TOKENS (CACHE MISS)</td>"
        "<td>-</td><td>$0.435</td></tr>"
        "<tr><td>1M INPUT TOKENS (CACHE HIT)</td><td>$0.001</td>"
        "<td>$0.0036</td></tr>"
        "<tr><td>1M OUTPUT TOKENS</td><td>$0.28</td><td>$0.87</td></tr>"
        "</table>"
    )
    found = pf.extract_deepseek(
        page, ["deepseek:deepseek-v4-flash", "deepseek:deepseek-v4-pro"],
    )
    # pro keeps its own input; flash is dropped (no input) rather than stealing
    # pro's 0.435.
    assert found["deepseek:deepseek-v4-pro"]["input"] == 0.435
    assert "deepseek:deepseek-v4-flash" not in found


def test_extract_deepseek_reads_positional_block() -> None:
    found = pf.extract_deepseek(
        _fixture("deepseek.html"),
        ["deepseek:deepseek-v4-pro", "deepseek:deepseek-v4-flash"],
    )
    assert found["deepseek:deepseek-v4-pro"] == {
        "input": 0.435, "output": 0.87, "cache_read": 0.003625,
    }
    assert found["deepseek:deepseek-v4-flash"] == {
        "input": 0.14, "output": 0.28, "cache_read": 0.0028,
    }


def test_extract_gemini_reads_anchored_sections() -> None:
    found = pf.extract_gemini(
        _fixture("gemini.html"),
        ["google:gemini-2.5-flash", "google:gemini-2.5-pro",
         "google:gemini-2.5-flash-lite"],
    )
    assert found["google:gemini-2.5-flash"] == {
        "input": 0.3, "output": 2.5, "cache_read": 0.03,
    }
    assert found["google:gemini-2.5-pro"]["input"] == 1.25
    assert found["google:gemini-2.5-pro"]["output"] == 10.0
    assert found["google:gemini-2.5-flash-lite"]["input"] == 0.1


def test_extract_gemini_absent_model_stays_absent() -> None:
    # A roster model whose anchor is not on the page (e.g. a future/renamed id)
    # is left unmatched, never guessed.
    found = pf.extract_gemini(
        _fixture("gemini.html"), ["google:gemini-9.9-imaginary"],
    )
    assert found == {}


def test_extract_glm_reads_table_rows() -> None:
    found = pf.extract_glm(
        _fixture("glm.html"),
        ["glm:glm-5.2", "glm:glm-4.5-air"],
    )
    assert found["glm:glm-5.2"] == {
        "input": 1.4, "output": 4.4, "cache_read": 0.26,
    }
    assert found["glm:glm-4.5-air"]["input"] == 0.2
    assert found["glm:glm-4.5-air"]["output"] == 1.1


def test_extract_glm_exact_match_never_confuses_shorter_id() -> None:
    # glm-5 and glm-5.2 are distinct rows with distinct prices; the shorter id
    # must not capture the longer row's number and vice-versa.
    found = pf.extract_glm(_fixture("glm.html"), ["glm:glm-5", "glm:glm-5.2"])
    assert found["glm:glm-5"]["input"] == 1.0
    assert found["glm:glm-5"]["output"] == 3.2
    assert found["glm:glm-5.2"]["input"] == 1.4
    assert found["glm:glm-5.2"]["output"] == 4.4


def test_qwen_has_no_extractor() -> None:
    # Alibaba/Qwen renders prices client-side, so it is deliberately NOT in the
    # extractor registry: it is handled like Google/Moonshot (manual entry),
    # never fetched, matching every doc surface.
    assert "qwen" not in pf._EXTRACTORS
    assert not hasattr(pf, "extract_qwen")


def test_extractor_absent_model_stays_absent() -> None:
    # A requested id with no matching row is never guessed into existence.
    found = pf.extract_glm(_fixture("glm.html"), ["glm:glm-does-not-exist"])
    assert found == {}


# -- number parsing ----------------------------------------------------------


def test_num_parses_dollar_and_plain() -> None:
    assert pf._num("$1.4") == 1.4
    assert pf._num("  0.87 ") == 0.87
    assert pf._num("$1,250") == 1250.0
    assert pf._num("Free") is None
    assert pf._num("-") is None
    assert pf._num("") is None


# -- end-to-end merge --------------------------------------------------------


def _write_repo(
    tmp_path: Path, *, pricing: dict, sources: dict,
) -> Path:
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    (repo / "experiments" / "pricing.json").write_text(
        json.dumps(pricing), encoding="utf-8",
    )
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps(sources), encoding="utf-8",
    )
    return repo


def _null_rate(date: str) -> dict:
    return {
        "effective_date": date,
        "currency": "USD",
        "per_million_tokens": {
            "input": None, "output": None, "cache_read": None,
            "cache_write": None, "reasoning": None,
        },
    }


def _fetcher_for(mapping: dict[str, str]):
    def fetch(url: str) -> str:
        return mapping[url]
    return fetch


def test_fetch_pricing_merges_with_provenance(tmp_path: Path) -> None:
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 1
    assert summary["providers"]["glm"]["matched"] == ["glm-5.2"]

    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    fetched = [r for r in rates if r.get("auto_fetched")]
    assert len(fetched) == 1
    rate = fetched[0]
    assert rate["per_million_tokens"]["input"] == 1.4
    assert rate["per_million_tokens"]["output"] == 4.4
    assert rate["source_url"] == "https://z/pricing"
    assert rate["fetched_at"] == "2026-08-16"
    assert rate["effective_date"] == "2026-08-16"


def test_fetch_pricing_never_overwrites_operator_rate(tmp_path: Path) -> None:
    # An operator-entered rate (no auto_fetched) on today's date must survive:
    # a same-valued fetch does not append, and even a differing fetch appends
    # rather than replacing the operator's figure.
    operator = {
        "effective_date": "2026-08-16",
        "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [operator]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    operator_rates = [r for r in rates if not r.get("auto_fetched")]
    assert len(operator_rates) == 1
    assert operator_rates[0]["per_million_tokens"]["input"] == 9.99


def test_fetch_pricing_later_fetch_never_supersedes_operator_rate(tmp_path: Path) -> None:
    # An operator correction dated BEFORE today must not be overridden by a
    # later-dated auto-fetch (the "never overwritten" guarantee holds across
    # dates, not only same-day).  The billed/effective value stays the
    # operator's, and no auto rate is appended.
    operator = {
        "effective_date": "2026-08-15",
        "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [operator]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    assert rates == [operator]  # untouched: no auto rate appended
    effective = pf._current_effective(
        written["providers"]["glm"]["models"]["glm-5.2"], "2026-08-16",
    )
    assert effective["per_million_tokens"]["input"] == 9.99


def test_fetch_pricing_preserves_operator_cache_write_on_price_change(tmp_path: Path) -> None:
    # An operator hand-entered a cache_write the provider page does not publish;
    # a routine input change must not append an auto rate that nulls it (which
    # would force the whole model's cost to N/A).
    operator = {
        "effective_date": "2026-01-01",
        "currency": "USD",
        "per_million_tokens": {
            "input": 1.0, "output": 4.4, "cache_read": 0.26, "cache_write": 0.50,
        },
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [operator]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    effective = pf._current_effective(
        written["providers"]["glm"]["models"]["glm-5.2"], "2026-08-16",
    )
    # Operator rate stands, cache_write intact.
    assert effective["per_million_tokens"]["cache_write"] == 0.50
    assert effective["per_million_tokens"]["input"] == 1.0


def test_fetch_pricing_later_placeholder_does_not_shadow_operator(tmp_path: Path) -> None:
    # A null placeholder dated AFTER an operator's real rate must not become the
    # effective row (which would let a fetch supersede the operator's price).
    operator = {
        "effective_date": "2026-08-10", "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    placeholder = _null_rate("2026-08-16")
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [operator, placeholder]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0  # operator rate protected, not superseded
    entry = json.loads(
        (repo / "experiments" / "pricing.json").read_text("utf-8")
    )["providers"]["glm"]["models"]["glm-5.2"]
    effective = pf._current_effective(entry, "2026-08-16")
    assert effective["per_million_tokens"]["input"] == 9.99


def test_fetch_pricing_preserves_operator_cache_only_rate(tmp_path: Path) -> None:
    # An operator who priced ONLY a cache category (input/output left null) has a
    # real, protectable rate - it must NOT be treated as an unset placeholder
    # and deleted on a same-date fetch.
    operator = {
        "effective_date": "2026-08-16",
        "currency": "USD",
        "per_million_tokens": {
            "input": None, "output": None, "cache_read": None, "cache_write": 0.50,
        },
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [operator]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",  # same date as the operator row
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    assert rates == [operator]  # survived intact, cache_write:0.50 preserved


def test_extract_openai_malformed_number_skips_only_that_model(tmp_path: Path) -> None:
    # A single malformed numeric token must not abort the whole provider: the
    # bad model is skipped, a well-formed sibling still parses.
    page = (
        'rows:[[0,"gpt-bad"],[0,1.2.3],[0,30]],'
        '[[0,"gpt-good"],[0,1.25],[0,0.125],[0,10]]'
    )
    found = pf.extract_openai(page, ["openai:gpt-bad", "openai:gpt-good"])
    assert "openai:gpt-bad" not in found  # malformed input -> skipped, no raise
    assert found["openai:gpt-good"] == {"input": 1.25, "output": 10.0, "cache_read": 0.125}


def test_fetch_pricing_non_dict_per_million_does_not_crash(tmp_path: Path) -> None:
    # A hand-mangled non-dict per_million_tokens on the current effective rate
    # must not raise AttributeError and abort the whole batch.
    bad = {
        "effective_date": "2026-08-15", "currency": "USD",
        "per_million_tokens": "TBD",
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [bad]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    # Must not raise.
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert "error" not in summary
    # 'TBD' is not a real operator price (input/output absent -> placeholder),
    # so the model is filled from the page rather than left mispriced.
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    assert any(r.get("auto_fetched") for r in rates)


def test_fetch_pricing_no_duplicate_when_unchanged(tmp_path: Path) -> None:
    # Fetch once, then fetch again same-day: the second run must not stack a
    # duplicate auto-fetched entry for the same date.
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    fetcher = _fetcher_for({"https://z/pricing": _fixture("glm.html")})
    pf.fetch_pricing(repo, today="2026-08-16", fetcher=fetcher)
    pf.fetch_pricing(repo, today="2026-08-16", fetcher=fetcher)
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    same_day_auto = [
        r for r in rates
        if r.get("auto_fetched") and r["effective_date"] == "2026-08-16"
    ]
    assert len(same_day_auto) == 1


def test_fetch_pricing_unmatched_model_left_as_na(tmp_path: Path) -> None:
    pricing = {
        "providers": {
            "glm": {"models": {"glm-nonexistent": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    assert "glm-nonexistent" in summary["providers"]["glm"]["unmatched"]
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-nonexistent"]["rates"]
    # Untouched: still the null-rate row, nothing fabricated.
    assert all(r["per_million_tokens"]["input"] is None for r in rates)


def test_fetch_pricing_records_transport_failure(tmp_path: Path) -> None:
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)

    def boom(url: str) -> str:
        raise OSError("connection refused")

    summary = pf.fetch_pricing(repo, today="2026-08-16", fetcher=boom)
    assert summary["rates_written"] == 0
    assert "fetch failed" in summary["providers"]["glm"]["note"]


def test_fetch_pricing_records_parser_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)

    def broken(page: str, models: list[str]) -> dict:
        raise RuntimeError("parser bug")

    monkeypatch.setitem(pf._EXTRACTORS, "glm", broken)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    assert "parse failed" in summary["providers"]["glm"]["note"]


def test_full_roster_fetch_covers_every_machine_readable_provider(tmp_path: Path) -> None:
    # The shipped example roster + sources must fetch rates for ALL machine-
    # readable providers and every model on the page - not just two Anthropic
    # models - with Kimi/Qwen honestly reported as manual.
    import shutil

    proj = Path(__file__).parents[2]
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True)
    shutil.copy(proj / "experiments/rig/pricing.example.json",
                repo / "experiments/pricing.json")
    shutil.copy(proj / "experiments/rig/pricing-sources.example.json",
                repo / "experiments/pricing-sources.json")
    urls = json.loads(
        (repo / "experiments/pricing-sources.json").read_text("utf-8")
    )["providers"]
    mapping = {
        urls["anthropic"]["url"]: _fixture("anthropic.html"),
        urls["openai"]["url"]: _fixture("openai.html"),
        urls["deepseek"]["url"]: _fixture("deepseek.html"),
        urls["glm"]["url"]: _fixture("glm.html"),
        urls["google"]["url"]: _fixture("gemini.html"),
    }
    summary = pf.fetch_pricing(repo, today="2026-08-15", fetcher=lambda u: mapping[u])

    anthropic = set(summary["providers"]["anthropic"]["matched"])
    assert anthropic == {
        "claude-opus-5", "claude-sonnet-5", "claude-mythos-5",
        "claude-fable-5", "claude-haiku-4-5-20251001",
    }
    assert summary["providers"]["google"]["matched"]  # Gemini extractor wired
    assert summary["providers"]["deepseek"]["matched"] == ["deepseek-v4-pro"]
    assert summary["providers"]["glm"]["matched"] == ["glm-5.2"]
    assert "manual" in summary["providers"]["kimi"]["note"]
    assert "manual" in summary["providers"]["qwen"]["note"]
    assert summary["rates_written"] >= 12  # far more than the old 2


@pytest.mark.parametrize("provider", ["kimi", "qwen"])
def test_fetch_pricing_notes_unreadable_provider(tmp_path: Path, provider: str) -> None:
    # A provider with a url but no extractor (Moonshot/Kimi and Alibaba/Qwen
    # render client-side) is reported as manual-entry, not fetched, not errored -
    # and no HTTP GET is issued for it (the fetcher would KeyError if it tried,
    # since the map is empty).
    pricing = {
        "providers": {
            provider: {"models": {"some-model": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {provider: {"url": "https://provider/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16", fetcher=_fetcher_for({}),
    )
    assert summary["rates_written"] == 0
    assert "manual" in summary["providers"][provider]["note"]


def test_fetch_pricing_corrupt_file_is_not_overwritten(tmp_path: Path) -> None:
    # A pricing.json that exists but is unparseable must NOT be reset to the
    # null example (that would wipe operator rates); the run refuses and the
    # file is left byte-for-byte intact.
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    corrupt = '{"providers": {"glm": {"models": {"glm-5.2": {"rates": [ ,, ]}}}}}'
    pricing_path = repo / "experiments" / "pricing.json"
    pricing_path.write_text(corrupt, encoding="utf-8")
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps({"providers": {"glm": {"url": "https://z/pricing"}}}),
        encoding="utf-8",
    )
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    assert "error" in summary and "not valid JSON" in summary["error"]
    # Untouched.
    assert pricing_path.read_text(encoding="utf-8") == corrupt


def test_fetch_pricing_unreadable_file_is_refused_and_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A present-but-UNREADABLE pricing.json (permission denial / transient lock)
    # must be refused, not treated as absent: treating it as absent would seed
    # the null example and overwrite the operator's real table once the lock
    # cleared. The file is left intact and no backup/temp is written.
    operator = {
        "effective_date": "2026-08-01", "currency": "USD",
        "per_million_tokens": {"input": 7.77, "output": 8.88},
    }
    pricing = {"providers": {"glm": {"models": {"glm-5.2": {"rates": [operator]}}}}}
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    pricing_path = repo / "experiments" / "pricing.json"
    prior_bytes = pricing_path.read_bytes()

    original = Path.read_text

    def guarded(self, *args, **kwargs):
        if self.name == "pricing.json":
            raise PermissionError("file is share-locked")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    monkeypatch.undo()
    assert summary["rates_written"] == 0
    assert "error" in summary and "could not be read" in summary["error"]
    assert pricing_path.read_bytes() == prior_bytes  # untouched
    assert not (repo / "experiments" / "pricing.json.bak").exists()
    assert not (repo / "experiments" / "pricing.json.tmp").exists()


def test_fetch_total_deadline_covers_stalled_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even if urlopen never returns (a connect/TLS/header-phase stall, which the
    # per-socket timeout misses on a trickle), _fetch must raise within the
    # total deadline rather than hang.
    import threading

    started = threading.Event()

    def blocking_urlopen(_request, timeout=None):  # noqa: ANN001
        started.set()
        threading.Event().wait()  # never returns

    monkeypatch.setattr(pf, "urlopen", blocking_urlopen)
    with pytest.raises(TimeoutError):
        pf._fetch("https://example/pricing", deadline=0.5)
    assert started.is_set()


def test_read_capped_enforces_deadline_on_trickle() -> None:
    # A peer that keeps returning data (never EOF) must not hang past the
    # deadline: read1 returns promptly so the wall-clock check runs each loop.
    class Trickle:
        def read1(self, _n: int) -> bytes:
            return b"x" * 10

    clock = iter([0, 10, 20, 30, 40, 50, 60])
    with pytest.raises(TimeoutError):
        pf._read_capped(Trickle(), deadline=30, clock=lambda: next(clock))


def test_read_capped_returns_all_bytes_before_eof() -> None:
    class Fixed:
        def __init__(self) -> None:
            self.parts = [b"abc", b"def", b""]
            self.i = 0

        def read1(self, _n: int) -> bytes:
            part = self.parts[self.i]
            self.i += 1
            return part

    assert pf._read_capped(Fixed(), deadline=30, clock=lambda: 0.0) == b"abcdef"


def test_fetch_pricing_non_dict_file_is_not_overwritten(tmp_path: Path) -> None:
    # Valid JSON that is not an object (a bare list) must be refused, not crash
    # with AttributeError, and must not be overwritten.
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    pricing_path = repo / "experiments" / "pricing.json"
    pricing_path.write_text("[]", encoding="utf-8")
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps({"providers": {"glm": {"url": "https://z/pricing"}}}),
        encoding="utf-8",
    )
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    assert "error" in summary and "not a JSON object" in summary["error"]
    assert pricing_path.read_text(encoding="utf-8") == "[]"


def test_fetch_pricing_writes_backup_and_is_atomic(tmp_path: Path) -> None:
    # A successful merge backs up the prior bytes to a .bak sibling and leaves
    # no stray .tmp (os.replace consumed it).
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    prior = (repo / "experiments" / "pricing.json").read_text(encoding="utf-8")
    pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    bak = repo / "experiments" / "pricing.json.bak"
    tmp = repo / "experiments" / "pricing.json.tmp"
    assert bak.read_text(encoding="utf-8") == prior
    assert not tmp.exists()


def test_fetch_pricing_non_dict_model_entry_is_skipped(tmp_path: Path) -> None:
    # A hand-mangled non-dict model entry must be recorded, not crash the run.
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    (repo / "experiments" / "pricing.json").write_text(
        json.dumps({"providers": {"glm": {"models": {"glm-5.2": "oops"}}}}),
        encoding="utf-8",
    )
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps({"providers": {"glm": {"url": "https://z/pricing"}}}),
        encoding="utf-8",
    )
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert "error" not in summary  # no crash on the mangled entry
    # The mangled entry is replaced with a fresh dict and priced (no crash).
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    entry = written["providers"]["glm"]["models"]["glm-5.2"]
    assert isinstance(entry, dict) and "rates" in entry


def test_fetch_pricing_prior_auto_unchanged_no_duplicate(tmp_path: Path) -> None:
    # A prior-dated auto rate identical to today's fetch must not append a new
    # dated duplicate every run.
    old_auto = {
        "effective_date": "2026-08-10",
        "currency": "USD",
        "per_million_tokens": {
            "input": 1.4, "output": 4.4, "cache_read": 0.26, "cache_write": None,
        },
        "auto_fetched": True,
        "source_url": "https://z/pricing",
        "fetched_at": "2026-08-10",
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [old_auto]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 0
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    assert len(rates) == 1  # unchanged: no new entry appended


def test_fetch_pricing_same_date_placeholder_is_replaced(tmp_path: Path) -> None:
    # When the shipped null placeholder's date equals today, filling it must
    # REPLACE it (not coexist): otherwise the non-auto placeholder outranks the
    # new auto rate on the equal date and the model still shows N/A.
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [_null_rate("2026-08-15")]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    summary = pf.fetch_pricing(
        repo, today="2026-08-15",  # same date as the placeholder
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    assert summary["rates_written"] == 1
    entry = json.loads(
        (repo / "experiments" / "pricing.json").read_text("utf-8")
    )["providers"]["glm"]["models"]["glm-5.2"]
    # The placeholder is gone; the effective rate is the real fetched value.
    assert len(entry["rates"]) == 1
    assert entry["rates"][0]["auto_fetched"] is True
    effective = pf._current_effective(entry, "2026-08-15")
    assert effective["per_million_tokens"]["input"] == 1.4


def test_current_effective_same_date_operator_beats_auto_any_order() -> None:
    # The same-date tie-break must favour the operator rate irrespective of the
    # order the two entries sit in the list.
    auto = {
        "effective_date": "2026-08-16", "currency": "USD",
        "per_million_tokens": {"input": 1.4, "output": 4.4}, "auto_fetched": True,
    }
    operator = {
        "effective_date": "2026-08-16", "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    for order in ([auto, operator], [operator, auto]):
        chosen = pf._current_effective({"rates": order}, "2026-08-16")
        assert chosen["per_million_tokens"]["input"] == 9.99


def test_iter_rows_and_cells_parse_table() -> None:
    page = "<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>"
    rows = [pf._cells(r) for r in pf._iter_rows(page)]
    assert rows == [["A", "B"], ["1", "2"]]


def test_iter_rows_terminates_on_unclosed_tr() -> None:
    # A page of <tr> opening tokens with no closing tag yields no rows in linear
    # time (the split-based scan cannot backtrack).
    page = "<tr>" * 100000
    assert list(pf._iter_rows(page)) == []


def test_cells_linear_on_flooded_cell() -> None:
    # A cell whose inner is a huge run of '<' with no '>' must strip in linear
    # time (a backtracking regex would take minutes at this size and hang).
    row = "<td>" + "<" * 400000 + "</td>"
    assert pf._cells(row) == [""]


def test_extract_glm_linear_on_flooded_cell() -> None:
    # The end-to-end extractor path (which calls _cells on every row) must also
    # stay linear on a hostile page.
    page = "<table><tr><td>" + "<" * 400000 + "</td></tr></table>"
    assert pf.extract_glm(page, ["glm:glm-5.2"]) == {}


def test_strip_tags_handles_normal_and_malformed() -> None:
    assert pf._strip_tags("<a href='x'>hello</a>") == "hello"
    assert pf._strip_tags("a<b>c</b>d") == "acd"
    assert pf._strip_tags("open<no-close") == "open"  # unclosed tail dropped
    assert pf._strip_tags("$1.4") == "$1.4"


def test_fetch_pricing_appends_new_date_when_price_changes(tmp_path: Path) -> None:
    # A prior auto-fetched rate exists; a later fetch with a different number
    # appends a new effective-dated entry (both are retained as history).
    old_auto = {
        "effective_date": "2026-08-10",
        "currency": "USD",
        "per_million_tokens": {"input": 1.0, "output": 3.0},
        "auto_fetched": True,
        "source_url": "https://z/pricing",
        "fetched_at": "2026-08-10",
    }
    pricing = {
        "providers": {
            "glm": {"models": {"glm-5.2": {"rates": [old_auto]}}},
        }
    }
    sources = {"providers": {"glm": {"url": "https://z/pricing"}}}
    repo = _write_repo(tmp_path, pricing=pricing, sources=sources)
    pf.fetch_pricing(
        repo, today="2026-08-16",
        fetcher=_fetcher_for({"https://z/pricing": _fixture("glm.html")}),
    )
    written = json.loads((repo / "experiments" / "pricing.json").read_text("utf-8"))
    rates = written["providers"]["glm"]["models"]["glm-5.2"]["rates"]
    dates = sorted(r["effective_date"] for r in rates)
    assert dates == ["2026-08-10", "2026-08-16"]
    latest = max(rates, key=lambda r: r["effective_date"])
    assert latest["per_million_tokens"]["input"] == 1.4
