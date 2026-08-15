"""Fetch per-model prices from providers' published pricing pages.

The console's calculated-cost display multiplies recorded tokens by an
operator-edited effective-dated price table (``experiments/pricing.json``).
Typing those rates by hand is tedious, so this tool retrieves them from each
provider's own published pricing page and writes them into the table stamped
with their source and fetch date.

It never fabricates a price.  A rate it cannot extract with confidence is left
untouched (rendered as N/A downstream), never guessed.  Every fetched rate
carries ``source_url``, ``fetched_at`` and ``auto_fetched: true`` provenance so
the console can badge it distinctly from an operator-entered rate.  Once the
operator has priced a model by hand (a rate without ``auto_fetched`` whose
input or output is non-null), that figure is authoritative and is never
superseded - not on the same date and not by a later-dated fetch - so the
console always bills the operator's number until the operator edits it
directly.  The fetcher only fills a model the operator has not priced or
updates a rate it set itself (appending a later-dated entry only when the
price actually differs).

Providers currently machine-readable: Anthropic (HTML pricing table), OpenAI
(the pricing page's embedded JSON), DeepSeek (HTML table), z.ai/GLM (HTML
table) and Google Gemini (per-model anchored sections; ``google`` is the
provider prefix, e.g. ``google:gemini-3.6-flash``).  Moonshot/Kimi and
Alibaba/Qwen render their prices client-side (no rates in the HTML), so they
stay manual - deliberately absent from the extractor registry, so the fetcher
records the attempt and leaves their rates untouched.

No provider exposes per-token prices through its inference API, so this is a
pricing-page reader, not an API-cost reader.  All requests are read-only
HTTPS GETs to the configured public URLs; nothing else leaves the machine.

The merge is atomic (temp-file + os.replace) with a prior-file backup.  The
console's "Fetch from provider pricing pages" button is the coordinated write
path: it serializes this fetch against the pricing config editor with an
in-process lock.  Running this module standalone (``python -m
experiments.pricing_fetch``) writes the same file WITHOUT that lock, so do not
run the CLI fetch at the same moment a running console is saving a pricing edit
- the two writes are each atomic but not mutually exclusive across processes,
so the later os.replace wins (recoverable from ``pricing.json.bak`` /
config-backups).  Use the console button while the console is running.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.request import Request, urlopen

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCES_LOCAL = "experiments/pricing-sources.json"
_SOURCES_EXAMPLE = "experiments/rig/pricing-sources.example.json"
_PRICING_LOCAL = "experiments/pricing.json"
_PRICING_EXAMPLE = "experiments/rig/pricing.example.json"
_MAX_BYTES = 8 * 1024 * 1024
#: Total wall-clock budget for a single page fetch, covering the WHOLE
#: operation (connect, TLS, headers and body).  urlopen's ``timeout`` is only a
#: per-socket-operation timeout that resets on every byte, so a peer that
#: trickles bytes just under it - in the header phase (before the body read is
#: even reached) or in the body - could otherwise stall a request forever.  The
#: fetch runs in a worker thread joined for this long; if it overruns, the
#: caller raises and moves on (recorded as a failed fetch) rather than hang.
_FETCH_DEADLINE = 30.0

#: The billing categories the fetchers may populate.  Cache and reasoning
#: rates are provider-specific and inconsistently published, so the fetchers
#: fill only input/output (and cache_read where a provider clearly lists it);
#: everything else stays for the operator to enter.
_FETCHED_CATEGORIES = ("input", "output", "cache_read", "cache_write")


def _read_capped(
    response: Any, *, deadline: float, clock: Callable[[], float] = time.monotonic,
) -> bytes:
    """Read at most ``_MAX_BYTES`` under a hard wall-clock ``deadline``.

    Uses ``read1`` (at most one underlying socket read per call), so the
    deadline is re-checked after every chunk.  A plain ``read(n)`` would block
    inside the socket buffer trying to fill the full request, letting a peer
    that trickles bytes just under the socket timeout stall the transfer far
    past the deadline; ``read1`` returns whatever arrived so the loop runs.
    """

    start = clock()
    chunks: list[bytes] = []
    total = 0
    while total < _MAX_BYTES:
        if clock() - start > deadline:
            raise TimeoutError(f"fetch exceeded {deadline:g}s deadline")
        chunk = response.read1(min(65536, _MAX_BYTES - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _fetch(url: str, *, timeout: int = 15, deadline: float = _FETCH_DEADLINE) -> str:
    request = Request(url, headers={"User-Agent": "Mozilla/5.0 (ura-rig pricing)"})

    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https pricing URLs
                box["data"] = _read_capped(response, deadline=deadline)
        except BaseException as exc:  # noqa: BLE001 - relayed to the caller
            box["error"] = exc

    # Run the blocking urlopen+read in a worker so the CALLER's wait for the
    # WHOLE operation (connect, TLS, headers, body) is bounded by one wall-clock
    # deadline.  urlopen's own timeout resets per socket-op, so a header-phase
    # trickle would otherwise hang past any per-op timeout; joining the worker
    # caps the caller's wait regardless.  If it overruns we abandon the daemon
    # thread and raise, so the caller records a failed fetch and releases any
    # lock it holds instead of freezing.  The abandoned worker keeps its socket
    # until the peer stops trickling or http.client's own header limits
    # (_MAXLINE / _MAXHEADERS) end the read - a bounded background cost, never a
    # console hang.
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(deadline)
    if thread.is_alive():
        raise TimeoutError(f"fetch exceeded {deadline:g}s deadline (stalled)")
    if "error" in box:
        raise box["error"]
    return box.get("data", b"").decode("utf-8", errors="replace")


def _num(value: str) -> float | None:
    value = value.strip().replace(",", "")
    if not re.fullmatch(r"\$?\s*\d+(?:\.\d+)?", value):
        return None
    return float(value.lstrip("$").strip())


# -- HTML row/cell scanning --------------------------------------------------
#
# Every scan here is linear (str.split / str.find / str.rfind, all C-level, and
# a single forward pass to strip tags).  A lazy ``<tr>(.*?)</tr>`` regex or a
# greedy ``<[^>]+>`` re.sub is O(n^2) on a pathological page (a long run of
# unclosed ``<`` scans to end-of-string once per start), which a slow/hostile
# provider page could weaponise into a multi-minute parse; the string
# operations below cannot backtrack, so an 8MB junk page stays bounded.


def _strip_tags(text: str) -> str:
    """Remove ``<...>`` spans in a single linear pass (no regex backtracking).

    An unclosed ``<`` (no following ``>``) ends the scan - a malformed tail is
    dropped rather than scanned repeatedly.
    """

    out: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text[i] == "<":
            close = text.find(">", i + 1)
            if close == -1:
                break
            i = close + 1
        else:
            nxt = text.find("<", i)
            if nxt == -1:
                out.append(text[i:])
                break
            out.append(text[i:nxt])
            i = nxt
    return "".join(out)


def _iter_rows(page: str) -> Iterator[str]:
    for chunk in page.split("</tr>")[:-1]:
        start = chunk.rfind("<tr")
        if start == -1:
            continue
        gt = chunk.find(">", start)
        if gt == -1:
            continue
        yield chunk[gt + 1:]


def _cells(row_html: str) -> list[str]:
    cells: list[str] = []
    for chunk in re.split(r"</t[dh]>", row_html, flags=re.I)[:-1]:
        # Last opening <td>/<th> in the chunk, found with rfind (linear) rather
        # than a regex that could backtrack on a flood of '<' with no '>'.
        lowered = chunk.lower()
        start = max(lowered.rfind("<td"), lowered.rfind("<th"))
        if start == -1:
            continue
        gt = chunk.find(">", start)
        if gt == -1:
            continue
        cells.append(_strip_tags(html.unescape(chunk[gt + 1:])).strip())
    return cells


# -- per-provider extractors -------------------------------------------------
#
# Each returns {model_id: {category: per_million_usd}} for the model ids it can
# confidently read.  A model it cannot find is simply absent (never guessed).


def _map_header(lowered: list[str]) -> dict[str, int]:
    """Map billing categories to column indices from a header row by name.

    Located by column name, not fixed position, so a reorder cannot silently
    mis-price.  Recognizes ``input``/``output`` base columns plus cache
    read/write where clearly labelled (``cached input`` -> cache_read).
    """

    header: dict[str, int] = {}
    for index, label in enumerate(lowered):
        if "input" in label and not any(
            tag in label for tag in ("cache", "cached", "batch", "write", "storage")
        ):
            header.setdefault("input", index)
        if "output" in label and "batch" not in label:
            header.setdefault("output", index)
        if (
            "cache_read" not in header
            and "storage" not in label
            and "write" not in label
            and (
                label.strip() in ("cached input", "cache")
                or (("cache" in label or "cached" in label)
                    and ("read" in label or "hit" in label))
            )
        ):
            header.setdefault("cache_read", index)
        if "cache" in label and "write" in label:
            # A provider may list several cache-write TTL columns (Anthropic has
            # a 5-minute and a 1-hour column); setdefault binds the first, which
            # is the provider's default TTL (5m for Anthropic).  Recorded usage
            # carries a single, undifferentiated cache_write bucket, so the
            # default-TTL rate is the correct one for the common case; 1h-cached
            # usage is a known under-count the single bucket cannot separate.
            header.setdefault("cache_write", index)
    return header


def _header_table(
    page: str, models: list[str], match: Callable[[str, str], bool],
) -> dict[str, dict[str, float]]:
    """Extract rates from a row-per-model table with a named-column header.

    ``match(model_id, row_label) -> bool`` decides whether a table row belongs
    to a requested model.  A model whose row is absent stays absent (never
    guessed).  Requires both input and output before a model is emitted.
    """

    out: dict[str, dict[str, float]] = {}
    header_idx: dict[str, int] = {}
    for row in _iter_rows(page):
        cells = _cells(row)
        if not cells:
            continue
        lowered = [c.lower() for c in cells]
        if any("input" in c for c in lowered) and any(
            "output" in c for c in lowered
        ):
            header_idx = _map_header(lowered)  # re-map on each header (tables repeat it)
            continue
        if not header_idx:
            continue
        label = cells[0]
        for model in models:
            if model in out or not match(model, label):
                continue
            rates: dict[str, float] = {}
            for category, index in header_idx.items():
                if index < len(cells):
                    value = _num(cells[index].split("/")[0])
                    if value is not None:
                        rates[category] = value
            if "input" in rates and "output" in rates:
                out[model] = rates
    return out


def _anthropic_name_hints(needle: str) -> list[str]:
    # Map an api-targets id like "anthropic:claude-haiku-4-5-20251001" to the
    # display-name fragments the pricing table uses ("Claude Haiku 4.5").
    base = needle.replace("anthropic:", "").replace("claude-", "")
    base = re.sub(r"-\d{8}$", "", base)  # drop a trailing date snapshot
    family = base.split("-")[0]  # haiku / opus / sonnet / fable / mythos
    version = re.sub(r"[^0-9.]", ".", base[len(family):]).strip(".")
    version = re.sub(r"\.+", ".", version)
    hints = [f"claude {family} {version}".strip()]
    if version:
        hints.append(f"{family} {version}")
    return [h for h in hints if h]


def _normalize_label(label: str) -> str:
    # Lowercase, drop a trailing parenthetical annotation ("Claude Opus 4
    # (deprecated ...)" -> "claude opus 4"), and collapse whitespace, so a name
    # can be compared for EXACT equality rather than substring containment.
    stripped = re.sub(r"\s*\(.*$", "", label.lower()).strip()
    return re.sub(r"\s+", " ", stripped)


def extract_anthropic(page: str, models: list[str]) -> dict[str, dict[str, float]]:
    """Anthropic pricing table (row per model, display names like
    'Claude Haiku 4.5').

    Matches the display name EXACTLY (after normalization) so a bare-version id
    like ``claude-opus-4`` binds only to the 'Claude Opus 4' row and never to a
    newer, differently-priced 'Claude Opus 4.8' whose label merely contains it.
    """

    def match(model: str, label: str) -> bool:
        needle = model.split(":", 1)[-1].lower()
        return _normalize_label(label) in _anthropic_name_hints(needle)

    return _header_table(page, models, match)


def _dash_name(model: str) -> str:
    # Provider id -> a dash/lowercase display token (glm:glm-5.2 -> glm-5.2).
    return model.split(":", 1)[-1].lower().strip()


def extract_glm(page: str, models: list[str]) -> dict[str, dict[str, float]]:
    """z.ai GLM pricing table (row per model, exact ids like 'GLM-5.2')."""

    def match(model: str, label: str) -> bool:
        needle = _dash_name(model)
        cell = label.lower().strip()
        # Exact match (case-insensitive) so glm-5 never captures glm-5.2.
        return cell == needle

    return _header_table(page, models, match)


def extract_openai(page: str, models: list[str]) -> dict[str, dict[str, float]]:
    """OpenAI's pricing page embeds rows as JSON: [name, in, cached_in, ..., out].

    The row shape is ``[[0,"gpt-5.6-sol"],[0,5],[0,0.5],[0,6.25],[0,30]]`` -
    the first inner value is the model id, the next is input $/MTok, then
    cached input, and the last is output $/MTok.  A tier that is unavailable is
    a ``"-"`` string or a JSON ``null``.

    The model id is matched EXACTLY (after stripping a trailing " (<272K
    context length)"-style annotation) so a requested base id like ``gpt-5``
    binds only to the real ``gpt-5`` row, never to an earlier-listed longer
    sibling such as ``gpt-5.6-sol`` or ``gpt-5-mini``.
    """

    out: dict[str, dict[str, float]] = {}
    text = html.unescape(page)
    wanted = {model.split(":", 1)[-1]: model for model in models}
    # The trailing ``\]`` requires the row array to be CLOSED, so a page cut at
    # the 8MB read cap mid-row (after a cache tier but before the output tier)
    # does not match a partial row - the straddling model is left absent (N/A)
    # rather than mis-priced by promoting a cheaper tier to output.
    row_re = re.compile(
        r"\[\[0,\"([^\"]*)\"\]"
        r"((?:,\[0,(?:\"[^\"]*\"|[0-9.]+|null)\])+)\]"
    )
    for row in row_re.finditer(text):
        model_id = re.sub(r"\s*\(.*$", "", row.group(1)).strip()
        model = wanted.get(model_id)
        if model is None or model in out:
            continue
        values = re.findall(r"\[0,(\"[^\"]*\"|[0-9.]+|null)\]", row.group(2))
        nums: list[float | None] = []
        for value in values:
            if value.startswith('"') or value == "null":
                nums.append(None)  # placeholder for an unavailable tier
            else:
                # _num, not float(): a ``[0-9.]+`` token like "1.2.3" is not a
                # valid float and would raise, aborting the whole provider; _num
                # returns None for it so only that one tier is dropped.
                nums.append(_num(value))
        if len(nums) < 2 or nums[0] is None or nums[-1] is None:
            continue
        rates = {"input": nums[0], "output": nums[-1]}
        if len(nums) >= 3 and nums[1] is not None and nums[1] < nums[0]:
            rates["cache_read"] = nums[1]
        out[model] = rates
    return out


def extract_deepseek(page: str, models: list[str]) -> dict[str, dict[str, float]]:
    """DeepSeek's simple pricing block lists the models left-to-right.

    A ``MODEL`` header names the columns (``deepseek-v4-flash``,
    ``deepseek-v4-pro``); the model prices are the trailing N cells of each
    price row (a leading rowspan label such as 'PRICING' offsets some rows, so
    the values are read from the right).  Each model is read at its own column
    position WITHOUT compacting out non-numeric cells, so a '-'/'Free' cell
    blanks only its own model rather than shifting its neighbours' prices.
    Only the flat block (from the flat ``MODEL`` header up to the next such
    header) is read; the tiered off-peak/peak block is skipped.
    """

    rows = [c for c in (_cells(r) for r in _iter_rows(page)) if c]
    header_i: int | None = None
    order: list[str] | None = None
    for index, row in enumerate(rows):
        joined = " ".join(row).lower()
        if row[0].strip().upper() == "MODEL" and "deepseek" in joined:
            cols = [c.lower() for c in row[1:]]
            if any("input" in c or "output" in c for c in cols):
                continue  # the tiered block's header; skip it
            order = cols
            header_i = index
            break
    if not order or header_i is None:
        return {}

    out: dict[str, dict[str, float]] = {}
    ncols = len(order)
    for row in rows[header_i + 1:]:
        if row[0].strip().upper() == "MODEL":
            break  # a subsequent block starts; stay within the flat block
        label = " ".join(row).lower()
        if "output" in label:
            kind = "output"
        elif "input" in label and "hit" in label:
            kind = "cache_read"
        elif "input" in label and ("miss" in label or "cache" not in label):
            kind = "input"
        else:
            continue
        model_cells = row[-ncols:] if len(row) >= ncols else []
        if len(model_cells) != ncols:
            continue
        for model in models:
            needle = _dash_name(model)
            if needle not in order:
                continue
            value = _num(model_cells[order.index(needle)])
            if value is not None:
                out.setdefault(model, {})[kind] = value
    # Keep only models with both a base input and an output.
    return {m: r for m, r in out.items() if "input" in r and "output" in r}


def _first_price(cell: str) -> float | None:
    """The first ``$N`` amount in a cell (the currently effective one).

    Gemini lists a phased price ("$0.75 through December 31, 2026.$1.50
    starting January 1, 2027."); the first amount is the rate in effect now.
    """

    match = re.search(r"\$\s?([0-9]+(?:\.[0-9]+)?)", cell)
    return float(match.group(1)) if match else None


def extract_gemini(page: str, models: list[str]) -> dict[str, dict[str, float]]:
    """Google Gemini pricing page: one section per model, keyed by an anchor
    ``id="gemini-..."``, each with 'Input price', 'Output price' and 'Context
    caching price' rows.

    The paid rate is the LAST cell of each row (a leading 'Free of charge' /
    'Not available' free-tier cell is ignored), and its first ``$`` amount is
    the rate in effect today (a phased price runs 'through <future date>').
    A model whose anchor is absent (not on the page) stays unmatched.
    """

    out: dict[str, dict[str, float]] = {}
    heads = [(m.start(), m.group(1).lower())
             for m in re.finditer(r'id="(gemini[^"]+)"', page)]
    if not heads:
        return out
    heads.append((len(page), ""))
    wanted = {model.split(":", 1)[-1].lower(): model for model in models}
    for index in range(len(heads) - 1):
        start, anchor = heads[index]
        model = wanted.get(anchor)
        if model is None or model in out:
            continue
        section = page[start:heads[index + 1][0]]
        rates: dict[str, float] = {}
        for row in _iter_rows(section):
            cells = _cells(row)
            if not cells:
                continue
            label = cells[0].lower()
            value = _first_price(cells[-1])  # paid column is the last cell
            if value is None:
                continue
            if label.startswith("input price"):
                rates.setdefault("input", value)
            elif label.startswith("output price"):
                rates.setdefault("output", value)
            elif "caching price" in label:
                rates.setdefault("cache_read", value)
        if "input" in rates and "output" in rates:
            out[model] = rates
    return out


#: Provider -> extractor.  Only providers whose published page is genuinely
#: machine-readable appear here; Moonshot/Kimi and Alibaba/Qwen render prices
#: client-side, so they are deliberately absent and fetch_pricing reports them
#: as "not machine-readable (enter rates manually)" - exactly the honest status
#: their source notes claim, rather than issuing a pointless fetch and burying
#: the model under an ambiguous "unmatched".  ``google`` is Gemini; its provider
#: prefix in model ids is ``google`` (e.g. ``google:gemini-3.6-flash``).
_EXTRACTORS: dict[str, Callable[[str, list[str]], dict[str, dict[str, float]]]] = {
    "anthropic": extract_anthropic,
    "openai": extract_openai,
    "deepseek": extract_deepseek,
    "glm": extract_glm,
    "google": extract_gemini,
}


def load_sources(repo_root: Path = _REPO_ROOT) -> dict[str, Any]:
    for candidate in (_SOURCES_LOCAL, _SOURCES_EXAMPLE):
        path = repo_root / candidate
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("providers"), dict):
            return data
    return {"providers": {}}


def _models_for_provider(pricing: dict[str, Any], provider: str) -> list[str]:
    entry = pricing.get("providers", {}).get(provider, {})
    models = entry.get("models") if isinstance(entry, dict) else None
    return sorted(models) if isinstance(models, dict) else []


def _current_effective(model_entry: dict[str, Any], today: str) -> dict[str, Any] | None:
    rates = model_entry.get("rates")
    if not isinstance(rates, list):
        return None
    applicable = [
        rate for rate in rates
        if isinstance(rate, dict)
        and isinstance(rate.get("effective_date"), str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rate["effective_date"])
        and rate["effective_date"] <= today
        # An all-null placeholder is not a real price: exclude it so an
        # operator's earlier real rate stays effective (and protected) even when
        # a later-dated placeholder was left in the list.
        and not _is_null_placeholder(rate)
    ]
    if not applicable:
        return None
    # On an equal effective_date, an operator-entered rate outranks an
    # auto-fetched one, and a later list position outranks an earlier one, so a
    # same-date operator correction always wins regardless of insertion order.
    return max(
        enumerate(applicable),
        key=lambda item: (
            item[1]["effective_date"],
            0 if item[1].get("auto_fetched") else 1,
            item[0],
        ),
    )[1]


def _priced_categories(rate: Any) -> bool:
    """True if the rate has any non-null per-million figure (any category).

    Keys on EVERY category, not just input/output, so an operator who priced
    only a cache category (leaving input/output null) still counts as having
    set a real, protectable rate.
    """

    if not isinstance(rate, dict):
        return False
    pm = rate.get("per_million_tokens")
    pm = pm if isinstance(pm, dict) else {}
    return any(value is not None for value in pm.values())


def _is_null_placeholder(rate: Any) -> bool:
    """True for a rate with no non-null figure in ANY category (unset).

    The shipped example ships such rows so the operator (or the fetcher) can
    fill them; they carry no `auto_fetched` flag but are not a real price.  A
    rate that prices even one category (e.g. a hand-entered cache_write) is NOT
    a placeholder and is never deleted.
    """

    if not isinstance(rate, dict):
        return False
    return not _priced_categories(rate)


def _load_pricing_for_merge(
    repo_root: Path, pricing_path: Path,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Load the table to merge into, preserving operator data on any fault.

    Returns ``(pricing, existing_raw, error)``.  If the local file exists but
    is unreadable/not-an-object, ``pricing`` is None and ``error`` is set so the
    caller refuses the merge - overwriting a file we could not parse would wipe
    the operator's rates.  A genuinely absent file starts from the null example.
    """

    try:
        existing_raw: str | None = pricing_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Genuinely absent: start from the checked-in null example.
        try:
            pricing = json.loads(
                (repo_root / _PRICING_EXAMPLE).read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            pricing = {"providers": {}}
        if not isinstance(pricing, dict):
            pricing = {"providers": {}}
        return pricing, None, None
    except OSError as exc:
        # Present but UNREADABLE (a permission denial, a transient share lock
        # from cloud sync/AV, an I/O error).  This is NOT an absent file, so it
        # must be refused rather than reset - treating it as absent would seed
        # the null example and os.replace() it over the operator's real table
        # once the lock cleared, silently wiping every hand-entered rate.
        return None, None, (
            f"experiments/pricing.json could not be read ({exc}); not fetching "
            "so operator-entered rates are preserved (retry once it is readable)"
        )

    try:
        pricing = json.loads(existing_raw)
    except ValueError:
        return None, existing_raw, (
            "experiments/pricing.json is not valid JSON; not fetching so "
            "operator-entered rates are preserved (fix the file and retry)"
        )
    if not isinstance(pricing, dict):
        return None, existing_raw, (
            "experiments/pricing.json is not a JSON object; not fetching so "
            "operator-entered rates are preserved"
        )
    return pricing, existing_raw, None


def _write_pricing_atomically(
    pricing_path: Path, pricing: dict[str, Any], existing_raw: str | None,
) -> None:
    """Write the merged table atomically, backing up prior bytes first.

    Mirrors the console's save_config discipline: preserve the previous content
    under a .bak sibling so a bad merge is recoverable, then write to a .tmp and
    os.replace() it into place so a crash mid-write can never leave a truncated
    pricing.json (which the load path would otherwise treat as corrupt).
    """

    text = json.dumps(pricing, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if existing_raw is not None:
        try:
            pricing_path.with_name(pricing_path.name + ".bak").write_text(
                existing_raw, encoding="utf-8",
            )
        except OSError:
            pass
    tmp = pricing_path.with_name(pricing_path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, pricing_path)


def fetch_pricing(
    repo_root: Path = _REPO_ROOT,
    *,
    today: str,
    fetcher: Callable[[str], str] = _fetch,
) -> dict[str, Any]:
    """Fetch published prices and merge them into the local pricing table.

    Returns a summary of what was fetched, matched, skipped, and errored.
    ``today`` is passed in explicitly (the runtime forbids ``Date.now`` in some
    contexts and it keeps the merge deterministic in tests).
    """

    sources = load_sources(repo_root)
    pricing_path = repo_root / _PRICING_LOCAL
    pricing, existing_raw, load_error = _load_pricing_for_merge(repo_root, pricing_path)
    if pricing is None:
        return {
            "fetched_at": today, "providers": {}, "rates_written": 0,
            "error": load_error,
        }
    pricing.setdefault("providers", {})
    if not isinstance(pricing["providers"], dict):
        return {
            "fetched_at": today, "providers": {}, "rates_written": 0,
            "error": "experiments/pricing.json 'providers' is not a JSON object",
        }

    summary: dict[str, Any] = {
        "fetched_at": today, "providers": {}, "rates_written": 0,
    }
    for provider, config in sorted(sources.get("providers", {}).items()):
        url = str(config.get("url", "")).strip() if isinstance(config, dict) else ""
        report = {"url": url, "matched": [], "unmatched": [], "note": ""}
        summary["providers"][provider] = report
        extractor = _EXTRACTORS.get(provider)
        models = _models_for_provider(pricing, provider)
        if not url or extractor is None or not models:
            report["note"] = (
                "no source url" if not url else
                "not machine-readable (enter rates manually)"
                if extractor is None else "no models in pricing table"
            )
            continue
        try:
            page = fetcher(url)
        except Exception as exc:  # noqa: BLE001 - surface any transport error
            report["note"] = f"fetch failed: {exc}"
            continue
        try:
            found = extractor(page, models)
        except Exception as exc:  # noqa: BLE001 - a parser fault must not abort
            report["note"] = f"parse failed: {exc}"
            continue
        provider_entry = pricing["providers"].get(provider)
        if not isinstance(provider_entry, dict):
            report["note"] = "provider entry is not a JSON object"
            continue
        provider_models = provider_entry.setdefault("models", {})
        if not isinstance(provider_models, dict):
            report["note"] = "provider 'models' is not a JSON object"
            continue
        for model in models:
            rates = found.get(model)
            if not rates:
                report["unmatched"].append(model)
                continue
            per_million = {cat: rates.get(cat) for cat in _FETCHED_CATEGORIES}
            model_entry = provider_models.get(model)
            if not isinstance(model_entry, dict):
                model_entry = {}
                provider_models[model] = model_entry
            existing_rates = model_entry.get("rates")
            if not isinstance(existing_rates, list):
                existing_rates = []
                model_entry["rates"] = existing_rates
            current = _current_effective(model_entry, today)
            if current is not None:
                current_pm = current.get("per_million_tokens")
                if not isinstance(current_pm, dict):
                    current_pm = {}
                operator_set = not current.get("auto_fetched") and _priced_categories(
                    current
                )
                if operator_set:
                    # The operator has priced this model by hand.  Their figure
                    # is authoritative and is NEVER superseded - not on the same
                    # date and not by a later-dated fetch (which would otherwise
                    # outrank it and silently bill the value they rejected, and
                    # would drop any category, e.g. cache_write, the page lacks).
                    # To change it the operator edits the rate directly.
                    report["matched"].append(model)
                    continue
                if current.get("auto_fetched"):
                    # Prior auto rate: skip when nothing the fetcher reads has
                    # changed, so a repeated (e.g. daily) fetch does not stack
                    # duplicate dated entries for an unchanged price.
                    if all(
                        current_pm.get(cat) == per_million.get(cat)
                        for cat in _FETCHED_CATEGORIES
                    ):
                        report["matched"].append(model)
                        continue
                # A placeholder (operator entry whose input/output are still
                # null, e.g. the shipped example) is treated as unset and filled.
            new_rate = {
                "effective_date": today,
                "currency": "USD",
                "per_million_tokens": per_million,
                "auto_fetched": True,
                "source_url": url,
                "fetched_at": today,
            }
            # Replace a same-date auto-fetched rate rather than stacking, and
            # drop a same-date NULL placeholder we are filling - otherwise the
            # non-auto placeholder would outrank the new auto rate on the equal
            # date (operator-beats-auto tie-break) and the model would still
            # render N/A despite the successful fetch.  A same-date real
            # operator rate is never reached here (that path already skipped).
            model_entry["rates"] = [
                rate for rate in existing_rates
                if not (isinstance(rate, dict)
                        and rate.get("effective_date") == today
                        and (rate.get("auto_fetched") or _is_null_placeholder(rate)))
            ]
            model_entry["rates"].append(new_rate)
            report["matched"].append(model)
            summary["rates_written"] += 1

    _write_pricing_atomically(pricing_path, pricing, existing_raw)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch per-model prices from providers' published pricing pages "
            "into experiments/pricing.json (read-only HTTPS; never fabricates "
            "a price - unreadable rates stay manual)"
        )
    )
    parser.add_argument("--repo-root", default=None)
    parser.add_argument(
        "--date", default=None,
        help="effective date to stamp fetched rates (default: today, UTC)",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root) if args.repo_root else _REPO_ROOT
    today = args.date or time.strftime("%Y-%m-%d", time.gmtime())
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", today):
        print("--date must be YYYY-MM-DD", file=sys.stderr)
        return 1
    summary = fetch_pricing(repo_root, today=today)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
