"""Bounded, offline-friendly acquisition bridge for the aggregator corpora.

Downloads the six released aggregator sources - SALAD-Bench, AIR-Bench 2024,
XSTest, SimpleSafetyTests, DecodingTrust (stereotype perspective) and HoliSafe
(gated multimodal) - into the exact on-disk layout their converters read, so the
whole acquisition is reproducible from the repo (the distro installer calls
this, and it mirrors the ``export_jalmbench``/``export_vlsbench`` pattern).

Each source is fetched from its authoritative host - the Hugging Face
datasets-server parquet/rows API, the upstream GitHub raw file, or (HoliSafe) a
full ``hf download`` of the gated dataset repo - and written under
``<out-root>/<Source>/``. Nothing here scores a model or contacts a provider; it
only prepares local corpus files. Usage::

    python -m experiments.export_aggregators --source all --out-root "$URA_CORPORA"
    python -m experiments.export_aggregators --source airbench --out-root /data/.../corpora

The printed target paths are what ``URA_SALADBENCH_PATH`` / ``URA_AIRBENCH_PATH``
/ ``URA_XSTEST_PATH`` / ``URA_SIMPLESAFETYTESTS_PATH`` /
``URA_DECODINGTRUST_STEREOTYPE_PATH`` / ``URA_HOLISAFE_PATH`` must point at.

Every export also writes an ``<corpus-stem>.acquisition.json`` sidecar beside
the corpus file: upstream identity (dataset id with config/split, or repo and
path), the upstream revision *resolved from the host itself*, the retrieval
endpoint and the exact URLs read, a UTC timestamp, and the exported file's
sha256/byte count/row count. Content is requested AT the resolved revision
wherever the endpoint allows it, so the bytes and the recorded revision provably
correspond; where an endpoint genuinely cannot be pinned or the host cannot name
a commit, the sidecar carries an explicit ``null`` plus a reason string rather
than anything that could be mistaken for a sha. The source-conformance receipt
reads these sidecars for its ``upstream_uri``/``requested_revision``/
``observed_revision`` fields.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ACQUISITION_SCHEMA = "ura-aggregator-acquisition/1"

_PARQUET_META = "https://datasets-server.huggingface.co/parquet?dataset={ds}"
#: The hub's own refs listing: the authority for a dataset's commit shas.
_HF_REFS = "https://huggingface.co/api/datasets/{ds}/refs"
#: Human-facing dataset page recorded as the arm's upstream identity.
_HF_DATASET_URI = "https://huggingface.co/datasets/{ds}"
#: Newest commit that touched one repository path (not the branch head, which
#: moves for unrelated files while the corpus file does not).
_GH_COMMITS = "https://api.github.com/repos/{repo}/commits?path={path}&per_page=1"
#: Raw file content at an exact commit rather than at a moving branch name.
_GH_RAW = "https://raw.githubusercontent.com/{repo}/{rev}/{path}"
_GH_REPO_URI = "https://github.com/{repo}"
#: Both spellings of the datasets-server convert branch that shard URLs use.
_PARQUET_CONVERT_REFS = ("refs%2Fconvert%2Fparquet", "refs/convert/parquet")


def _http_json(url: str, headers: dict[str, str] | None = None) -> object:
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers or {}), timeout=120
    ) as resp:
        return json.load(resp)


def _http_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def _auth_header() -> dict[str, str]:
    """Bearer header from HF_TOKEN when present (needed for gated datasets)."""
    token = __import__("os").environ.get("HF_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _csv_row_count(payload: bytes) -> int:
    """Data rows (header excluded) in a released CSV, quoted newlines included."""
    reader = csv.reader(payload.decode("utf-8-sig").splitlines(True))
    return max(sum(1 for _ in reader) - 1, 0)


def _branch_commit(entries: object, name: str) -> str | None:
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("name") == name:
            commit = entry.get("targetCommit")
            return commit if isinstance(commit, str) and commit else None
    return None


def _hf_revisions(dataset: str, headers: dict[str, str] | None = None) -> dict:
    """Resolve a HF dataset's revisions from the hub's own refs listing.

    ``main`` is the released dataset commit a receipt pins the arm to; the
    ``refs/convert/parquet`` commit is what the parquet bridge actually reads,
    so both are resolved and recorded. A hub that cannot answer yields explicit
    nulls plus a reason - never a fabricated or placeholder sha.
    """
    url = _HF_REFS.format(ds=urllib.parse.quote(dataset, safe="/"))
    record: dict = {
        "revision": None,
        "revision_ref": "refs/heads/main",
        "revision_resolved_from": url,
        "revision_unavailable_reason": None,
        "parquet_revision": None,
        "parquet_revision_ref": "refs/convert/parquet",
    }
    try:
        payload = _http_json(url, headers)
    except (OSError, ValueError) as exc:  # provenance degrades, never aborts
        record["revision_unavailable_reason"] = (
            f"hub refs request failed: {type(exc).__name__}: {exc}"
        )
        return record
    if not isinstance(payload, dict):
        record["revision_unavailable_reason"] = "hub refs response is not an object"
        return record
    record["revision"] = _branch_commit(payload.get("branches"), "main")
    record["parquet_revision"] = _branch_commit(payload.get("converts"), "parquet")
    if record["revision"] is None:
        record["revision_unavailable_reason"] = (
            f"hub refs for {dataset} name no main-branch commit"
        )
    return record


def _github_file_revision(repo: str, path: str) -> dict:
    """Resolve the newest commit that touched one path, from the commits API."""
    url = _GH_COMMITS.format(repo=repo, path=urllib.parse.quote(path))
    record: dict = {
        "revision": None,
        "revision_ref": "refs/heads/main",
        "revision_resolved_from": url,
        "revision_unavailable_reason": None,
    }
    try:
        payload = _http_json(url, {"Accept": "application/vnd.github+json"})
    except (OSError, ValueError) as exc:  # provenance degrades, never aborts
        record["revision_unavailable_reason"] = (
            f"GitHub commits request failed: {type(exc).__name__}: {exc}"
        )
        return record
    head = payload[0] if isinstance(payload, list) and payload else None
    commit = head.get("sha") if isinstance(head, dict) else None
    if isinstance(commit, str) and commit:
        record["revision"] = commit
    else:
        record["revision_unavailable_reason"] = (
            f"GitHub commits API named no commit for {repo}:{path}"
        )
    return record


def _pin_parquet_url(url: str, revision: str) -> str:
    """Rewrite one shard URL from the moving convert branch to an exact commit."""
    for ref in _PARQUET_CONVERT_REFS:
        marker = f"/resolve/{ref}/"
        if marker in url:
            return url.replace(marker, f"/resolve/{revision}/")
    return url


def _urls_pinned(urls: list[str], revision: str | None) -> bool:
    return bool(revision) and bool(urls) and all(revision in url for url in urls)


def _retrieval(
    endpoint: str,
    urls: list[str],
    revision: str | None,
    revision_ref: str | None,
    unpinned_reason: str | None = None,
) -> dict:
    """The retrieval half of a sidecar: where the bytes came from, and whether
    they were requested at an exact revision or at a moving reference."""
    pinned = revision is not None
    return {
        "endpoint": endpoint,
        "urls": list(urls),
        "fetched_revision": revision,
        "fetched_revision_ref": revision_ref if pinned else None,
        "fetched_at_revision": pinned,
        "unpinned_reason": None if pinned else unpinned_reason,
    }


def _acquisition_path(target: Path) -> Path:
    return target.with_suffix(".acquisition.json")


def _write_acquisition(
    source: str,
    target: Path,
    out_root: Path,
    upstream: dict,
    revision: dict,
    retrieval: dict,
    rows: int | None,
) -> Path:
    """Write the sidecar recording exactly what was acquired, from where, at
    which upstream revision, and what landed on disk."""
    record = {
        "schema_version": ACQUISITION_SCHEMA,
        "source": source,
        "retrieved_at": _utc_now(),
        "upstream": upstream,
        "revision": revision["revision"],
        "revision_ref": revision["revision_ref"],
        "revision_resolved_from": revision["revision_resolved_from"],
        "revision_unavailable_reason": revision["revision_unavailable_reason"],
        "retrieval": retrieval,
        "export": {
            "path": target.relative_to(out_root).as_posix(),
            "sha256": _sha256_file(target),
            "bytes": target.stat().st_size,
            "rows": rows,
        },
    }
    sidecar = _acquisition_path(target)
    with sidecar.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
    return sidecar


def _parquet_records(
    dataset: str,
    config: str,
    split: str,
    columns: list[str] | None = None,
    *,
    revision: str | None = None,
) -> tuple[list[dict], list[str]]:
    """Read one HF dataset config/split fully via its parquet shards.

    ``revision`` pins every shard URL to that exact ``refs/convert/parquet``
    commit instead of the moving branch reference the index hands back, so the
    bytes read here provably belong to the recorded revision. Returns the rows
    and the shard URLs actually requested, which the sidecar records.
    """
    import io

    import pandas as pd  # local import: only needed for parquet sources

    hdr = _auth_header()
    meta = _http_json(_PARQUET_META.format(ds=dataset.replace("/", "%2F")), hdr)
    urls = [
        f["url"]
        for f in meta["parquet_files"]
        if f["config"] == config and f["split"] == split
    ]
    if not urls:
        raise SystemExit(f"no parquet shards for {dataset} {config}/{split}")
    if revision:
        urls = [_pin_parquet_url(url, revision) for url in urls]
    shards = []
    for url in urls:
        with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=300) as resp:
            shards.append(pd.read_parquet(io.BytesIO(resp.read())))
    frame = pd.concat(shards, ignore_index=True)
    if columns is not None:
        missing = [c for c in columns if c not in frame.columns]
        if missing:
            raise SystemExit(f"{dataset} missing expected columns {missing}")
        frame = frame[columns]

    def _norm(value):
        if hasattr(value, "item"):
            try:
                return value.item()
            except Exception:  # noqa: BLE001 - best-effort scalar coercion
                return value
        if isinstance(value, dict):
            return {k: _norm(v) for k, v in value.items()}
        return value

    rows = [{k: _norm(v) for k, v in row.items()} for row in frame.to_dict(orient="records")]
    return rows, urls


def _write_json(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return path


def _export_hf_parquet(
    source: str,
    dataset: str,
    config: str,
    split: str,
    columns: list[str] | None,
    out_root: Path,
    relative: str,
) -> Path:
    """Acquire one parquet-backed HF config/split at its resolved revision."""
    revision = _hf_revisions(dataset, _auth_header())
    rows, urls = _parquet_records(
        dataset, config, split, columns, revision=revision["parquet_revision"]
    )
    target = _write_json(out_root / relative, rows)
    if _urls_pinned(urls, revision["parquet_revision"]):
        pinned, reason = revision["parquet_revision"], None
    elif revision["parquet_revision"]:
        pinned, reason = None, (
            "the parquet index returned shard URLs carrying no "
            "refs/convert/parquet reference to substitute a commit into"
        )
    else:
        pinned, reason = None, (
            "the hub named no refs/convert/parquet commit for this dataset: "
            + (revision["revision_unavailable_reason"] or "no parquet conversion branch")
        )
    _write_acquisition(
        source, target, out_root,
        {
            "kind": "huggingface_dataset",
            "id": dataset,
            "config": config,
            "split": split,
            "uri": _HF_DATASET_URI.format(ds=dataset),
        },
        revision,
        _retrieval(
            _PARQUET_META.format(ds=dataset.replace("/", "%2F")),
            urls, pinned, revision["parquet_revision_ref"], reason,
        ),
        len(rows),
    )
    return target


def export_saladbench(out_root: Path) -> Path:
    return _export_hf_parquet(
        "saladbench", "OpenSafetyLab/Salad-Data", "base_set", "train",
        ["qid", "question", "source", "1-category", "2-category", "3-category"],
        out_root, "SALAD-Data/base_set.json",
    )


def export_airbench(out_root: Path) -> Path:
    return _export_hf_parquet(
        "airbench", "stanford-crfm/air-bench-2024", "default", "test",
        ["cate-idx", "l2-name", "l3-name", "l4-name", "prompt"],
        out_root, "AIR-Bench-2024/air_bench_default.json",
    )


def export_xstest(out_root: Path) -> Path:
    # The released prompt file lives in a git repo, so the exact commit that
    # last touched it is the revision - fetch AT that sha, never at 'main',
    # which moves and would leave the exported bytes unattributable.
    repo, path = "paul-rottger/xstest", "xstest_prompts.csv"
    revision = _github_file_revision(repo, path)
    url = _GH_RAW.format(repo=repo, rev=revision["revision"] or "main", path=path)
    raw = _http_bytes(url)
    target = out_root / "XSTest" / "xstest_prompts.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    _write_acquisition(
        "xstest", target, out_root,
        {
            "kind": "github_raw",
            "repo": repo,
            "path": path,
            "uri": _GH_REPO_URI.format(repo=repo),
        },
        revision,
        _retrieval(
            url, [url], revision["revision"], revision["revision_ref"],
            "the GitHub commits API named no commit for this path, so the file "
            "was fetched from the moving 'main' reference: "
            + (revision["revision_unavailable_reason"] or "reason unrecorded"),
        ),
        _csv_row_count(raw),
    )
    return target


def export_simplesafetytests(out_root: Path) -> Path:
    # Read through the parquet bridge rather than the datasets-server /rows
    # endpoint: /rows accepts a ?revision= parameter and ignores it (a bogus
    # forty-zero revision still answers HTTP 200), so a rows-backed retrieval
    # can never be pinned and the acquisition sidecar has to declare the fetch
    # unpinned. The parquet path resolves and fetches at an exact commit. The
    # switch was verified content-neutral against the live corpus: the parquet
    # shard at the pinned revision, projected onto the released column order,
    # equals the previously exported 100 rows exactly.
    return _export_hf_parquet(
        "simplesafetytests", "Bertievidgen/SimpleSafetyTests", "default", "test",
        ["id", "harm_area", "counter", "category", "prompt"],
        out_root, "SimpleSafetyTests/simplesafetytests.json",
    )


def export_decodingtrust(out_root: Path) -> Path:
    # Gated dataset: needs HF_TOKEN in the environment. Only the stereotype
    # perspective is converted; the toxicity/privacy perspectives are excluded.
    return _export_hf_parquet(
        "decodingtrust", "AI-Secure/DecodingTrust", "stereotype", "stereotype",
        None, out_root, "DecodingTrust/stereotype.json",
    )


def _resolve_hf_cli(executable: str | None = None) -> str:
    """Locate the ``hf`` CLI: next to the running interpreter first, then PATH.

    The distro installer runs this module as ``<venv>/bin/python -m ...`` without
    activating the venv, so a bare ``hf`` on PATH does not resolve on the rig;
    the console-script sibling of ``sys.executable`` is the authoritative copy.
    """
    interpreter = Path(executable or sys.executable)
    sibling = interpreter.parent / ("hf.exe" if os.name == "nt" else "hf")
    if sibling.is_file():
        return str(sibling)
    on_path = shutil.which("hf")
    if on_path:
        return on_path
    raise SystemExit(
        f"hf CLI not found: neither {sibling} (next to {interpreter}) nor 'hf' on PATH; "
        "install 'huggingface_hub[cli]' into this interpreter's environment "
        "(distro/install.sh deps does) and re-run"
    )


def export_holisafe(out_root: Path) -> Path:
    # Gated multimodal dataset shipped as a metadata JSON plus an images/ folder;
    # a full `hf download` (needs HF_TOKEN + accepted terms) is the right tool,
    # not the parquet bridge. Delegate to the hf CLI and return the metadata path.
    import subprocess

    dataset = "etri-vilab/holisafe-bench"
    revision = _hf_revisions(dataset, _auth_header())
    target = out_root / "HoliSafe"
    command = [
        _resolve_hf_cli(), "download", dataset, "--repo-type", "dataset",
        "--local-dir", str(target),
    ]
    if revision["revision"]:
        command += ["--revision", revision["revision"]]
    subprocess.run(command, check=True)
    meta = target / "holisafe_bench.json"
    if not meta.is_file():
        raise SystemExit(f"HoliSafe metadata not found at {meta}")
    records = json.loads(meta.read_text(encoding="utf-8"))
    _write_acquisition(
        "holisafe", meta, out_root,
        {
            "kind": "huggingface_dataset_repo",
            "id": dataset,
            "config": None,
            "split": None,
            "uri": _HF_DATASET_URI.format(ds=dataset),
        },
        revision,
        _retrieval(
            " ".join(command), [], revision["revision"], revision["revision_ref"],
            "the hub named no main-branch commit, so the CLI downloaded the "
            "moving branch head: "
            + (revision["revision_unavailable_reason"] or "reason unrecorded"),
        ),
        len(records) if isinstance(records, list) else None,
    )
    return meta


_EXPORTERS = {
    "saladbench": export_saladbench,
    "airbench": export_airbench,
    "xstest": export_xstest,
    "simplesafetytests": export_simplesafetytests,
    "decodingtrust": export_decodingtrust,
    "holisafe": export_holisafe,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", required=True, choices=[*_EXPORTERS, "all"],
        help="which aggregator corpus to prepare",
    )
    parser.add_argument(
        "--out-root", required=True, type=Path,
        help="corpora root (e.g. $URA_CORPORA); each source writes under its own subdir",
    )
    args = parser.parse_args(argv)
    out_root = args.out_root.expanduser()
    names = list(_EXPORTERS) if args.source == "all" else [args.source]
    for name in names:
        target = _EXPORTERS[name](out_root)
        size = target.stat().st_size
        print(f"{name}: wrote {target} ({size} bytes)")
        # Echo the recorded provenance so the acquisition log itself carries the
        # revision instead of only a ".done" marker.
        sidecar = _acquisition_path(target)
        if sidecar.is_file():
            record = json.loads(sidecar.read_text(encoding="utf-8"))
            upstream = record["upstream"]
            identity = upstream.get("id") or upstream.get("repo")
            revision = record["revision"] or (
                f"UNRESOLVED ({record['revision_unavailable_reason']})"
            )
            print(f"{name}: {identity} @ {revision} -> {sidecar}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
