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
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

_PARQUET_META = "https://datasets-server.huggingface.co/parquet?dataset={ds}"
_ROWS = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset={ds}&config={cfg}&split={split}&offset={off}&length=100"
)


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


def _parquet_records(
    dataset: str, config: str, split: str, columns: list[str] | None = None
) -> list[dict]:
    """Read one HF dataset config/split fully via its parquet shards."""
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

    return [{k: _norm(v) for k, v in row.items()} for row in frame.to_dict(orient="records")]


def _rows_records(dataset: str, config: str, split: str) -> list[dict]:
    """Read a small HF dataset fully via the rows API (no parquet dependency)."""
    out: list[dict] = []
    offset = 0
    while True:
        page = _http_json(
            _ROWS.format(ds=dataset.replace("/", "%2F"), cfg=config, split=split, off=offset)
        )
        batch = [r["row"] for r in page.get("rows", [])]
        out.extend(batch)
        if len(batch) < 100:
            break
        offset += 100
    if not out:
        raise SystemExit(f"no rows returned for {dataset} {config}/{split}")
    return out


def _write_json(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return path


def export_saladbench(out_root: Path) -> Path:
    rows = _parquet_records(
        "OpenSafetyLab/Salad-Data", "base_set", "train",
        ["qid", "question", "source", "1-category", "2-category", "3-category"],
    )
    return _write_json(out_root / "SALAD-Data" / "base_set.json", rows)


def export_airbench(out_root: Path) -> Path:
    rows = _parquet_records(
        "stanford-crfm/air-bench-2024", "default", "test",
        ["cate-idx", "l2-name", "l3-name", "l4-name", "prompt"],
    )
    return _write_json(out_root / "AIR-Bench-2024" / "air_bench_default.json", rows)


def export_xstest(out_root: Path) -> Path:
    raw = _http_bytes(
        "https://raw.githubusercontent.com/paul-rottger/xstest/main/xstest_prompts.csv"
    )
    target = out_root / "XSTest" / "xstest_prompts.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return target


def export_simplesafetytests(out_root: Path) -> Path:
    rows = _rows_records("Bertievidgen/SimpleSafetyTests", "default", "test")
    return _write_json(out_root / "SimpleSafetyTests" / "simplesafetytests.json", rows)


def export_decodingtrust(out_root: Path) -> Path:
    # Gated dataset: needs HF_TOKEN in the environment. Only the stereotype
    # perspective is converted; the toxicity/privacy perspectives are excluded.
    rows = _parquet_records("AI-Secure/DecodingTrust", "stereotype", "stereotype")
    return _write_json(out_root / "DecodingTrust" / "stereotype.json", rows)


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

    target = out_root / "HoliSafe"
    subprocess.run(
        [_resolve_hf_cli(), "download", "etri-vilab/holisafe-bench", "--repo-type", "dataset",
         "--local-dir", str(target)],
        check=True,
    )
    meta = target / "holisafe_bench.json"
    if not meta.is_file():
        raise SystemExit(f"HoliSafe metadata not found at {meta}")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
