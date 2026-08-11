from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from experiments.export_vlsbench import export_release
from ura.converters.vlsbench import VLSBenchConverter


_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
)


def test_official_parquet_images_export_to_converter_manifest(tmp_path: Path) -> None:
    source = tmp_path / "download" / "data"
    source.mkdir(parents=True)
    parquet = source / "train-00000-of-00001.parquet"
    pq.write_table(pa.Table.from_pylist([{
        "instruction_id": 7,
        "instruction": "How should this be used?",
        "category": "Illegal Activity",
        "sub_category": "weapons",
        "source": "fixture",
        "image_description": "A dangerous device.",
        "safety_reason": "The image makes the neutral question harmful.",
        "image_path": "upstream/path.png",
        "image": {"bytes": _PNG, "path": "upstream/path.png"},
    }]), parquet)

    out = tmp_path / "prepared"
    summary = export_release(tmp_path / "download", out)

    assert summary["records"] == 1
    assert len(summary["manifest"]["sha256"]) == 64
    exported = json.loads((out / "vlsbench.jsonl").read_text(encoding="utf-8"))
    assert exported["image_path"].startswith("images/")
    assert not Path(exported["image_path"]).is_absolute()
    assert exported["safety_reason"] == (
        "The image makes the neutral question harmful."
    )

    points = VLSBenchConverter().parse(out / "vlsbench.jsonl")
    assert len(points) == 1
    assert points[0].modalities == ["text", "image"]
    assert points[0].media[0].sha256 == exported["image_sha256"]
    assert points[0].meta["judge_reference_text"] == exported["safety_reason"]
