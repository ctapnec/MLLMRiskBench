from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from experiments.export_jalmbench import export_release
from ura.converters.jalmbench import JALMBenchConverter


_WAV = b"RIFF\x04\x00\x00\x00WAVE"


def test_official_parquet_audio_exports_to_converter_manifest(tmp_path: Path) -> None:
    source = tmp_path / "download" / "HarmfulQuery"
    source.mkdir(parents=True)
    parquet = source / "AHarm.parquet"
    pq.write_table(
        pa.Table.from_pylist([
            {
                "id": "adv-1",
                "text": "harmful transcript",
                "original_text": "harmful transcript",
                "source": "AdvBench",
                "audio": {"bytes": _WAV, "path": "adv-1.wav"},
            },
            {
                "id": "text-only",
                "text": "not an audio row",
                "original_text": "not an audio row",
                "source": "AdvBench",
                "audio": None,
            },
        ]),
        parquet,
    )

    out = tmp_path / "prepared"
    summary = export_release(tmp_path / "download", out)

    assert summary["records"] == 1
    assert summary["skipped_text_only_rows"] == 1
    assert len(summary["manifest"]["sha256"]) == 64
    exported = json.loads((out / "jalmbench.jsonl").read_text(encoding="utf-8"))
    assert exported["audio_sha256"]
    assert not Path(exported["audio_path"]).is_absolute()

    points = JALMBenchConverter().parse(out / "jalmbench.jsonl")
    assert len(points) == 1
    assert points[0].modalities == ["text", "audio"]
    assert points[0].media[0].sha256 == exported["audio_sha256"]
    assert points[0].meta["transcript_sent_to_target"] is False
