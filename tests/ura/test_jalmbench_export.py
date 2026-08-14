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


def test_duplicate_id_and_identical_audio_do_not_collide(tmp_path: Path) -> None:
    # JALMBench repeats an id across attempt rows, and some rows carry
    # byte-identical audio, so an id+digest filename collides and the
    # exclusive-open write crashes mid-export. Every accepted row must get a
    # distinct audio file and a distinct manifest entry.
    source = tmp_path / "download" / "Audio_Originated_Jailbreak"
    source.mkdir(parents=True)
    row = {
        "id": "dup-1",
        "attempt_id": "0",
        "original_text": "harmful transcript",
        "source": "AdvWave",
        "audio": {"bytes": _WAV, "path": "dup-1.wav"},
    }
    second = dict(row, attempt_id="1")  # same id, same audio bytes
    pq.write_table(pa.Table.from_pylist([row, second]), source / "AdvWave.parquet")

    out = tmp_path / "prepared"
    summary = export_release(tmp_path / "download", out)

    assert summary["records"] == 2
    lines = (out / "jalmbench.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    exported = [json.loads(line) for line in lines]
    paths = {entry["audio_path"] for entry in exported}
    assert len(paths) == 2  # distinct files despite identical id+audio
    for entry in exported:
        assert (out / entry["audio_path"]).is_file()
    # Same audio bytes => same content digest, which is expected and fine.
    assert exported[0]["audio_sha256"] == exported[1]["audio_sha256"]


def test_released_decoded_array_is_encoded_to_wav(tmp_path: Path) -> None:
    # The pinned release materializes the HF Audio feature in decoded form
    # ({array, sampling_rate, path}) with no encoded bytes; the export must
    # re-encode the exact samples to a validator-recognized WAV container
    # rather than silently skipping every audio-bearing row.
    source = tmp_path / "download" / "Audio_Originated_Jailbreak"
    source.mkdir(parents=True)
    samples = [0.0, 0.5, -0.5, 1.0, -1.0, 0.25]
    pq.write_table(
        pa.Table.from_pylist([
            {
                "id": "arr-1",
                "original_text": "harmful transcript",
                "source": "AdvWave",
                "audio": {
                    "array": samples,
                    "sampling_rate": 16000,
                    "path": "arr-1.wav",
                },
            },
        ]),
        source / "AdvWave.parquet",
    )

    out = tmp_path / "prepared"
    summary = export_release(tmp_path / "download", out)

    assert summary["records"] == 1
    assert summary["skipped_text_only_rows"] == 0
    exported = json.loads((out / "jalmbench.jsonl").read_text(encoding="utf-8"))
    assert exported["audio_mime"] in {"audio/wav", "audio/x-wav"}
    assert exported["audio_encoding"] == "pcm16_wav_from_released_array"
    audio_bytes = (out / exported["audio_path"]).read_bytes()
    assert audio_bytes[:4] == b"RIFF" and audio_bytes[8:12] == b"WAVE"
    # 6 mono PCM16 frames = 12 sample bytes in the data chunk.
    assert len(audio_bytes) == 44 + len(samples) * 2

    points = JALMBenchConverter().parse(out / "jalmbench.jsonl")
    assert len(points) == 1
    assert points[0].modalities == ["text", "audio"]
