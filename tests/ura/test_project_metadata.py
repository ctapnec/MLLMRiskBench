from __future__ import annotations

import tomllib
from pathlib import Path


def test_harmbench_extra_pins_proven_prepare_dependencies() -> None:
    project_root = Path(__file__).resolve().parents[2]
    document = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["harmbench"]

    assert dependencies == [
        "accelerate==1.14.0",
        "confection==0.1.4",
        "datasketch==1.8.0",
        "fschat==0.2.36",
        "msgpack==1.2.1",
        "ray==2.56.0",
        "spacy==3.8.11",
        (
            "en-core-web-sm @ https://github.com/explosion/spacy-models/releases/download/"
            "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
            "#sha256=1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85"
        ),
    ]
