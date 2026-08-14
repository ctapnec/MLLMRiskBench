"""The vLLM local-target roster (CLI and console share one source).

The roster is the set of vLLM-supported models offered as free on-rig targets.
It is a checked-in curated default that the operator refreshes from vLLM's own
supported-models documentation for the exact vLLM version installed on the rig,
so the roster never drifts from what the rig's vLLM can actually serve.
Selecting a roster model runs it through ``--local`` and vLLM downloads the
weights automatically on first use.

This performs no provider call or scientific validation. ``--refresh`` makes
read-only HTTPS requests to the public vLLM documentation at the installed
version's tag; every other action is offline. Discovered revisions are left as
``OPERATOR_TODO`` - the operator pins each one before a measured run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Doc paths tried within a vLLM ref (tag or branch); vLLM has moved the file.
_VLLM_DOC_PATHS = (
    "docs/source/models/supported_models.md",
    "docs/models/supported_models.md",
    "docs/source/models/generative_models.md",
)

#: Vision/audio hints to infer modalities from a repo id.
_IMAGE_HINTS = (
    "vl", "llava", "vision", "vlm", "internvl", "pixtral", "idefics",
    "paligemma", "-vl-", "qwen2-vl", "qwen2.5-vl", "qwen3-vl", "phi-3.5-vision",
    "llama-3.2-11b-vision", "llama-3.2-90b-vision", "gemma-3",
)
_AUDIO_HINTS = ("audio", "ultravox", "qwen2-audio")

_ROSTER_LOCAL = "experiments/vllm-roster.json"
_ROSTER_EXAMPLE = "experiments/rig/vllm-roster.example.json"


def infer_modalities(spec: str) -> list[str]:
    # Match against the repo id only; the "vllm:" prefix itself contains "vl".
    lower = spec.lower()
    if lower.startswith("vllm:"):
        lower = lower[len("vllm:"):]
    mods = ["text"]
    if any(hint in lower for hint in _IMAGE_HINTS):
        mods.append("image")
    if any(hint in lower for hint in _AUDIO_HINTS):
        mods.append("audio")
    return mods


def installed_vllm_version() -> str | None:
    """The vLLM version to sync against: env override, then the import."""

    env = os.environ.get("VLLM_VERSION", "").strip().lstrip("v")
    if env:
        return env
    try:
        import vllm  # noqa: PLC0415 - optional heavy dependency, probed lazily

        return str(getattr(vllm, "__version__", "")).strip() or None
    except Exception:  # noqa: BLE001 - vllm is optional and may be absent
        return None


def load_roster(repo_root: Path = _REPO_ROOT) -> dict[str, object]:
    """The full roster document (with metadata), local override then example."""

    for candidate in (_ROSTER_LOCAL, _ROSTER_EXAMPLE):
        path = repo_root / candidate
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _models_map(document: dict[str, object]) -> dict[str, object]:
    models = document.get("models")
    if isinstance(models, dict):
        return models
    # Back-compat: a flat {spec: config} document is its own model map.
    return {k: v for k, v in document.items() if isinstance(v, dict)}


def roster_version(repo_root: Path = _REPO_ROOT) -> str | None:
    version = load_roster(repo_root).get("vllm_version")
    return str(version) if isinstance(version, str) and version else None


def roster_models(repo_root: Path = _REPO_ROOT) -> list[dict[str, object]]:
    """``[{"spec", "modalities"}]`` for every vLLM roster entry."""

    out: list[dict[str, object]] = []
    for spec, entry in _models_map(load_roster(repo_root)).items():
        mods = ["text"]
        if isinstance(entry, dict) and isinstance(entry.get("modalities"), list):
            mods = [str(m) for m in entry["modalities"] if isinstance(m, str)] or ["text"]
        out.append({"spec": str(spec), "modalities": mods})
    return out


def _fetch(url: str, *, timeout: int = 20, max_bytes: int = 8_000_000) -> str:
    import urllib.request  # noqa: PLC0415 - stdlib, imported only on refresh

    request = urllib.request.Request(url, headers={"User-Agent": "ura-rig"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https vLLM doc URLs
        return response.read(max_bytes).decode("utf-8", errors="replace")


def parse_vllm_doc(markdown: str) -> list[str]:
    """Extract ``org/model`` HF identities from the vLLM supported-models doc.

    Only backtick code spans of exactly ``org/model`` shape count; a couple of
    non-model path prefixes seen in the doc (docs/, examples/, http URLs) are
    excluded so the roster stays model identities.
    """

    ids = set()
    excluded = ("docs", "examples", "http", "https", "tests", "vllm")
    for match in re.findall(r"`([A-Za-z0-9][\w.-]+/[\w.-]+)`", markdown):
        if match.count("/") != 1:
            continue
        if match.split("/", 1)[0].lower() in excluded:
            continue
        ids.add(match)
    return sorted(ids)


def _candidate_urls(version: str | None) -> list[str]:
    refs = []
    if version:
        refs.append("v" + version)
    refs.append("main")
    return [
        f"https://raw.githubusercontent.com/vllm-project/vllm/{ref}/{path}"
        for ref in refs for path in _VLLM_DOC_PATHS
    ]


def refresh_roster(
    repo_root: Path = _REPO_ROOT, *, version: str | None = None,
) -> dict[str, object]:
    """Fetch the version-matched vLLM doc and write the local roster.

    Resolves the vLLM version (argument, else the rig's installed version),
    fetches that tag's supported-models doc, merges the discovered identities
    with the existing roster (keeping operator-pinned revisions), and writes
    ``experiments/vllm-roster.json`` stamped with the version it synced to.
    Raises on total fetch failure.
    """

    resolved = (version or installed_vllm_version() or "").strip().lstrip("v") or None
    markdown = ""
    used_url = ""
    errors = []
    for url in _candidate_urls(resolved):
        try:
            markdown = _fetch(url)
            used_url = url
            break
        except Exception as exc:  # noqa: BLE001 - report any transport failure
            errors.append(f"{url}: {exc}")
    if not markdown:
        raise RuntimeError("could not fetch vLLM supported-models doc: "
                           + "; ".join(errors))
    existing = _models_map(load_roster(repo_root))
    models: dict[str, object] = dict(existing)
    for repo_id in parse_vllm_doc(markdown):
        spec = f"vllm:{repo_id}"
        if spec in models:
            continue
        models[spec] = {
            "revision": "OPERATOR_TODO",
            "modalities": infer_modalities(spec),
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.85,
            "max_tokens": 4096,
        }
    document = {
        "vllm_version": resolved,
        "source_url": used_url,
        "models": dict(sorted(models.items())),
    }
    (repo_root / _ROSTER_LOCAL).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "The vLLM local-target roster shared by the CLI and rig console. "
            "Lists the roster, or refreshes it from vLLM's supported-models "
            "documentation for the installed vLLM version (read-only HTTPS)"
        )
    )
    parser.add_argument(
        "--refresh", action="store_true",
        help="fetch the version-matched vLLM doc and update the local roster",
    )
    parser.add_argument(
        "--vllm-version", default=None,
        help="override the vLLM version to sync against (default: the rig's "
             "installed vllm or $VLLM_VERSION)",
    )
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root) if args.repo_root else _REPO_ROOT
    if args.refresh:
        try:
            document = refresh_roster(repo_root, version=args.vllm_version)
        except Exception as exc:  # noqa: BLE001 - surface the transport error
            print(f"refresh failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "refreshed": True,
            "vllm_version": document.get("vllm_version"),
            "models": len(_models_map(document)),
            "source_url": document.get("source_url"),
        }))
        return 0
    print(json.dumps({
        "vllm_version": roster_version(repo_root),
        "models": roster_models(repo_root),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
