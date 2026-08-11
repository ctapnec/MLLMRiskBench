"""Turnkey experiment driver for URA-Bench (thesis Chapter V).

Runs the model x attacker x judge matrix over one or more corpora, aggregates the
metrics, and writes per-cell JSONL plus a completed-grid directory consumed by
``python -m experiments.figures`` through its explicit model/defense roots and
corpus facets.
Each cell also writes joinable Attempt/Response artifacts and an append-only
checkpoint. A matching completion marker makes reruns call-free; an interrupted
cell restores completed responses locally, including state needed by native
multi-turn attackers.

This is designed to run on the project rig with provider API keys in the
environment. Construction failures are reported before a cell begins; lazy SDK,
credential, model, and runtime failures produce a per-cell ``*.error.json`` plus
any partial checkpoint rather than silently shrinking the requested matrix. A
`--dry-run` uses the offline MockTarget so the whole flow is verifiable with no
keys and no GPU.

Examples
--------
# offline smoke of the whole matrix (no keys, no GPU):
python experiments/run_matrix.py --dry-run --limit 12 --out runs/dry

# cross-provider run: use the frozen Fable and Responses conditions (Pro is a
# mode, not a model slug):
# POSIX shell environment syntax is shown here. In PowerShell use
# ``$env:ANTHROPIC_API_KEY='...'`` and ``$env:OPENAI_API_KEY='...'``; see README.
export ANTHROPIC_API_KEY=...  OPENAI_API_KEY=...  GOOGLE_API_KEY=...
python experiments/run_matrix.py \
    --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=current_turn" \
    --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:google/gemma-3-27b-it,ollama:llama3.3:70b \
    --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
    --corpora synth --limit 200 --seeds 0,1 --out runs/full

Hosted comparison ids should be provider-qualified. The Fable case is the public
``claude-fable-5`` model with explicit high effort, adaptive thinking, a 25,000
token output ceiling, and no temperature parameter; live account access still
must pass preflight. The OpenAI case is the exact public ``gpt-5.6-sol`` model via
the Responses API with Pro mode, medium effort, and current-turn reasoning
context frozen in the target specification; no Sol-Pro slug is inferred. Such a
comparison is cross-provider and is not a causal same-base-model defense ablation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

# make `import ura` work when run as a script from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.adapters.base import AttackBudget           # noqa: E402
from ura.adapters.engines import get_attacker         # noqa: E402
from ura.converters import get_converter, synth_corpus  # noqa: E402
from ura.data_models import (                         # noqa: E402
    SCHEMA_VERSION,
    Attempt,
    DataPoint,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
)
from ura.judges.base import JudgeCascade              # noqa: E402
from ura.judges.llm import LLMJudge                   # noqa: E402
from ura.judges.rules import RuleJudge                # noqa: E402
from ura.runner import (                              # noqa: E402
    CODE_VERSION,
    Runner,
    realized_identity_summary,
)
from ura.targets.api import build_api_target              # noqa: E402


_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def _safe_component(value: str, *, max_base: int = 48) -> str:
    """Return a bounded filesystem component with collision-resistant identity."""
    raw = str(value)
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", raw)
    cleaned = re.sub(r"\s+", "_", cleaned).strip(" ._") or "unnamed"
    if cleaned.lower() in _WINDOWS_RESERVED:
        cleaned = f"item-{cleaned}"
    cleaned = cleaned[:max_base].rstrip(" ._") or "unnamed"
    suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{cleaned}--{suffix}"


def _runtime_env() -> dict:
    """Capture reproducibility-relevant versions without importing backends."""
    packages = {}
    for package in (
        "pydantic", "numpy", "pandas", "torch", "transformers", "vllm",
        "anthropic", "openai", "google-genai", "google-generativeai", "ollama",
    ):
        try:
            packages[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": packages,
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(
            payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False
        ) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: object) -> str:
    material = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _record_count(path: Path) -> int:
    if path.name.endswith(".manifest.json"):
        return 1
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _artifact_descriptor(path: Path) -> dict[str, object]:
    return {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
        "records": _record_count(path),
}


def _json_loads_strict(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden")

    return json.loads(text, parse_constant=reject_constant)


_SECRET_CONFIG_KEY = re.compile(
    r"(?:api[_-]?key|token|secret|password|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)


def _load_attacker_config(
    path_value: str, selected_attackers: list[str]
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load constructor kwargs without admitting literal secrets.

    External tools receive credentials only through their explicit
    ``credential_env`` allowlist. Persisting a literal key in this JSON would
    leak it into grid and run manifests, so secret-like keys are rejected at any
    nesting level.
    """

    if not path_value:
        return {}, None
    path = Path(path_value).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("--attacker-config must be a regular non-symlink JSON file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("--attacker-config exceeds the 1 MiB limit")
    try:
        value = _json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid --attacker-config JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("--attacker-config must be an object keyed by attacker name")
    normalized: dict[str, dict[str, object]] = {}
    for raw_name, raw_config in value.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("attacker config keys must be non-blank strings")
        name = raw_name.strip().lower()
        if name in normalized:
            raise ValueError(f"duplicate normalized attacker config key {name!r}")
        if not isinstance(raw_config, dict):
            raise ValueError(f"attacker config {name!r} must be an object")

        def reject_secrets(node: object, trail: tuple[str, ...] = ()) -> None:
            if isinstance(node, dict):
                for key, child in node.items():
                    if not isinstance(key, str):
                        raise ValueError(
                            f"attacker config {name!r} contains a non-string key"
                        )
                    if key != "credential_env" and _SECRET_CONFIG_KEY.search(key):
                        location = ".".join((*trail, key))
                        raise ValueError(
                            f"literal secret-like attacker config field {location!r} "
                            "is forbidden; use credential_env names"
                        )
                    reject_secrets(child, (*trail, key))
            elif isinstance(node, list):
                for index, child in enumerate(node):
                    reject_secrets(child, (*trail, str(index)))

        reject_secrets(raw_config)
        normalized[name] = dict(raw_config)
    selected = {name.lower() for name in selected_attackers}
    unused = sorted(set(normalized) - selected)
    if unused:
        raise ValueError(
            "--attacker-config contains unselected attackers: " + ", ".join(unused)
        )
    return normalized, {
        "path": str(path),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _load_local_config(
    path_value: str, selected_specs: list[str]
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load exact immutable identities and declared modalities for local targets."""
    if not selected_specs:
        if path_value:
            raise ValueError("--local-config was supplied but --local selected no targets")
        return {}, None
    if not path_value:
        raise ValueError(
            "measured --local targets require --local-config with immutable identity "
            "and modalities"
        )
    path = Path(path_value).resolve(strict=True)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("--local-config must be a regular <=1 MiB JSON file")
    value = _json_loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != set(selected_specs):
        raise ValueError(
            "--local-config keys must exactly match the selected --local specs"
        )
    normalized: dict[str, dict[str, object]] = {}
    for spec in selected_specs:
        config = value[spec]
        if not isinstance(config, dict) or set(config) - {
            "revision", "digest", "modalities",
        }:
            raise ValueError(
                f"local config {spec!r} may contain only revision/digest/modalities"
            )
        modalities = config.get("modalities")
        if (
            not isinstance(modalities, list)
            or not modalities
            or any(item not in {"text", "image"} for item in modalities)
            or "text" not in modalities
            or len(set(modalities)) != len(modalities)
        ):
            raise ValueError(
                f"local config {spec!r} requires unique declared text[/image] modalities"
            )
        backend = spec.split(":", 1)[0].lower()
        revision = config.get("revision")
        digest = config.get("digest")
        if backend == "vllm":
            if bool(revision) == bool(digest):
                raise ValueError(
                    f"vLLM config {spec!r} requires exactly one revision or digest"
                )
        elif backend == "ollama":
            if revision is not None or not isinstance(digest, str):
                raise ValueError(
                    f"Ollama config {spec!r} requires digest and forbids revision"
                )
            if modalities != ["text"]:
                raise ValueError("OllamaTarget currently declares text capability only")
        else:
            raise ValueError(f"unsupported local backend in {spec!r}")
        normalized[spec] = dict(config)
    return normalized, {
        "path": str(path),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = _json_loads_strict(line)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSONL row in {path}:{line_number}")
            rows.append(value)
    return rows


def _validate_completion_marker(
    paths: dict[str, Path], planned: RunManifest, required: tuple[str, ...]
) -> dict:
    """Validate a completed cell before allowing a call-free skip."""
    marker = _json_loads_strict(paths["complete"].read_text(encoding="utf-8"))
    if not isinstance(marker, dict) or marker.get("status") != "complete":
        raise ValueError("completion marker does not declare status=complete")
    if marker.get("format_version") != 2:
        raise ValueError(
            "completion marker lacks v2 integrity metadata; manual audit required"
        )
    if marker.get("run_id") != planned.run_id:
        raise ValueError("completion marker run_id differs from planned cell")
    if marker.get("code_version") != planned.code_version:
        raise ValueError("completion marker code_version differs from planned cell")
    if marker.get("schema_version") != planned.schema_version:
        raise ValueError("completion marker schema_version differs from planned cell")
    artifacts = marker.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(required):
        raise ValueError("completion marker has an incomplete artifact inventory")
    for name in required:
        descriptor = artifacts.get(name)
        if not isinstance(descriptor, dict):
            raise ValueError(f"completion artifact {name!r} lacks an integrity descriptor")
        path = paths[name]
        if descriptor.get("file") != path.name or not path.is_file():
            raise ValueError(f"completion artifact {name!r} is missing or renamed")
        if descriptor.get("bytes") != path.stat().st_size:
            raise ValueError(f"completion artifact {name!r} byte count mismatch")
        if descriptor.get("sha256") != _sha256_file(path):
            raise ValueError(f"completion artifact {name!r} digest mismatch")
        if descriptor.get("records") != _record_count(path):
            raise ValueError(f"completion artifact {name!r} record count mismatch")

    manifest = RunManifest.model_validate_json(
        paths["manifest"].read_text(encoding="utf-8")
    )
    if manifest.run_id != planned.run_id:
        raise ValueError("stored manifest run_id differs from planned cell")
    if manifest.code_version != CODE_VERSION or manifest.schema_version != SCHEMA_VERSION:
        raise ValueError("stored manifest code/schema version is stale")

    attempt_rows = _read_jsonl(paths["attempts"])
    response_rows = _read_jsonl(paths["responses"])
    judgment_rows = _read_jsonl(paths["judgments"])
    trails = _read_jsonl(paths["trails"])
    result_rows = _read_jsonl(paths["results"])
    attempts = [Attempt.model_validate(row) for row in attempt_rows]
    responses = [Response.model_validate(row) for row in response_rows]
    judgments = [Judgment.model_validate(row) for row in judgment_rows]
    results = [EvalResult.model_validate(row) for row in result_rows]
    expected_counts = {
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
        "n_results": len(results),
    }
    for field, count in expected_counts.items():
        if marker.get(field) != count:
            raise ValueError(f"completion marker {field} mismatch")
        if field != "n_results" and manifest.config.get(field) != count:
            raise ValueError(f"stored manifest {field} mismatch")
    if not attempts or not responses or not judgments or not results:
        raise ValueError("completed scored cell has an empty core/result artifact")
    attempt_ids = [row.id for row in attempts]
    response_ids = [row.attempt_id for row in responses]
    judgment_ids = [row.attempt_id for row in judgments]
    if len(set(attempt_ids)) != len(attempt_ids):
        raise ValueError("duplicate attempt id in completed artifact")
    if (
        Counter(attempt_ids) != Counter(response_ids)
        or Counter(attempt_ids) != Counter(judgment_ids)
    ):
        raise ValueError("Attempt/Response/Judgment identities do not join exactly")
    if {str(row.get("attempt_id")) for row in trails} != set(attempt_ids):
        raise ValueError("judge trails do not cover every completed attempt")
    for name, rows in (
        ("attempts", attempts), ("responses", responses),
        ("judgments", judgments), ("results", results),
    ):
        if any(row.run_id != planned.run_id for row in rows):
            raise ValueError(f"mixed or missing run_id in completed {name}")
    if any(row.get("run_id") != planned.run_id for row in trails):
        raise ValueError("mixed or missing run_id in completed trails")

    immutable_manifest_fields = (
        "code_version", "schema_version", "seeds", "models", "adapters",
        "judges", "dataset_hashes", "env",
    )
    for field in immutable_manifest_fields:
        if getattr(manifest, field) != getattr(planned, field):
            raise ValueError(f"stored manifest immutable field {field!r} changed")
    for key in (
        "budget", "components", "run", "media_validation", "n_datapoints",
        "n_media_hashes", "harness_source",
    ):
        if manifest.config.get(key) != planned.config.get(key):
            raise ValueError(f"stored manifest config field {key!r} changed")
    if manifest.config.get("realized_attempts_sha256") != _sha256_json(
        [row.model_dump(mode="json") for row in attempts]
    ):
        raise ValueError("stored manifest realized_attempts_sha256 mismatch")
    realized_media: dict[str, str] = {}
    for attempt in attempts:
        if attempt.target not in planned.models:
            raise ValueError("completed Attempt names an unexpected target")
        media = attempt.params.get("attempt_media_hashes")
        if not isinstance(media, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in media.items()
        ):
            raise ValueError("completed Attempt has invalid realized media hashes")
        for key, value in media.items():
            if key in realized_media and realized_media[key] != value:
                raise ValueError("completed Attempts have conflicting media hashes")
            realized_media[key] = value
    if manifest.config.get("attempt_media_hashes") != dict(sorted(realized_media.items())):
        raise ValueError("stored manifest realized media digest inventory mismatch")
    if manifest.config.get("n_attempt_media_hashes") != len(realized_media):
        raise ValueError("stored manifest realized media digest count mismatch")
    for response in responses:
        if response.target not in planned.models:
            raise ValueError("completed Response names an unexpected target")
        if response.raw.get("run_id") != planned.run_id:
            raise ValueError("completed Response raw lineage lacks the run_id")
        if not isinstance(response.raw.get("target_sampling_control"), str):
            raise ValueError("completed Response lacks sampling-control provenance")
    for judgment in judgments:
        if judgment.raw.get("run_id") != planned.run_id:
            raise ValueError("completed Judgment raw lineage lacks the run_id")
        if judgment.raw.get("target") not in planned.models:
            raise ValueError("completed Judgment names an unexpected target")

    trails_by_attempt: dict[str, list[dict]] = defaultdict(list)
    for row in trails:
        trails_by_attempt[str(row["attempt_id"])].append(row)
    if set(trails_by_attempt) != set(attempt_ids):
        raise ValueError("judge trails do not cover exactly the completed attempts")
    for attempt_id, rows in trails_by_attempt.items():
        ordered = sorted(rows, key=lambda row: row.get("stage", -1))
        if len(ordered) != len(planned.judges):
            raise ValueError(f"judge trail stage count mismatch for {attempt_id}")
        if [row.get("stage") for row in ordered] != list(range(len(ordered))):
            raise ValueError(f"judge trail stage ordering mismatch for {attempt_id}")
        if [row.get("judge") for row in ordered] != planned.judges:
            raise ValueError(f"judge trail identities mismatch for {attempt_id}")
        if sum(row.get("cascade_role") == "authoritative" for row in ordered) != 1:
            raise ValueError(f"judge trail authority count mismatch for {attempt_id}")
        for row in ordered:
            if row.get("cascade_policy") != "first_confident_with_full_shadow_trail":
                raise ValueError(f"judge trail policy mismatch for {attempt_id}")
            if not isinstance(row.get("cascade_confident"), bool):
                raise ValueError(f"judge trail confidence state mismatch for {attempt_id}")
            confidence = row.get("confidence")
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0.0 <= float(confidence) <= 1.0
            ):
                raise ValueError(f"judge trail numeric confidence mismatch for {attempt_id}")
    identity_summary = realized_identity_summary(
        responses,
        trails,
        expected_judges=planned.judges,
    )
    identity_digest = _sha256_json(identity_summary)
    if manifest.config.get("realized_identities") != identity_summary:
        raise ValueError("stored manifest realized identity inventory mismatch")
    if manifest.config.get("realized_identities_sha256") != identity_digest:
        raise ValueError("stored manifest realized identity digest mismatch")
    if marker.get("realized_identities_sha256") != identity_digest:
        raise ValueError("completion marker realized identity digest mismatch")
    expected_identity_counts = {
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(planned.judges),
    }
    for field, expected_count in expected_identity_counts.items():
        if manifest.config.get(field) != expected_count:
            raise ValueError(f"stored manifest {field} mismatch")
    for result in results:
        if result.n <= 0:
            raise ValueError("completed aggregate has a non-positive population")
        if not 0.0 <= result.value <= 1.0 and result.metric != "median_turns_to_break":
            raise ValueError("completed aggregate value is outside its metric domain")
        if (result.ci_low is None) != (result.ci_high is None):
            raise ValueError("completed aggregate has a half-defined confidence interval")
        if result.ci_low is not None and result.ci_low > result.ci_high:
            raise ValueError("completed aggregate confidence interval is inverted")
    return marker


def _source_tree_digest(path: Path) -> tuple[str | None, int]:
    """Hash the complete released source tree, including relative filenames."""
    if not path.exists():
        return None, 0
    if path.is_file():
        return _sha256_file(path), 1
    digest = hashlib.sha256()
    count = 0
    for file_path in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        relative = file_path.relative_to(path).as_posix()
        file_digest = _sha256_file(file_path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(file_path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def build_target(
    spec: str,
    *,
    quantization: str = "",
    dtype: str = "auto",
    local_identity: dict[str, object] | None = None,
):
    """Resolve a target spec to a :class:`BaseTarget`.

    spec is one of:
      * a registered hosted id (including "mock") or the preferred
        "<provider>:<exact-account-visible-id>" form;
      * a local "<backend>:<model>" - "vllm:Qwen/Qwen3-VL-8B-Instruct",
        "ollama:llama3.3:70b".

    ``quantization``/``dtype`` are forwarded to the vLLM engine so a 27B-class
    model fits the 2x RTX 4090 rig (e.g. ``--quantization awq``); a pre-quantized
    (AWQ/GPTQ) checkpoint is auto-detected and needs no flag. Vision-language
    Local capabilities and immutable identities come only from ``local_identity``;
    model-name substrings are never treated as capability evidence.
    """
    if ":" in spec:
        backend, model = spec.split(":", 1)
        backend = backend.lower().strip()
        model = model.strip()
        if not backend or not model:
            raise ValueError(
                "provider/backend-qualified targets require non-empty "
                "'<provider>:<exact-id>' components"
            )
        if backend in {"vllm", "ollama"}:
            if local_identity is None:
                raise ValueError(
                    f"local target {spec!r} requires an explicit local identity config"
                )
            modalities = tuple(local_identity["modalities"])
            if backend == "vllm":
                from ura.targets.local import VLLMTarget
                kwargs: dict = {
                    "dtype": dtype,
                    "modality_support": modalities,
                    "revision": local_identity.get("revision"),
                    "model_digest": local_identity.get("digest"),
                }
                if quantization:
                    kwargs["quantization"] = quantization
                target = VLLMTarget(model=model, **kwargs)
                target.validate_research_identity()
                return target
            from ura.targets.local import OllamaTarget
            target = OllamaTarget(
                model=model, model_digest=str(local_identity["digest"])
            )
            target.validate_research_identity()
            return target
        # provider:model (anthropic/openai/google/gemini)
        return build_api_target(spec)
    # bare id: resolve against the verified hosted/mock registry
    return build_api_target(spec)


def build_judges(
    names: list[str],
    judge_model: str,
    *,
    guardrail_model: str = "meta-llama/Llama-Guard-3-8B",
    guardrail_revision: str = "",
    guardrail_device: str = "",
) -> JudgeCascade:
    if "llm" in names and judge_model == "mock":
        # The llm judge backed by the offline MockTarget is a keyword heuristic, not
        # a model. Fine for a keyless smoke run, but it silently invalidates any
        # scored run (ASR, and especially the inter-judge kappa of V.2.5). Warn loud.
        print(
            "  ! WARNING: --judges includes 'llm' but --judge-model is 'mock'. "
            "The llm stage will use the offline keyword mock, NOT a real model; "
            "kappa and llm-judged ASR will be meaningless. Pass e.g. "
            "--judge-model claude-haiku-4-5-20251001 for a scored run.",
            file=sys.stderr,
        )
    stages = []
    for n in names:
        if n == "rules":
            stages.append(RuleJudge())
        elif n == "llm":
            # build_api_target resolves both bare registered ids and provider:model
            # forms, so the judge can be any provider (e.g. kimi:kimi-k3), not only a
            # registry default; falls back to REGISTRY.create for bare ids like "mock".
            stages.append(LLMJudge(judge_target=build_api_target(judge_model)))
        elif n == "guardrail":
            from ura.judges.guardrail import GuardrailJudge
            stages.append(GuardrailJudge(
                model=guardrail_model,
                revision=guardrail_revision,
                device=guardrail_device or None,
            ))
        else:
            raise ValueError(f"unknown judge {n!r}")
    return JudgeCascade(stages or [RuleJudge()])


def _cluster_key(index: int, record: object) -> str:
    """Group key for whole-cluster sampling: a source cluster id (e.g. a
    GPTGeoChat conversation's five threshold rows, or an R-Judge trajectory)
    if present, else the DataPoint id, else the row index (independent rows)."""
    meta = getattr(record, "meta", None)
    if isinstance(meta, dict):
        cluster = meta.get("source_cluster_id")
        if isinstance(cluster, str) and cluster.strip():
            return cluster
    identifier = getattr(record, "id", None)
    if isinstance(identifier, str) and identifier.strip():
        return identifier
    return f"__row_{index}__"


def _select_corpus(
    name: str, dps: list[DataPoint], limit: int, sample_seed: int
) -> tuple[list[DataPoint], list[int]]:
    if not limit or limit >= len(dps):
        return dps, list(range(len(dps)))
    # Sample whole clusters, never splitting a conversation/threshold cluster,
    # so per-cluster classification denominators stay intact.
    clusters: dict[str, list[int]] = {}
    for index, record in enumerate(dps):
        clusters.setdefault(_cluster_key(index, record), []).append(index)
    keys = list(clusters)
    seed_material = f"ura-corpus-sample-v2\0{name}\0{sample_seed}".encode("utf-8")
    scoped_seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
    order = random.Random(scoped_seed).sample(range(len(keys)), k=len(keys))
    chosen: list[int] = []
    total = 0
    for position in order:
        members = clusters[keys[position]]
        if chosen and total + len(members) > limit:
            continue  # never split a cluster; skip an overflowing one
        chosen.extend(members)
        total += len(members)
        if total >= limit:
            break
    indices = sorted(chosen)
    return [dps[index] for index in indices], indices


def _verify_expected_release(
    name: str, *, source_tree_sha256: str, total_records: int
) -> None:
    """Optional preregistered release check: URA_<CORPUS>_EXPECT_COUNT / _SHA256.

    Unset means no check. A mismatch fails closed so a truncated or altered
    corpus tree cannot silently shrink the evaluation denominator.
    """
    prefix = f"URA_{name.upper()}_EXPECT"
    want_count = os.environ.get(f"{prefix}_COUNT")
    if want_count and want_count.strip():
        try:
            expected = int(want_count)
        except ValueError as exc:
            raise ValueError(
                f"{prefix}_COUNT must be an integer, got {want_count!r}"
            ) from exc
        if expected != total_records:
            raise ValueError(
                f"corpus {name!r} release record-count mismatch: expected "
                f"{expected}, converted {total_records} (partial or altered tree)"
            )
    want_sha = os.environ.get(f"{prefix}_SHA256")
    if want_sha and want_sha.strip() and want_sha.strip().lower() != (source_tree_sha256 or ""):
        raise ValueError(
            f"corpus {name!r} source-tree sha256 mismatch: expected "
            f"{want_sha.strip().lower()!r}, got {source_tree_sha256!r} "
            "(partial or altered corpus tree)"
        )


def _corpus_path(name: str) -> Path:
    return Path(os.environ.get(
        f"URA_{name.upper()}_PATH", f"datasets/samples/{name}.jsonl"
    ))


def load_corpus(name: str, limit: int, sample_seed: int = 0) -> list[DataPoint]:
    """Load a corpus and take a deterministic seeded subset when limited.

    The seed is scoped by corpus name so independent corpora do not reuse the same
    pseudo-random index pattern. Selected records retain source order, which makes
    artifacts easy to compare while avoiding the bias of first-N slicing.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if name == "synth":
        return synth_corpus(12 if limit == 0 else limit)
    conv = get_converter(name)
    # expects data under datasets/<name>.jsonl by default; override via env
    path = _corpus_path(name)
    dps = conv.parse(path)
    selected, _ = _select_corpus(name, dps, limit, sample_seed)
    return selected


def load_corpus_with_audit(
    name: str, limit: int, sample_seed: int = 0
) -> tuple[list[DataPoint], dict[str, object]]:
    """Load one source and retain enough information to audit the frozen sample."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if name == "synth":
        selected = synth_corpus(12 if limit == 0 else limit)
        return selected, {
            "corpus": name,
            "source_kind": "generated_fixture",
            "source_path": None,
            "source_tree_sha256": None,
            "source_file_count": 0,
            "total_records": len(selected),
            "selected_indices": list(range(len(selected))),
            "selected_ids": [datapoint.id for datapoint in selected],
            "sample_seed": sample_seed,
            "limit": limit,
        }
    path = _corpus_path(name)
    full = get_converter(name).parse(path)
    selected, indices = _select_corpus(name, full, limit, sample_seed)
    resolved = path.expanduser().resolve(strict=True)
    tree_digest, file_count = _source_tree_digest(resolved)
    _verify_expected_release(name, source_tree_sha256=tree_digest, total_records=len(full))
    full_digest = hashlib.sha256(
        json.dumps(
            [datapoint.model_dump(mode="json") for datapoint in full],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return selected, {
        "corpus": name,
        "source_kind": "directory" if resolved.is_dir() else "file",
        "source_path": str(resolved),
        "source_tree_sha256": tree_digest,
        "source_file_count": file_count,
        "full_converted_corpus_sha256": full_digest,
        "total_records": len(full),
        "selected_indices": indices,
        "selected_ids": [datapoint.id for datapoint in selected],
        "sample_seed": sample_seed,
        "limit": limit,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="URA-Bench experiment matrix.")
    ap.add_argument("--dry-run", action="store_true", help="use MockTarget only")
    ap.add_argument("--api", default="", help="comma list of API model ids")
    ap.add_argument("--local", default="", help="comma list of backend:model specs")
    ap.add_argument(
        "--local-config",
        default="",
        help=(
            "JSON keyed by each exact --local spec with immutable revision/digest "
            "and explicit modalities"
        ),
    )
    ap.add_argument("--attackers", default="replay,crescendo")
    ap.add_argument(
        "--attacker-config",
        default="",
        help=(
            "JSON object mapping selected attacker names to constructor kwargs; "
            "literal secrets are forbidden (use credential_env names)"
        ),
    )
    ap.add_argument("--judges", default="rules,llm")
    ap.add_argument("--judge-model", default="mock", help="target id used by LLMJudge")
    ap.add_argument(
        "--guardrail-model",
        default="meta-llama/Llama-Guard-3-8B",
        help="exact Hugging Face model id for guardrail judge/defense cells",
    )
    ap.add_argument(
        "--guardrail-revision",
        default="",
        help="required immutable 40-64 hex Hugging Face commit for guardrail cells",
    )
    ap.add_argument(
        "--guardrail-device",
        default="",
        help="optional torch device for guardrail inference (empty uses device_map=auto)",
    )
    ap.add_argument("--corpora", default="synth")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument(
        "--sample-seed", type=int, default=0,
        help="seed for deterministic corpus subsampling (real corpora only)",
    )
    ap.add_argument("--seeds", default="0")
    ap.add_argument("--max-queries", type=int, default=4,
                    help="maximum target calls per datapoint and seed")
    ap.add_argument("--max-turns", type=int, default=4,
                    help="maximum dialog turns per datapoint and seed")
    ap.add_argument("--group", default="model,risk",
                    help="aggregation group keys, e.g. model,risk,modality (E5 m-ASR)")
    ap.add_argument("--defense", default="none",
                    choices=["none", "input", "output", "both"],
                    help="wrap targets in a GuardedTarget pre/post-filter (E4 ablation)")
    ap.add_argument("--defense-guard", default="rules", choices=["rules", "guardrail"],
                    help="judge used as the defense guardrail when --defense is set")
    ap.add_argument("--quantization", default="",
                    help="vLLM quantization for local models (e.g. awq, gptq, fp8); "
                         "empty auto-detects from a pre-quantized checkpoint")
    ap.add_argument("--dtype", default="auto",
                    help="vLLM dtype for local models (auto, bfloat16, float16)")
    ap.add_argument("--out", default="runs/exp")
    args = ap.parse_args(argv)

    if args.limit < 0:
        ap.error("--limit must be non-negative")
    if args.max_queries <= 0 or args.max_turns <= 0:
        ap.error("--max-queries and --max-turns must be positive")

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    if not seeds:
        ap.error("--seeds must contain at least one integer")
    if len(set(seeds)) != len(seeds):
        ap.error("--seeds must be unique")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Wall-clock provenance for V.2.6 (run date). Recorded in the manifest but kept
    # OUT of the run_id hash, so runs stay reproducible while the date is captured.
    run_started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_env = _runtime_env()

    api_specs = [s.strip() for s in args.api.split(",") if s.strip()]
    local_specs = [s.strip() for s in args.local.split(",") if s.strip()]
    if len(set(api_specs)) != len(api_specs):
        ap.error("--api specs must be unique")
    if len(set(local_specs)) != len(local_specs):
        ap.error("--local specs must be unique")
    model_specs = ["mock"] if args.dry_run else (api_specs + local_specs)
    if len(set(model_specs)) != len(model_specs):
        ap.error("target specs must be unique across --api and --local")
    if not model_specs:
        ap.error("a real run requires at least one --api or --local target; use --dry-run for mock")

    attacker_names = [a.strip() for a in args.attackers.split(",") if a.strip()]
    judge_names = [j.strip() for j in args.judges.split(",") if j.strip()]
    corpora = [c.strip() for c in args.corpora.split(",") if c.strip()]
    if not attacker_names:
        ap.error("--attackers must contain at least one adapter name")
    if not judge_names:
        ap.error("--judges must contain at least one judge name")
    if not corpora:
        ap.error("--corpora must contain at least one corpus name")
    for _label, _values in (
        ("--attackers", attacker_names), ("--judges", judge_names),
        ("--corpora", corpora),
    ):
        if len(set(_values)) != len(_values):
            ap.error(f"{_label} entries must be unique")
    try:
        attacker_configs, attacker_config_artifact = _load_attacker_config(
            args.attacker_config, attacker_names
        )
        local_configs, local_config_artifact = _load_local_config(
            args.local_config, [] if args.dry_run else local_specs
        )
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    if not args.dry_run and "llm" in judge_names and args.judge_model == "mock":
        ap.error("a real run with the llm judge requires an explicit non-mock --judge-model")
    guardrail_selected = "guardrail" in judge_names or (
        args.defense != "none" and args.defense_guard == "guardrail"
    )
    if guardrail_selected:
        if not args.guardrail_model.strip():
            ap.error("guardrail cells require a non-blank --guardrail-model")
        if re.fullmatch(r"[0-9a-fA-F]{40,64}", args.guardrail_revision) is None:
            ap.error(
                "guardrail cells require --guardrail-revision as an immutable "
                "40-64 hex Hugging Face commit"
            )

    group_keys = [k.strip() for k in args.group.split(",") if k.strip()]
    if not group_keys:
        ap.error("--group must contain at least one grouping key")

    # The experiment driver controls sampling, grid accounting, and completion
    # semantics that the runner's src/ura source hash does not cover. Content-
    # address it so a changed driver yields a different grid_id and cannot reuse
    # stale completion evidence, and record it in per-cell provenance.
    driver_digest, driver_file_count = _source_tree_digest(Path(__file__).resolve())
    driver_source = {
        "module": Path(__file__).name,
        "sha256": driver_digest,
        "file_count": driver_file_count,
    }

    grid_request = {
        "models": model_specs,
        "corpora": corpora,
        "attackers": attacker_names,
        "attacker_configs": attacker_configs,
        "attacker_config_artifact": attacker_config_artifact,
        "local_configs": local_configs,
        "local_config_artifact": local_config_artifact,
        "judges": judge_names,
        "judge_model": args.judge_model,
        "guardrail_model": args.guardrail_model if guardrail_selected else None,
        "guardrail_revision": (
            args.guardrail_revision.lower() if guardrail_selected else None
        ),
        "guardrail_device": args.guardrail_device or None,
        "seeds": seeds,
        "sample_seed": args.sample_seed,
        "limit": args.limit,
        "max_queries": args.max_queries,
        "max_turns": args.max_turns,
        "group_keys": group_keys,
        "defense": args.defense,
        "defense_guard": args.defense_guard,
        "quantization": args.quantization,
        "dtype": args.dtype,
        "dry_run": bool(args.dry_run),
        "driver_source": driver_source,
    }
    grid_material = json.dumps(
        grid_request, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    grid_id = f"grid-{hashlib.sha256(grid_material).hexdigest()[:24]}"
    grid_path = out / f"{grid_id}.grid.json"
    grid_lock = out / f"{grid_id}.grid.lock"
    try:
        descriptor = os.open(
            str(grid_lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY
        )
    except FileExistsError:
        print(
            f"grid lock already exists; refusing concurrent execution: {grid_lock}",
            file=sys.stderr,
        )
        return 1
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "grid_id": grid_id,
            "pid": os.getpid(),
            "started_at": run_started,
        }) + "\n")
    cell_statuses: list[dict[str, object]] = []
    _write_json(grid_path, {
        "status": "running",
        "grid_id": grid_id,
        "started_at": run_started,
        "request": grid_request,
        "requested_cells": len(model_specs) * len(corpora) * len(attacker_names),
        "cells": cell_statuses,
    })

    n_cells = 0
    n_skipped = 0
    n_errors = 0
    for corpus_name in corpora:
        try:
            corpus, sampling_audit = load_corpus_with_audit(
                corpus_name, args.limit, args.sample_seed
            )
        except Exception as exc:  # noqa: BLE001 - requested source failure
            n_errors += 1
            _write_json(out / f"{_safe_component(corpus_name)}.corpus.error.json", {
                "status": "error",
                "phase": "corpus_loading",
                "corpus": corpus_name,
                "exception_type": type(exc).__name__,
                "message": str(exc),
            })
            for spec in model_specs:
                for attacker_name in attacker_names:
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": spec,
                        "attacker": attacker_name,
                        "status": "error",
                        "phase": "corpus_loading",
                    })
            print(
                f"corpus '{corpus_name}' failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            continue
        if not corpus:
            n_errors += 1
            _write_json(out / f"{_safe_component(corpus_name)}.corpus.error.json", {
                "status": "error",
                "phase": "corpus_loading",
                "corpus": corpus_name,
                "exception_type": "EmptyCorpusError",
                "message": "requested corpus converted to zero datapoints",
            })
            for spec in model_specs:
                for attacker_name in attacker_names:
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": spec,
                        "attacker": attacker_name,
                        "status": "error",
                        "phase": "empty_corpus",
                    })
            print(f"corpus '{corpus_name}' is empty; requested cells failed")
            continue
        print(f"corpus '{corpus_name}': {len(corpus)} datapoints")
        for spec in model_specs:
            try:
                target = build_target(
                    spec,
                    quantization=args.quantization,
                    dtype=args.dtype,
                    local_identity=local_configs.get(spec),
                )
            except Exception as exc:  # noqa: BLE001 - isolate requested targets
                n_errors += 1
                setup_error = out / (
                    "__".join((
                        _safe_component(corpus_name),
                        _safe_component(spec),
                        "target-setup",
                    ))
                    + ".error.json"
                )
                _write_json(setup_error, {
                    "status": "error",
                    "phase": "target_construction",
                    "corpus": corpus_name,
                    "model_spec": spec,
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                })
                for attacker_name in attacker_names:
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": spec,
                        "local_identity": local_configs.get(spec),
                        "attacker": attacker_name,
                        "status": "error",
                        "phase": "target_construction",
                        "error_artifact": setup_error.name,
                    })
                print(
                    f"  ! cannot construct target '{spec}': "
                    f"{type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                continue
            if args.defense != "none":  # E4: wrap in a guardrail pre/post-filter
                from ura.targets.guarded import GuardedTarget
                if args.defense_guard == "guardrail":
                    from ura.judges.guardrail import GuardrailJudge
                    guard = GuardrailJudge(
                        model=args.guardrail_model,
                        revision=args.guardrail_revision,
                        device=args.guardrail_device or None,
                    )
                else:
                    guard = RuleJudge()
                target = GuardedTarget(target, guard, mode=args.defense)
            for attacker_name in attacker_names:
                runner = None
                planned = None
                stem = None
                execution_started = False
                cell_lock_acquired = False
                cell_lock_conflict = False
                cell_lock: Path | None = None
                paths: dict[str, Path] = {}
                fallback_error = out / (
                    "__".join((
                        _safe_component(corpus_name),
                        _safe_component(spec),
                        _safe_component(attacker_name),
                        "unplanned",
                    ))
                    + ".error.json"
                )
                try:
                    attacker_config = attacker_configs.get(
                        attacker_name.lower(), {}
                    )
                    attacker = get_attacker(attacker_name, **attacker_config)
                    if getattr(attacker, "runner_replay_eligible", True) is False:
                        raise ValueError(
                            f"attacker {attacker_name!r} is a native-artifact "
                            "integration and cannot be replayed through Runner"
                        )
                    cascade = build_judges(
                        judge_names,
                        args.judge_model,
                        guardrail_model=args.guardrail_model,
                        guardrail_revision=args.guardrail_revision,
                        guardrail_device=args.guardrail_device,
                    )
                    runner = Runner(
                        attacker,
                        target,
                        cascade,
                        AttackBudget(
                            max_queries=args.max_queries,
                            max_turns=args.max_turns,
                            seed=seeds[0],
                        ),
                        seeds,
                    )
                    cell_config = {
                        "corpus": corpus_name,
                        "limit": args.limit,
                        "sample_seed": args.sample_seed,
                        "sampling_audit": sampling_audit,
                        "model_spec": spec,
                        "local_identity": local_configs.get(spec),
                        "attacker": attacker_name,
                        "attacker_config": attacker_config,
                        "judge_names": judge_names,
                        "judge_model": args.judge_model,
                        "guardrail_model": (
                            args.guardrail_model if guardrail_selected else None
                        ),
                        "guardrail_revision": (
                            args.guardrail_revision.lower()
                            if guardrail_selected else None
                        ),
                        "guardrail_device": args.guardrail_device or None,
                        "group_keys": group_keys,
                        "defense": args.defense,
                        "defense_guard": args.defense_guard,
                        "quantization": args.quantization,
                        "dtype": args.dtype,
                        "dry_run": bool(args.dry_run),
                        "driver_source": driver_source,
                    }
                    planned = runner.plan_manifest(
                        corpus,
                        started_at=run_started,
                        env=run_env,
                        run_config=cell_config,
                    )
                    stem = "__".join((
                        _safe_component(corpus_name),
                        _safe_component(target.name),
                        _safe_component(attacker_name),
                        planned.run_id,
                    ))
                    paths = {
                        "attempts": out / f"{stem}.attempts.jsonl",
                        "responses": out / f"{stem}.responses.jsonl",
                        "judgments": out / f"{stem}.jsonl",
                        "trails": out / f"{stem}.trails.jsonl",
                        "results": out / f"{stem}.results.jsonl",
                        "manifest": out / f"{stem}.manifest.json",
                        "checkpoint": out / f"{stem}.checkpoint.jsonl",
                        "complete": out / f"{stem}.complete.json",
                        "error": out / f"{stem}.error.json",
                    }
                    cell_lock = out / f"{stem}.cell.lock"
                    try:
                        cell_descriptor = os.open(
                            str(cell_lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                        )
                    except FileExistsError as exc:
                        cell_lock_conflict = True
                        raise RuntimeError(
                            f"cell lock already exists; another grid may be writing "
                            f"this exact run: {cell_lock}"
                        ) from exc
                    with os.fdopen(cell_descriptor, "w", encoding="utf-8") as handle:
                        handle.write(json.dumps({
                            "grid_id": grid_id,
                            "run_id": planned.run_id,
                            "pid": os.getpid(),
                            "started_at": run_started,
                        }, allow_nan=False) + "\n")
                    cell_lock_acquired = True

                    required = (
                        "attempts", "responses", "judgments", "trails",
                        "results", "manifest",
                    )
                    if paths["complete"].is_file():
                        _validate_completion_marker(paths, planned, required)
                        # A fully verified success supersedes a stale same-stem
                        # failure from an earlier retry.
                        paths["error"].unlink(missing_ok=True)
                        print(f"  [{stem}] already complete; no calls made")
                        n_skipped += 1
                        cell_statuses.append({
                            "corpus": corpus_name,
                            "model_spec": spec,
                            "target": target.name,
                            "attacker": attacker_name,
                            "run_id": planned.run_id,
                            "status": "complete_existing",
                            "completion_marker": paths["complete"].name,
                        })
                        continue

                    resumed = Runner.load_checkpoint(
                        paths["checkpoint"], expected_run_id=planned.run_id
                    )
                    execution_started = True
                    judgments, manifest = runner.run(
                        corpus,
                        started_at=run_started,
                        env=run_env,
                        run_config=cell_config,
                        manifest=planned,
                        resume_records=resumed,
                        on_record=lambda record, checkpoint=paths["checkpoint"]: (
                            Runner.append_checkpoint(checkpoint, record)
                        ),
                    )
                    results = runner.aggregate(judgments, group_keys=group_keys)

                    runner.save_attempts(paths["attempts"])
                    runner.save_responses(paths["responses"])
                    runner.save_results(judgments, paths["judgments"])
                    runner.save_trails(paths["trails"])
                    paths["results"].write_text(
                        "\n".join(r.model_dump_json() for r in results) + "\n",
                        encoding="utf-8",
                    )
                    paths["manifest"].write_text(
                        manifest.model_dump_json(indent=1), encoding="utf-8"
                    )
                    _write_json(paths["complete"], {
                        "status": "complete",
                        "format_version": 2,
                        "run_id": manifest.run_id,
                        "code_version": manifest.code_version,
                        "schema_version": manifest.schema_version,
                        "n_attempts": len(runner.attempts),
                        "n_responses": len(runner.responses),
                        "n_judgments": len(judgments),
                        "n_results": len(results),
                        "realized_identities_sha256": manifest.config[
                            "realized_identities_sha256"
                        ],
                        "artifacts": {
                            name: _artifact_descriptor(paths[name])
                            for name in required
                        },
                    })
                    _validate_completion_marker(paths, planned, required)
                    paths["error"].unlink(missing_ok=True)
                    print(
                        f"  [{stem}] {len(judgments)} judgments -> {len(results)} "
                        f"results (run {manifest.run_id}; resumed {len(resumed)})"
                    )
                    n_cells += 1
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": spec,
                        "target": target.name,
                        "attacker": attacker_name,
                        "run_id": manifest.run_id,
                        "status": "complete",
                        "completion_marker": paths["complete"].name,
                    })
                except Exception as exc:  # noqa: BLE001 - isolate matrix cells
                    n_errors += 1
                    run_id = planned.run_id if planned is not None else None
                    if execution_started and runner is not None and paths:
                        # These snapshots are diagnostic fallbacks; the append-only
                        # checkpoint remains the authoritative resume source.
                        try:
                            runner.save_attempts(paths["attempts"])
                            runner.save_responses(paths["responses"])
                            runner.save_results(runner.judgments, paths["judgments"])
                            runner.save_trails(paths["trails"])
                            partial_manifest = runner.last_manifest or planned
                            if partial_manifest is not None:
                                paths["manifest"].write_text(
                                    partial_manifest.model_dump_json(indent=1),
                                    encoding="utf-8",
                                )
                        except Exception as artifact_exc:  # noqa: BLE001
                            print(
                                f"  ! partial artifact write also failed: "
                                f"{type(artifact_exc).__name__}: {artifact_exc}",
                                file=sys.stderr,
                            )
                    error_path = (
                        out / f"{stem}__{grid_id}.lock.error.json"
                        if cell_lock_conflict and stem is not None
                        else paths.get("error", fallback_error)
                    )
                    _write_json(error_path, {
                            "status": "error",
                            "run_id": run_id,
                            "corpus": corpus_name,
                            "model_spec": spec,
                            "target": getattr(target, "name", spec),
                            "attacker": attacker_name,
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "completed_attempts": len(runner.attempts) if runner else 0,
                        })
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": spec,
                        "target": getattr(target, "name", spec),
                        "attacker": attacker_name,
                        "run_id": run_id,
                        "status": "error",
                        "phase": "cell_execution_or_validation",
                        "error_artifact": error_path.name,
                    })
                    print(
                        f"  ! cell failed [{stem or f'{corpus_name}/{spec}/{attacker_name}'}]: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )
                finally:
                    if cell_lock_acquired and cell_lock is not None:
                        cell_lock.unlink(missing_ok=True)

    requested_cells = len(model_specs) * len(corpora) * len(attacker_names)
    if len(cell_statuses) != requested_cells:
        n_errors += 1
        cell_statuses.append({
            "status": "error",
            "phase": "grid_accounting",
            "message": (
                f"accounted for {len(cell_statuses)} of {requested_cells} "
                "requested cells"
            ),
        })
    _write_json(grid_path, {
        "status": "complete" if n_errors == 0 else "partial",
        "grid_id": grid_id,
        "started_at": run_started,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "request": grid_request,
        "requested_cells": requested_cells,
        "accounted_cells": min(len(cell_statuses), requested_cells),
        "n_new_complete": n_cells,
        "n_existing_complete": n_skipped,
        "n_errors": n_errors,
        "cells": cell_statuses,
    })
    grid_lock.unlink(missing_ok=True)

    print(
        f"\ndone: {n_cells} cells written, {n_skipped} already complete, "
        f"{n_errors} failed; artifacts in {out}"
    )
    print(
        "figures: python -m experiments.figures --help  "
        "# pass explicit model/defense grid roots and preregistered corpus facets"
    )
    return 1 if n_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
