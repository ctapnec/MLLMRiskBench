"""Validate source-native evaluator artifacts and write one canonical envelope.

The native adapters remain the substantive authorities: this command only
dispatches a configured ``import_run`` call, validates its ``NativeEngineRun``
contract, re-hashes every referenced source artifact, and writes canonical
JSON.  It never runs an upstream evaluator, target, attacker, or judge.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pydantic import ValidationError  # noqa: E402

from ura.adapters._engine_common import ExternalEngineOutputError  # noqa: E402
from ura.adapters._native_artifacts import (  # noqa: E402
    DEFAULT_MAX_ARTIFACT_BYTES,
    NativeEngineRun,
    describe_artifact,
    read_utf8_artifact,
    strict_json_loads,
)


CONFIG_SCHEMA = "ura-native-import-config/1"
ENVELOPE_SCHEMA = "ura-native-import-envelope/2"
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_NORMALIZED_RUN_BYTES = DEFAULT_MAX_ARTIFACT_BYTES
_PATH_ARGUMENTS = frozenset({
    "config_path",
    "generated_config",
    "log_path",
    "report_path",
    "repo",
    "result_csv",
    "result_jsonl",
    "results_dir",
    "results_json",
    "trace_root",
})


def _engine_factory(engine: str) -> tuple[type[Any], str]:
    """Resolve only the audited, result-producing adapter surfaces."""

    if engine == "agentdojo":
        from ura.adapters.agentdojo import AgentDojoAttacker

        return AgentDojoAttacker, "import_run"
    if engine == "asb":
        from ura.adapters.asb import ASBAttacker

        return ASBAttacker, "import_run"
    if engine == "autodan_turbo":
        from ura.adapters.autodan import AutoDANTurboAttacker

        return AutoDANTurboAttacker, "import_run"
    if engine == "easyjailbreak":
        from ura.adapters.easyjailbreak import EasyJailbreakAttacker

        return EasyJailbreakAttacker, "import_run"
    if engine == "fuzzyai":
        from ura.adapters.fuzzyai import FuzzyAIAttacker

        return FuzzyAIAttacker, "import_run"
    if engine == "garak":
        from ura.adapters.garak import GarakAttacker

        return GarakAttacker, "import_run"
    if engine == "giskard":
        from ura.adapters.giskard import GiskardAttacker

        return GiskardAttacker, "import_run"
    if engine == "petri":
        from ura.adapters.petri import PetriAttacker

        return PetriAttacker, "import_run"
    if engine == "promptfoo":
        from ura.adapters.promptfoo import PromptfooAttacker

        return PromptfooAttacker, "import_run"
    raise ValueError(
        "unsupported native engine; choose agentdojo, asb, autodan_turbo, "
        "easyjailbreak, fuzzyai, garak, giskard, petri, or promptfoo"
    )


def _read_json_object(path: Path, *, max_bytes: int) -> tuple[Path, bytes, dict[str, Any]]:
    resolved, data, text = read_utf8_artifact(path, max_bytes=max_bytes)
    try:
        value = strict_json_loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid strict JSON in {resolved}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain one object: {resolved}")
    return resolved, data, value


def _relative_paths(kwargs: dict[str, Any], *, base: Path) -> dict[str, Any]:
    """Resolve the small explicit set of adapter path fields by config location."""

    resolved = dict(kwargs)
    for key in _PATH_ARGUMENTS & resolved.keys():
        value = resolved[key]
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"native import path {key!r} must be a nonblank string")
        path = Path(value).expanduser()
        resolved[key] = str(path if path.is_absolute() else base / path)
    return resolved


def _validate_kwargs(call: Callable[..., Any], kwargs: dict[str, Any], *, label: str) -> None:
    if any(not isinstance(key, str) or not key.strip() for key in kwargs):
        raise ValueError(f"{label} keys must be nonblank strings")
    parameters = inspect.signature(call).parameters
    unknown = sorted(set(kwargs) - set(parameters))
    if unknown:
        raise ValueError(f"unsupported {label} key(s): {', '.join(unknown)}")


def validate_native_run(run: NativeEngineRun) -> NativeEngineRun:
    """Re-hash a normalized run's authoritative files and verify its joins."""

    artifact_roles = [artifact.role for artifact in run.source_artifacts]
    artifact_paths = [artifact.path for artifact in run.source_artifacts]
    if len(set(artifact_roles)) != len(artifact_roles):
        raise ValueError("native run source-artifact roles must be unique")
    if len(set(artifact_paths)) != len(artifact_paths):
        raise ValueError("native run source-artifact paths must be unique")

    role_set = set(artifact_roles)
    target_set = set(run.target_models)
    for case in run.cases:
        if case.source_run_id != run.native_run_id:
            raise ValueError(
                f"native case {case.id!r} does not join to native_run_id"
            )
        if case.source_artifact_role not in role_set:
            raise ValueError(
                f"native case {case.id!r} references an unknown artifact role"
            )
        if case.target_model not in target_set:
            raise ValueError(
                f"native case {case.id!r} references an undeclared target model"
            )

    for artifact in run.source_artifacts:
        observed = describe_artifact(
            Path(artifact.path), role=artifact.role, records=artifact.records
        )
        if (
            observed.path != artifact.path
            or observed.sha256 != artifact.sha256
            or observed.bytes != artifact.bytes
        ):
            raise ExternalEngineOutputError(
                f"normalized native artifact no longer matches {artifact.role!r}"
            )
    return run


def _load_native_envelope(
    path: Path,
) -> tuple[NativeEngineRun, str, Path]:
    """Re-run the bound importer so raw artifacts remain authoritative."""

    resolved, data, envelope = _read_json_object(path, max_bytes=_MAX_NORMALIZED_RUN_BYTES)
    if set(envelope) != {"schema_version", "import_config", "run"}:
        raise ValueError(
            "canonical native envelope requires schema_version, import_config, run"
        )
    if envelope["schema_version"] != ENVELOPE_SCHEMA:
        raise ValueError(
            f"unsupported canonical native envelope: {envelope['schema_version']!r}"
        )
    config_ref = envelope["import_config"]
    if not isinstance(config_ref, dict) or set(config_ref) != {
        "locator", "sha256", "bytes"
    }:
        raise ValueError("canonical native envelope has invalid import_config")
    locator = config_ref["locator"]
    if (
        not isinstance(locator, str)
        or not locator.strip()
        or Path(locator).is_absolute()
    ):
        raise ValueError("native import-config locator must be nonblank and relative")
    config_path = resolved.parent / Path(locator)
    config_resolved, config_data, _ = _read_json_object(
        config_path, max_bytes=_MAX_CONFIG_BYTES
    )
    if (
        config_ref["bytes"] != len(config_data)
        or config_ref["sha256"] != hashlib.sha256(config_data).hexdigest()
    ):
        raise ExternalEngineOutputError(
            "canonical native envelope import config no longer matches"
        )
    value = envelope["run"]
    try:
        run = NativeEngineRun.model_validate(value, strict=True)
    except ValidationError as exc:
        raise ValueError(f"schema-invalid NativeEngineRun in {resolved}: {exc}") from exc
    reimported = import_from_config(config_resolved)
    stored_identity = run.model_dump(mode="json")
    reimported_identity = reimported.model_dump(mode="json")
    # Physical artifact paths are runtime locators, not scientific identity.
    # The importer-bound config is re-resolved at the extraction location; all
    # roles, hashes, byte/record counts, cases, outcomes, scores and aggregates
    # must still match exactly.
    for identity in (stored_identity, reimported_identity):
        for artifact in identity["source_artifacts"]:
            artifact["path"] = "@import-config-resolved-artifact"
    if reimported_identity != stored_identity:
        raise ExternalEngineOutputError(
            "canonical native run differs from a fresh import of its authoritative files"
        )
    return reimported, hashlib.sha256(data).hexdigest(), config_resolved


def load_native_run(path: Path) -> tuple[NativeEngineRun, str]:
    """Load an importer-bound canonical envelope and rederive its run."""

    run, digest, _ = _load_native_envelope(path)
    return run, digest


def import_from_config(path: Path) -> NativeEngineRun:
    """Invoke one configured adapter importer without executing its upstream tool."""

    resolved, _, config = _read_json_object(path, max_bytes=_MAX_CONFIG_BYTES)
    if set(config) != {"schema_version", "engine", "adapter", "import"}:
        raise ValueError(
            "native import config requires exactly schema_version, engine, adapter, import"
        )
    if config["schema_version"] != CONFIG_SCHEMA:
        raise ValueError(f"unsupported native import config schema: {config['schema_version']!r}")
    engine = config["engine"]
    if not isinstance(engine, str):
        raise ValueError("native import engine must be a string")
    adapter_kwargs = config["adapter"]
    import_kwargs = config["import"]
    if not isinstance(adapter_kwargs, dict) or not isinstance(import_kwargs, dict):
        raise ValueError("native import adapter and import fields must be objects")

    adapter_type, method_name = _engine_factory(engine)
    adapter_kwargs = _relative_paths(adapter_kwargs, base=resolved.parent)
    import_kwargs = _relative_paths(import_kwargs, base=resolved.parent)
    _validate_kwargs(adapter_type, adapter_kwargs, label="adapter configuration")
    adapter = adapter_type(**adapter_kwargs)
    importer = getattr(adapter, method_name)
    _validate_kwargs(importer, import_kwargs, label="import configuration")
    run = importer(**import_kwargs)
    if not isinstance(run, NativeEngineRun):
        raise TypeError(f"{engine} importer did not return NativeEngineRun")
    return validate_native_run(run)


def _canonical_envelope_bytes(
    run: NativeEngineRun,
    *,
    config_path: Path,
    output_path: Path,
) -> bytes:
    config_resolved, config_data, _ = _read_json_object(
        config_path, max_bytes=_MAX_CONFIG_BYTES
    )
    try:
        locator = Path(os.path.relpath(
            config_resolved,
            start=output_path.parent.resolve(),
        )).as_posix()
    except ValueError as exc:
        raise ValueError(
            "native import config and canonical envelope must share a filesystem volume"
        ) from exc
    return (
        json.dumps(
            {
                "schema_version": ENVELOPE_SCHEMA,
                "import_config": {
                    "locator": locator,
                    "sha256": hashlib.sha256(config_data).hexdigest(),
                    "bytes": len(config_data),
                },
                "run": run.model_dump(mode="json"),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import or revalidate a source-native evaluator run"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path, help="strict adapter import config JSON")
    source.add_argument(
        "--validate", type=Path, help="existing canonical NativeEngineRun JSON"
    )
    parser.add_argument("--out", type=Path, help="new canonical output path")
    args = parser.parse_args(argv)
    if args.config is not None and args.out is None:
        parser.error("--config requires --out")

    try:
        if args.config is not None:
            run = import_from_config(args.config)
            payload = _canonical_envelope_bytes(
                run,
                config_path=args.config,
                output_path=args.out,
            )
            _write_new(args.out, payload)
            output = str(args.out.resolve())
            digest = hashlib.sha256(payload).hexdigest()
        else:
            run, digest, config_path = _load_native_envelope(args.validate)
            output = str(args.validate.resolve())
            if args.out is not None:
                payload = _canonical_envelope_bytes(
                    run,
                    config_path=config_path,
                    output_path=args.out,
                )
                _write_new(args.out, payload)
                output = str(args.out.resolve())
                digest = hashlib.sha256(payload).hexdigest()
    except (OSError, TypeError, ValueError, ExternalEngineOutputError) as exc:
        print(f"native import failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "status": "validated",
        "engine": run.engine,
        "native_run_id": run.native_run_id,
        "n_cases": len(run.cases),
        "output": output,
        "sha256": digest,
        "common_metric_eligible": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
