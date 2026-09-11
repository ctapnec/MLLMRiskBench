"""Builder validation, projection, ceilings, and preview rendering."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Mapping

from ura.targets.api import (
    api_target_endpoint_identity,
    api_target_requires_config,
    build_api_target,
    canonical_api_target_identity,
    normalize_api_target_config,
)
from ura.targets.local import canonical_local_model_identity
from ura.source_conformance import validate_source_conformance_manifest
from ura.strict_json import strict_json_loads
from ura.sampling import SAMPLING_POLICIES
from ura.adapters._engine_runtime import (
    ENGINE_RUNTIME_CONFIG_SCHEMA,
    RUNTIME_REQUIRED_ATTACKERS,
    parse_engine_runtime_config,
)
from ura.adapters.nanogcg import LIVE_NANOGCG_DISABLED_MESSAGE

from .catalog import (
    _ARM_CATALOG,
    _SOURCE_METRIC_ARMS,
    _INELIGIBLE_ARMS,
    _INELIGIBLE_REASONS,
    _ATTACKER_NAMES,
    _NATIVE_ONLY_ATTACKERS,
    _CLI_ONLY_ATTACKERS,
    _SOURCE_RESTRICTED_ATTACKERS,
    _FRAMEWORKS,
    _BUILD_MODES,
    _icon,
)

from .ui import _page

from .artifacts import _argv_out_dir


def _hosted_model_identity(
    spec: str,
    config: Mapping[str, object] | None = None,
) -> frozenset[tuple[str, ...]] | None:
    """Strong hosted identities without changing the requested execution route."""

    try:
        provider, model = canonical_api_target_identity(spec)
        endpoint = api_target_endpoint_identity(spec, dict(config or {}))
        if endpoint is not None:
            keys: set[tuple[str, ...]] = {("endpoint-model", endpoint, model)}
        else:
            keys = {("provider-model", provider, model)}
        return frozenset(keys)
    except (KeyError, ValueError):
        return None


def _local_model_identity(
    spec: str,
    entry: Mapping[str, object],
) -> tuple[str, ...] | None:
    """Immutable local identity shared with runtime duplicate admission."""

    backend, separator, model = spec.partition(":")
    if separator != ":" or backend.lower() not in {"vllm", "ollama"}:
        return None
    return canonical_local_model_identity(
        model,
        revision=entry.get("revision"),
        model_digest=entry.get("digest"),
    )


def _condition_sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _hosted_target_condition(
    spec: str,
    config: Mapping[str, object] | None,
) -> str:
    try:
        if not api_target_requires_config(spec):
            built = build_api_target(spec)
            provider, model = canonical_api_target_identity(spec)
            return _condition_sha256({
                "fixed_inherent_route_class": (
                    f"{built.__class__.__module__}."
                    f"{built.__class__.__qualname__}"
                ),
                "provider": provider,
                "model": model,
            })
        normalized = normalize_api_target_config(spec, dict(config or {}))
        normalized.pop("base_url", None)
        return _condition_sha256({"generic_route_config": normalized})
    except (KeyError, TypeError, ValueError):
        # Validation reports the authoritative route/config error separately;
        # keep duplicate accounting total and deterministic meanwhile.
        return _condition_sha256({"invalid_route": spec})


def _local_target_condition(
    spec: str,
    entry: Mapping[str, object],
    *,
    quantization: str,
    dtype: str,
) -> str:
    condition = {
        key: value
        for key, value in entry.items()
        if key not in {"revision", "digest"}
    }
    backend = spec.partition(":")[0].lower()
    condition["backend"] = backend
    if backend == "vllm":
        condition.update({"quantization": quantization, "dtype": dtype})
    return _condition_sha256(condition)


class BuilderValidationMixin:
    @staticmethod
    def _bounded_content_snapshot(
        path_value: str,
        expected_sha256: str,
        *,
        label: str,
        max_bytes: int,
    ) -> tuple[bytes, str]:
        """Read one exact regular file once and bind the bytes to its digest."""

        expected = str(expected_sha256).strip().lower()
        if not path_value or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError(f"{label} requires a path and exact SHA-256")
        candidate = Path(path_value).expanduser()
        descriptor: int | None = None
        try:
            initial = candidate.lstat()
            if (
                candidate.is_symlink()
                or candidate.is_junction()
                or not stat.S_ISREG(initial.st_mode)
                or initial.st_nlink != 1
                or not 0 < initial.st_size <= max_bytes
            ):
                raise ValueError(
                    f"{label} must be one non-link file within its size bound"
                )
            path = candidate.resolve(strict=True)
            resolved = path.lstat()
            if (
                path.is_symlink()
                or path.is_junction()
                or (resolved.st_dev, resolved.st_ino, resolved.st_mode)
                != (initial.st_dev, initial.st_ino, initial.st_mode)
            ):
                raise ValueError(f"{label} must not be a link")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != initial.st_size
                or (opened.st_dev, opened.st_ino, opened.st_mode)
                != (initial.st_dev, initial.st_ino, initial.st_mode)
            ):
                raise ValueError(f"{label} changed while being opened")
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                descriptor = None
                raw = handle.read(max_bytes + 1)
                after = os.fstat(handle.fileno())
            final = path.lstat()
        except OSError as exc:
            raise ValueError(f"{label} must be a readable regular file") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_mode)
        if (
            len(raw) != opened.st_size
            or len(raw) > max_bytes
            or (after.st_dev, after.st_ino, after.st_mode) != identity
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or path.is_symlink()
            or path.is_junction()
            or final.st_nlink != 1
            or (final.st_dev, final.st_ino, final.st_mode) != identity
        ):
            raise ValueError(f"{label} changed while being read")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{label} SHA-256 does not match the file")
        return raw, actual

    def _selected_api_config_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[
        dict[str, object],
        str,
        str,
        dict[str, dict[str, object]],
    ]:
        """Validate and bind the exact selected hosted execution conditions.

        The snapshot contains no endpoint URL: compatible routes retain only a
        typed SHA-256 endpoint identity.  Its digest is used by confirmation
        tickets and no-call projection reuse, while the complete registry byte
        digest makes an operator edit require a fresh review.
        """

        api_specs = self._split_list(params.get("api", ""))
        judges = self._split_list(params.get("judges", ""))
        mode = params.get("mode", "measured")
        dry = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        judge_model = params.get("judge_model", "").strip()
        if (
            not dry
            and "llm" in judges
            and judge_model
            and judge_model != "mock"
            and not judge_model.startswith(("vllm:", "ollama:"))
            and judge_model not in api_specs
        ):
            api_specs.append(judge_model)

        registry_candidates = (
            self.repo_root / "experiments" / "api-targets.json",
            self.repo_root / "experiments" / "rig" / "api-targets.example.json",
        )
        path = next((candidate for candidate in registry_candidates if candidate.exists()), None)
        registry: dict[str, object] = {}
        registry_sha256 = "none"
        registry_relative = ""
        if path is not None:
            if path.is_symlink() or not path.is_file():
                raise ValueError("API target registry must be a regular non-symlink file")
            raw = path.read_bytes()
            if not raw or len(raw) > 1024 * 1024:
                raise ValueError("API target registry must be a regular <=1 MiB JSON file")

            def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, child in pairs:
                    if key in value:
                        raise ValueError(f"API target registry has duplicate key {key!r}")
                    value[key] = child
                return value

            try:
                loaded = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"API target registry is invalid UTF-8 JSON: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ValueError("API target registry must be a JSON object")
            registry = loaded
            registry_sha256 = hashlib.sha256(raw).hexdigest()
            registry_relative = path.relative_to(self.repo_root).as_posix()
        elif api_specs:
            raise ValueError("selected hosted models require an API target registry")

        routes: list[dict[str, object]] = []
        runtime_configs: dict[str, dict[str, object]] = {}
        for spec in api_specs:
            entry = registry.get(spec)
            provider, model = canonical_api_target_identity(spec)
            if api_target_requires_config(spec):
                if not isinstance(entry, dict):
                    raise ValueError(
                        f"API target registry is missing selected generic route {spec!r}"
                    )
                normalized = normalize_api_target_config(spec, entry)
                runtime_configs[spec] = normalized
                # The constructor is side-effect free; this is the authoritative
                # adapter compatibility gate before any Job/Popen is possible.
                built = build_api_target(spec, config=normalized)
                portable_config = dict(normalized)
                endpoint_identity = api_target_endpoint_identity(spec, normalized)
                portable_config.pop("base_url", None)
                if endpoint_identity is not None:
                    portable_config["base_url_identity"] = endpoint_identity
            else:
                built = build_api_target(spec)
                declared = (
                    entry.get("modalities") if isinstance(entry, dict) else None
                )
                if declared is not None and (
                    not isinstance(declared, list)
                    or any(not isinstance(item, str) for item in declared)
                    or tuple(declared) != tuple(built.modality_support)
                ):
                    raise ValueError(
                        f"fixed API route {spec!r} registry modalities must exactly "
                        "match the authoritative adapter"
                    )
                if isinstance(entry, dict) and set(entry) != {"modalities"}:
                    raise ValueError(
                        f"fixed API route {spec!r} must not advertise mutable "
                        "execution config"
                    )
                portable_config = {
                    "inherent_route": True,
                    "modalities": list(built.modality_support),
                }
                endpoint_identity = api_target_endpoint_identity(spec)
            routes.append({
                "requested_spec": spec,
                "provider": provider,
                "model": model,
                "endpoint_identity": endpoint_identity,
                "config": portable_config,
                "selected_entry_sha256": (
                    hashlib.sha256(
                        json.dumps(
                            entry,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        ).encode("utf-8")
                    ).hexdigest()
                    if entry is not None
                    else "inherent-not-in-registry"
                ),
            })
        snapshot: dict[str, object] = {
            "schema": "ura-builder-selected-api-config/1",
            "registry_sha256": registry_sha256,
            "routes": routes,
        }
        digest = hashlib.sha256(
            json.dumps(
                snapshot,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        return snapshot, digest, registry_relative, runtime_configs

    def _bind_selected_api_config_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        """Return params bound to the current selected registry snapshot."""

        _snapshot, digest, _relative, _configs = (
            self._selected_api_config_snapshot(params)
        )
        prior = params.get("_api_config_snapshot_sha256", "")
        if prior and prior != digest:
            raise ValueError(
                "selected API registry/config changed after review; review the lane again"
            )
        bound = {key: str(value) for key, value in params.items()}
        bound["_api_config_snapshot_sha256"] = digest
        return bound

    def _selected_source_config_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, object], str, dict[str, dict[str, object]]]:
        """Bind the exact selected logical-source execution mapping.

        The example registry is presentation/setup material, never execution
        authority.  Every selected non-synthetic arm therefore requires the
        operator registry.  Only the literal ``synth`` arm may use the built-in
        generated fixture; a mutable registry can never relabel a real arm as
        synthetic and thereby make Runner discard its source receipt.
        """

        corpora = self._split_list(params.get("corpora", ""))
        if (
            params.get("mode") == "diagnostic_canary"
            and params.get("canary_dry") == "on"
        ):
            corpora = ["synth"]
        registry = self.repo_root / "experiments" / "source-instances.json"
        real_arms = [arm for arm in corpora if arm != "synth"]
        if real_arms and not registry.exists():
            raise ValueError(
                "selected real source arms require the executable operator "
                "registry experiments/source-instances.json"
            )
        if registry.exists():
            if registry.is_symlink() or not registry.is_file():
                raise ValueError(
                    "source instance registry must be a regular non-symlink file"
                )
            from experiments import run_matrix  # noqa: PLC0415

            configs, _artifact = run_matrix._load_source_config(  # noqa: SLF001
                str(registry), corpora
            )
        else:
            configs = {
                "synth": {"converter": "synth", "synth": True}
            } if corpora == ["synth"] else {}
        for arm in corpora:
            config = configs.get(arm)
            if not isinstance(config, dict):
                raise ValueError(f"source registry omits selected arm {arm!r}")
            synthetic = config.get("synth") is True
            if arm == "synth":
                if not synthetic or config.get("converter") != "synth":
                    raise ValueError(
                        "the literal synth arm must use converter='synth' and synth=true"
                    )
            elif synthetic or config.get("converter") == "synth":
                raise ValueError(
                    f"real source arm {arm!r} cannot be reclassified as synthetic"
                )
        runtime_fields = {"converter", "path_env", "synth", "source_label", "split"}
        runtime_configs = {
            arm: {
                key: value
                for key, value in configs[arm].items()
                if key in runtime_fields
            }
            for arm in corpora
        }
        snapshot: dict[str, object] = {
            "schema": "ura-builder-selected-source-config/1",
            "arms": runtime_configs,
        }
        digest = _condition_sha256(snapshot)
        return snapshot, digest, runtime_configs

    def _bind_selected_source_config_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        _snapshot, digest, _configs = self._selected_source_config_snapshot(params)
        prior = params.get("_source_config_snapshot_sha256", "")
        if prior and prior != digest:
            raise ValueError(
                "selected source registry/config changed after review; "
                "review the lane again"
            )
        bound = {key: str(value) for key, value in params.items()}
        bound["_source_config_snapshot_sha256"] = digest
        return bound

    def _selected_engine_runtime_config_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, object], str, bytes | None, str | None]:
        """Bind the exact private venv selection without retaining locators."""

        selected = sorted(
            set(self._split_list(str(params.get("attackers", ""))))
            & RUNTIME_REQUIRED_ATTACKERS
        )
        path_value = str(params.get("engine_runtime_config", "")).strip()
        expected = str(params.get("engine_runtime_config_sha", "")).strip().lower()
        if not selected:
            if path_value or expected:
                raise ValueError(
                    "engine runtime config is allowed only when PyRIT, DeepTeam, "
                    "h4rm3l, or Spikee is selected"
                )
            projection: dict[str, object] = {
                "schema": "ura-builder-selected-engine-runtime-config/1",
                "engines": [],
                "selection": None,
            }
            return projection, _condition_sha256(projection), None, None

        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        raw, actual = self._bounded_content_snapshot(
            str(candidate),
            expected,
            label="engine runtime config",
            max_bytes=4 * 1024 * 1024,
        )
        try:
            document = strict_json_loads(raw, max_nodes=100_000, max_depth=16)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("engine runtime config is not strict JSON") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "runtimes"}
            or document.get("schema") != ENGINE_RUNTIME_CONFIG_SCHEMA
            or not isinstance(document.get("runtimes"), dict)
            or set(document["runtimes"]) != set(selected)
        ):
            raise ValueError(
                "engine runtime config must contain exactly the selected "
                "third-party framework runtimes"
            )
        selection = parse_engine_runtime_config(
            raw,
            selected_attackers=selected,
        )
        projection = {
            "schema": "ura-builder-selected-engine-runtime-config/1",
            "engines": selected,
            "selection": selection.identity_descriptor(),
        }
        return projection, _condition_sha256(projection), raw, actual

    def _bind_selected_engine_runtime_config_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        _snapshot, digest, _raw, _actual = (
            self._selected_engine_runtime_config_snapshot(params)
        )
        prior = str(params.get("_engine_runtime_config_snapshot_sha256", ""))
        if prior and prior != digest:
            raise ValueError(
                "selected engine runtime config changed after review; "
                "review the lane again"
            )
        bound = {key: str(value) for key, value in params.items()}
        bound["_engine_runtime_config_snapshot_sha256"] = digest
        return bound

    def _source_conformance_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[bytes, str] | None:
        path_value = str(params.get("source_conformance", "")).strip()
        expected = str(params.get("source_conformance_sha", "")).strip().lower()
        if not path_value and not expected:
            return None
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        return self._bounded_content_snapshot(
            str(candidate),
            expected,
            label="source conformance",
            max_bytes=4 * 1024 * 1024,
        )

    def _source_conformance_arm_dispositions(
        self,
        params: Mapping[str, str],
    ) -> dict[str, tuple[str, str]]:
        """Return validated arm dispositions from the exact bound receipt."""

        bound = {key: str(value) for key, value in params.items()}
        for field, env_name in (
            ("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST"),
            ("source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256"),
        ):
            if not bound.get(field, "").strip():
                bound[field] = os.environ.get(env_name, "")
        snapshot = self._source_conformance_snapshot(bound)
        if snapshot is None:
            return {}
        try:
            document = strict_json_loads(
                snapshot[0],
                max_nodes=100_000,
                max_depth=16,
            )
            receipt = validate_source_conformance_manifest(document)
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                "source conformance is not a valid receipt"
            ) from exc
        return {
            str(arm["arm_id"]): (
                str(arm["disposition"]),
                str(arm["reason"]),
            )
            for arm in receipt["arms"]
        }

    def _project_revision_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[bytes, str] | None:
        path_value = str(params.get("project_revision", "")).strip()
        expected = str(params.get("project_revision_sha", "")).strip().lower()
        if not path_value and not expected:
            return None
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        return self._bounded_content_snapshot(
            str(candidate),
            expected,
            label="project revision",
            max_bytes=4 * 1024 * 1024,
        )

    def _capture_execution_config_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, str], dict[str, bytes], str]:
        """Capture deterministic reviewed bytes for every mutable launch input."""

        bound = self._bind_selected_api_config_identity(params)
        bound = self._bind_selected_source_config_identity(bound)
        bound = self._bind_selected_prepared_attacker_identity(bound)
        bound = self._bind_selected_engine_runtime_config_identity(bound)
        components: dict[str, bytes] = {}

        _api_snapshot, _api_digest, _relative, api_configs = (
            self._selected_api_config_snapshot(bound)
        )
        if api_configs:
            components["api_config"] = self._canonical_json_bytes(api_configs)

        _source_snapshot, _source_digest, source_configs = (
            self._selected_source_config_snapshot(bound)
        )
        if source_configs:
            components["source_config"] = self._canonical_json_bytes(source_configs)

        _attacker_snapshot, _attacker_digest, attacker_configs = (
            self._selected_prepared_attacker_snapshot(bound)
        )
        if attacker_configs:
            components["attacker_config"] = self._canonical_json_bytes(
                attacker_configs
            )
            for attacker, path_field, digest_field, max_bytes in (
                (
                    "t3mp3st",
                    "response_artifact",
                    "response_artifact_sha256",
                    256 * 1024 * 1024,
                ),
                (
                    "harmbench",
                    "replay_artifact",
                    "replay_artifact_sha256",
                    64 * 1024 * 1024,
                ),
            ):
                entry = attacker_configs.get(attacker)
                if not isinstance(entry, Mapping) or path_field not in entry:
                    continue
                raw, _actual = self._bounded_content_snapshot(
                    str(entry[path_field]),
                    str(entry.get(digest_field, "")),
                    label=f"prepared {attacker} artifact",
                    max_bytes=max_bytes,
                )
                components[f"attacker_artifact_{attacker}"] = raw
            ideator = attacker_configs.get("ideator")
            if isinstance(ideator, Mapping):
                manifest_path = ideator.get("seed_pair_manifest")
                manifest_sha256 = ideator.get("seed_pair_manifest_sha256")
                if not isinstance(manifest_path, str) or not isinstance(
                    manifest_sha256, str
                ):
                    raise ValueError("prepared IDEATOR manifest identity is incomplete")
                raw_manifest, _manifest_actual = self._bounded_content_snapshot(
                    manifest_path,
                    manifest_sha256,
                    label="prepared IDEATOR seed-pair manifest",
                    max_bytes=4 * 1024 * 1024,
                )
                components["attacker_artifact_ideator"] = raw_manifest
                seed_pairs = ideator.get("seed_pairs")
                if not isinstance(seed_pairs, list):
                    raise ValueError("prepared IDEATOR seed-pair inventory is invalid")
                for index, pair in enumerate(seed_pairs):
                    if not isinstance(pair, Mapping):
                        raise ValueError("prepared IDEATOR seed-pair inventory is invalid")
                    image_path = pair.get("image_path")
                    image_sha256 = pair.get("image_sha256")
                    if not isinstance(image_path, str) or not isinstance(
                        image_sha256, str
                    ):
                        raise ValueError("prepared IDEATOR image identity is incomplete")
                    raw_image, _image_actual = self._bounded_content_snapshot(
                        image_path,
                        image_sha256,
                        label=f"prepared IDEATOR image {index}",
                        max_bytes=25 * 1024 * 1024,
                    )
                    components[
                        f"attacker_artifact_ideator_image_{index:04d}"
                    ] = raw_image

        _engine_snapshot, _engine_digest, engine_raw, engine_actual = (
            self._selected_engine_runtime_config_snapshot(bound)
        )
        if engine_raw is not None:
            components["engine_runtime_config"] = engine_raw
            if engine_actual is None:  # pragma: no cover - tuple invariant
                raise ValueError("engine runtime config lacks a byte identity")
            bound["engine_runtime_config_sha"] = engine_actual

        mode = bound.get("mode", "measured")
        dry = mode == "dry_run" or (
            mode == "diagnostic_canary" and bound.get("canary_dry") == "on"
        )
        local_specs = [] if dry else self._split_list(bound.get("local", ""))
        judge_model = str(bound.get("judge_model", "")).strip()
        if (
            not dry
            and judge_model.startswith(("vllm:", "ollama:"))
            and judge_model not in local_specs
        ):
            local_specs.append(judge_model)
        if local_specs:
            local_payload = self._selected_local_config_payload(
                local_specs,
                default_quantization=str(bound.get("quantization", "")),
                quantization_overrides={
                    key.removeprefix("quantization::"): str(value)
                    for key, value in bound.items()
                    if key.startswith("quantization::")
                },
                require_live_ollama=True,
            )
            _byte_digest, durable_digest = self._local_config_snapshot_digests(
                local_payload,
                local_specs,
            )
            prior = str(bound.get("_local_config_snapshot_sha256", ""))
            if prior and prior != durable_digest:
                raise ValueError(
                    "selected local registry/model changed after review; "
                    "review the lane again"
                )
            bound["_local_config_snapshot_sha256"] = durable_digest
            components["local_config"] = local_payload

        source_conformance = self._source_conformance_snapshot(bound)
        if source_conformance is not None:
            components["source_conformance"] = source_conformance[0]
            bound["source_conformance_sha"] = source_conformance[1]
        project_revision = self._project_revision_snapshot(bound)
        if project_revision is not None:
            components["project_revision"] = project_revision[0]
            bound["project_revision_sha"] = project_revision[1]

        for index in range(1, self._MAX_ATT_ROWS + 1):
            path_value = str(bound.get(f"att_path{index}", "")).strip()
            expected = str(bound.get(f"att_sha{index}", "")).strip().lower()
            if not path_value and not expected:
                continue
            candidate = Path(path_value).expanduser()
            if not candidate.is_absolute():
                candidate = self.repo_root / candidate
            raw, actual = self._bounded_content_snapshot(
                str(candidate),
                expected,
                label=f"live attestation row {index}",
                max_bytes=4 * 1024 * 1024,
            )
            components[f"live_attestation_{index:02d}"] = raw
            bound[f"att_sha{index}"] = actual

        snapshot_sha256 = self._execution_snapshot_digest(bound, components)
        prior_snapshot = str(bound.get("_execution_snapshot_sha256", ""))
        if prior_snapshot and prior_snapshot != snapshot_sha256:
            raise ValueError(
                "selected execution snapshot changed after review; review the lane again"
            )
        bound["_execution_snapshot_sha256"] = snapshot_sha256
        return bound, components, snapshot_sha256

    def _execution_snapshot_digest(
        self,
        params: Mapping[str, str],
        components: Mapping[str, bytes],
    ) -> str:
        allowed_components = {
            "api_config",
            "attacker_config",
            "engine_runtime_config",
            "local_config",
            "project_revision",
            "source_config",
            "source_conformance",
        }
        dynamic_components = {
            name
            for name in components
            if re.fullmatch(
                r"(?:live_attestation_\d{2}|attacker_artifact_(?:t3mp3st|harmbench|ideator)|attacker_artifact_ideator_image_\d{4})",
                name,
            )
        }
        if set(components) - allowed_components - dynamic_components:
            raise ValueError("reviewed execution snapshot has unsupported components")
        component_manifest = {
            name: {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in sorted(components.items())
        }
        manifest = {
            "schema": "ura-builder-execution-snapshot/1",
            "bindings": {
                name: str(params.get(name, "none"))
                for name in (
                    "_api_config_snapshot_sha256",
                    "_attacker_config_snapshot_sha256",
                    "_engine_runtime_config_snapshot_sha256",
                    "_local_config_snapshot_sha256",
                    "_source_config_snapshot_sha256",
                )
            },
            "components": component_manifest,
        }
        return hashlib.sha256(
            self._canonical_json_bytes(manifest)
        ).hexdigest()

    def _validate_execution_snapshot(
        self,
        params: Mapping[str, str],
        components: Mapping[str, bytes],
    ) -> dict[str, bytes]:
        """Validate one controller-held byte snapshot without mutable re-reads."""

        snapshot = {
            str(name): bytes(payload) for name, payload in components.items()
        }
        expected = str(params.get("_execution_snapshot_sha256", "")).strip()
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("reviewed execution snapshot identity is missing")
        actual = self._execution_snapshot_digest(params, snapshot)
        if not secrets.compare_digest(actual, expected):
            raise ValueError("reviewed execution snapshot bytes do not match the ticket")
        return snapshot

    @staticmethod
    def _portable_prepared_attacker_entries(
        entries: Mapping[str, Mapping[str, object]],
    ) -> dict[str, dict[str, object]]:
        portable: dict[str, dict[str, object]] = {}
        for name, raw_entry in entries.items():
            entry = dict(raw_entry)
            if name == "ideator":
                manifest_path = entry.pop("seed_pair_manifest", None)
                manifest_sha256 = entry.get("seed_pair_manifest_sha256")
                if not isinstance(manifest_path, str) or not manifest_path:
                    raise ValueError("prepared IDEATOR manifest path is missing")
                if not isinstance(manifest_sha256, str) or re.fullmatch(
                    r"[0-9a-f]{64}", manifest_sha256
                ) is None:
                    raise ValueError(
                        "prepared IDEATOR manifest lacks an exact content digest"
                    )
                raw_pairs = entry.get("seed_pairs")
                if not isinstance(raw_pairs, list) or not raw_pairs:
                    raise ValueError("prepared IDEATOR seed-pair inventory is invalid")
                pair_limit = entry.get("pair_limit")
                if (
                    isinstance(pair_limit, bool)
                    or not isinstance(pair_limit, int)
                    or not 0 <= pair_limit <= 256
                    or pair_limit > len(raw_pairs)
                ):
                    raise ValueError("prepared IDEATOR pair limit is invalid")
                portable_pairs: list[dict[str, object]] = []
                for index, raw_pair in enumerate(raw_pairs):
                    if not isinstance(raw_pair, Mapping):
                        raise ValueError(
                            "prepared IDEATOR seed-pair inventory is invalid"
                        )
                    pair = dict(raw_pair)
                    path = pair.pop("image_path", None)
                    digest = pair.get("image_sha256")
                    byte_count = pair.get("image_bytes")
                    text = pair.get("text")
                    if (
                        set(pair) != {"text", "image_sha256", "image_bytes"}
                        or not isinstance(path, str)
                        or not path
                        or not isinstance(text, str)
                        or not text.strip()
                        or not isinstance(digest, str)
                        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                        or isinstance(byte_count, bool)
                        or not isinstance(byte_count, int)
                        or byte_count <= 0
                    ):
                        raise ValueError(
                            f"prepared IDEATOR seed-pair {index} is invalid"
                        )
                    portable_pairs.append(pair)
                entry["seed_pairs"] = portable_pairs
            for path_field, digest_field in (
                ("response_artifact", "response_artifact_sha256"),
                ("replay_artifact", "replay_artifact_sha256"),
            ):
                if path_field not in entry:
                    continue
                entry.pop(path_field)
                digest = entry.get(digest_field)
                if not isinstance(digest, str) or re.fullmatch(
                    r"[0-9a-f]{64}", digest
                ) is None:
                    raise ValueError(
                        f"prepared {name} artifact lacks an exact content digest"
                    )
            portable[str(name)] = entry
        return portable

    def _selected_prepared_attacker_snapshot(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, object], str, dict[str, dict[str, object]]]:
        entries = self._prepared_attacker_entries(params)
        snapshot: dict[str, object] = {
            "schema": "ura-builder-selected-attacker-config/1",
            "attackers": self._portable_prepared_attacker_entries(entries),
        }
        return snapshot, _condition_sha256(snapshot), entries

    def _bind_selected_prepared_attacker_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        _snapshot, digest, _entries = self._selected_prepared_attacker_snapshot(params)
        prior = params.get("_attacker_config_snapshot_sha256", "")
        if prior and prior != digest:
            raise ValueError(
                "selected prepared attacker config changed after review; "
                "review the lane again"
            )
        bound = {key: str(value) for key, value in params.items()}
        bound["_attacker_config_snapshot_sha256"] = digest
        return bound

    def _bind_execution_config_bundle_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        """Bind one deterministic digest across every selected config class."""

        fields = (
            "_api_config_snapshot_sha256",
            "_local_config_snapshot_sha256",
            "_source_config_snapshot_sha256",
            "_attacker_config_snapshot_sha256",
            "_engine_runtime_config_snapshot_sha256",
        )
        snapshot = {
            "schema": "ura-builder-selected-execution-config/1",
            "bindings": {field: str(params.get(field, "none")) for field in fields},
            "project_revision_sha256": str(
                params.get("project_revision_sha", "")
            ).lower(),
            "source_conformance_sha256": str(
                params.get("source_conformance_sha", "")
            ).lower(),
            "live_attestation_sha256": [
                str(params.get(f"att_sha{index}", "")).lower()
                for index in range(1, self._MAX_ATT_ROWS + 1)
                if str(params.get(f"att_sha{index}", "")).strip()
            ],
        }
        digest = _condition_sha256(snapshot)
        prior = params.get("_execution_config_bundle_sha256", "")
        if prior and prior != digest:
            raise ValueError(
                "selected execution config changed after review; review the lane again"
            )
        bound = {key: str(value) for key, value in params.items()}
        bound["_execution_config_bundle_sha256"] = digest
        return bound

    def _bind_selected_execution_config_identity(
        self,
        params: Mapping[str, str],
    ) -> dict[str, str]:
        bound = self._bind_selected_api_config_identity(params)
        bound = self._bind_selected_source_config_identity(bound)
        bound = self._bind_selected_prepared_attacker_identity(bound)
        bound = self._bind_selected_engine_runtime_config_identity(bound)
        conformance = self._source_conformance_snapshot(bound)
        if conformance is not None:
            bound["source_conformance_sha"] = conformance[1]
        return bound

    @staticmethod
    def _canonical_json_bytes(value: Any) -> bytes:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    def _materialize_private_config(
        self,
        *,
        payload: bytes,
        directory_name: str,
        filename_prefix: str,
    ) -> tuple[Path, str]:
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.state_dir / directory_name
        if directory.is_symlink():
            raise ValueError(f"private {filename_prefix} directory must not be a symlink")
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"private {filename_prefix} directory must be a directory")
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        path = directory / (
            f"selected-{filename_prefix}-{digest[:24]}-{os.urandom(8).hex()}.json"
        )
        try:
            with path.open("xb") as handle:
                handle.write(payload)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError:
            path.unlink(missing_ok=True)
            raise
        return path, digest

    def _materialize_selected_source_config(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
    ) -> tuple[Path | None, str | None]:
        if snapshot_payload is None:
            _snapshot, digest, configs = self._selected_source_config_snapshot(params)
            if params.get("_source_config_snapshot_sha256", "") != digest:
                raise ValueError(
                    "selected source registry/config changed after review; "
                    "review the lane again"
                )
            if not configs:
                return None, None
            payload = self._canonical_json_bytes(configs)
        else:
            payload = bytes(snapshot_payload)
        try:
            snapshot_configs = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("reviewed source config snapshot is invalid") from exc
        selected = self._split_list(params.get("corpora", ""))
        if (
            params.get("mode") == "diagnostic_canary"
            and params.get("canary_dry") == "on"
        ):
            selected = ["synth"]
        if (
            not isinstance(snapshot_configs, dict)
            or set(snapshot_configs) != set(selected)
            or payload != self._canonical_json_bytes(snapshot_configs)
        ):
            raise ValueError("reviewed source config snapshot no longer matches selection")
        for arm, config in snapshot_configs.items():
            if not isinstance(config, dict):
                raise ValueError("reviewed source config snapshot contains an invalid arm")
            synthetic = config.get("synth") is True
            if arm == "synth":
                if not synthetic or config.get("converter") != "synth":
                    raise ValueError("reviewed synth arm is not the exact synthetic fixture")
            elif synthetic or config.get("converter") == "synth":
                raise ValueError(f"real source arm {arm!r} cannot be synthetic")
        return self._materialize_private_config(
            payload=payload,
            directory_name=".private-source-configs",
            filename_prefix="source",
        )

    def _materialize_selected_engine_runtime_config(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
    ) -> tuple[Path | None, str | None]:
        """Create one ticket-bound, read-once explicit-venv config."""

        selected = sorted(
            set(self._split_list(str(params.get("attackers", ""))))
            & RUNTIME_REQUIRED_ATTACKERS
        )
        expected = str(params.get("engine_runtime_config_sha", "")).strip().lower()
        if not selected:
            if snapshot_payload is not None:
                raise ValueError(
                    "reviewed engine runtime config exists without a selected runtime"
                )
            return None, None
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("engine runtime config requires an exact SHA-256")
        if snapshot_payload is None:
            _snapshot, digest, raw, actual = (
                self._selected_engine_runtime_config_snapshot(params)
            )
            if raw is None or actual is None:  # pragma: no cover - selection invariant
                raise ValueError("selected engine runtime config is missing")
            payload = raw
        else:
            payload = bytes(snapshot_payload)
            actual = hashlib.sha256(payload).hexdigest()
            if not payload or len(payload) > 4 * 1024 * 1024 or actual != expected:
                raise ValueError(
                    "reviewed engine runtime config bytes do not match the ticket"
                )
            try:
                document = strict_json_loads(
                    payload,
                    max_nodes=100_000,
                    max_depth=16,
                )
            except (UnicodeError, ValueError) as exc:
                raise ValueError("reviewed engine runtime config is invalid") from exc
            if (
                not isinstance(document, dict)
                or set(document) != {"schema", "runtimes"}
                or document.get("schema") != ENGINE_RUNTIME_CONFIG_SCHEMA
                or not isinstance(document.get("runtimes"), dict)
                or set(document["runtimes"]) != set(selected)
            ):
                raise ValueError(
                    "reviewed engine runtime config no longer matches selection"
                )
            selection = parse_engine_runtime_config(
                payload,
                selected_attackers=selected,
            )
            projection = {
                "schema": "ura-builder-selected-engine-runtime-config/1",
                "engines": selected,
                "selection": selection.identity_descriptor(),
            }
            digest = _condition_sha256(projection)
        if actual != expected:
            raise ValueError("engine runtime config SHA-256 no longer matches")
        if str(params.get("_engine_runtime_config_snapshot_sha256", "")) != digest:
            raise ValueError(
                "selected engine runtime config changed after review; "
                "review the lane again"
            )
        path, materialized_digest = self._materialize_private_config(
            payload=payload,
            directory_name=".private-engine-runtime-configs",
            filename_prefix="engine-runtime",
        )
        if materialized_digest != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError("engine runtime config digest changed while materializing")
        return path, materialized_digest

    def _materialize_selected_source_conformance(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
    ) -> tuple[Path | None, str | None]:
        expected = str(params.get("source_conformance_sha", "")).strip().lower()
        if snapshot_payload is None:
            snapshot = self._source_conformance_snapshot(params)
            if snapshot is None:
                return None, None
            raw, expected = snapshot
        else:
            raw = bytes(snapshot_payload)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("reviewed source conformance snapshot no longer matches")
        path, actual = self._materialize_private_config(
            payload=raw,
            directory_name=".private-source-conformance",
            filename_prefix="source-conformance",
        )
        if actual != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError("source conformance snapshot digest changed")
        return path, actual

    def _materialize_selected_project_revision(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
    ) -> tuple[Path | None, str | None]:
        expected = str(params.get("project_revision_sha", "")).strip().lower()
        if snapshot_payload is None:
            snapshot = self._project_revision_snapshot(params)
            if snapshot is None:
                return None, None
            raw, expected = snapshot
        else:
            raw = bytes(snapshot_payload)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("reviewed project revision snapshot no longer matches")
        path, actual = self._materialize_private_config(
            payload=raw,
            directory_name=".private-project-revision",
            filename_prefix="project-revision",
        )
        if actual != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError("project revision snapshot digest changed")
        return path, actual

    def _materialize_selected_live_attestations(
        self,
        params: Mapping[str, str],
        *,
        execution_snapshot: Mapping[str, bytes] | None = None,
    ) -> list[tuple[Path, str]]:
        materialized: list[tuple[Path, str]] = []
        snapshot = dict(execution_snapshot or {})
        try:
            for index in range(1, self._MAX_ATT_ROWS + 1):
                path_value = str(params.get(f"att_path{index}", "")).strip()
                expected = str(params.get(f"att_sha{index}", "")).strip().lower()
                if not path_value and not expected:
                    continue
                key = f"live_attestation_{index:02d}"
                payload = snapshot.get(key)
                if payload is None:
                    candidate = Path(path_value).expanduser()
                    if not candidate.is_absolute():
                        candidate = self.repo_root / candidate
                    payload, _actual = self._bounded_content_snapshot(
                        str(candidate),
                        expected,
                        label=f"live attestation row {index}",
                        max_bytes=4 * 1024 * 1024,
                    )
                if hashlib.sha256(payload).hexdigest() != expected:
                    raise ValueError(
                        f"reviewed live attestation row {index} no longer matches"
                    )
                path, actual = self._materialize_private_config(
                    payload=bytes(payload),
                    directory_name=".private-live-attestations",
                    filename_prefix=f"live-attestation-{index:02d}",
                )
                materialized.append((path, actual))
        except BaseException:
            for path, _digest in materialized:
                path.unlink(missing_ok=True)
            raise
        return materialized

    def _selected_api_registry_relative_path(
        self,
        params: Mapping[str, str],
    ) -> str:
        """Return the exact registry path already covered by the bound snapshot."""

        _snapshot, digest, relative, _configs = (
            self._selected_api_config_snapshot(params)
        )
        if params.get("_api_config_snapshot_sha256", "") != digest:
            raise ValueError(
                "selected API registry/config changed after review; review the lane again"
            )
        return relative

    def _materialize_selected_api_config(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
    ) -> tuple[Path | None, str | None]:
        """Create one private read-once config containing selected routes only."""

        if snapshot_payload is None:
            _snapshot, digest, _relative, configs = (
                self._selected_api_config_snapshot(params)
            )
            if params.get("_api_config_snapshot_sha256", "") != digest:
                raise ValueError(
                    "selected API registry/config changed after review; review the lane again"
                )
            if not configs:
                return None, None
            payload = self._canonical_json_bytes(configs)
        else:
            payload = bytes(snapshot_payload)
        try:
            snapshot_configs = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("reviewed API config snapshot is invalid") from exc
        selected = self._split_list(params.get("api", ""))
        judges = self._split_list(params.get("judges", ""))
        judge_model = str(params.get("judge_model", "")).strip()
        if (
            "llm" in judges
            and judge_model
            and judge_model != "mock"
            and not judge_model.startswith(("vllm:", "ollama:"))
            and judge_model not in selected
        ):
            selected.append(judge_model)
        expected_configured = {
            spec for spec in selected if api_target_requires_config(spec)
        }
        if (
            not isinstance(snapshot_configs, dict)
            or set(snapshot_configs) != expected_configured
            or payload != self._canonical_json_bytes(snapshot_configs)
        ):
            raise ValueError("reviewed API config snapshot no longer matches selection")
        for spec, entry in snapshot_configs.items():
            if not isinstance(entry, dict):
                raise ValueError("reviewed API config snapshot contains an invalid route")
            normalized = normalize_api_target_config(spec, entry)
            if normalized != entry:
                raise ValueError("reviewed API config snapshot is not normalized")
            build_api_target(spec, config=normalized)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        directory = self.state_dir / ".private-api-configs"
        if directory.is_symlink():
            raise ValueError("private API-config directory must not be a symlink")
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("private API-config directory must be a directory")
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        path = directory / (
            f"selected-api-{payload_sha256[:24]}-{os.urandom(8).hex()}.json"
        )
        try:
            with path.open("xb") as handle:
                handle.write(payload)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError:
            path.unlink(missing_ok=True)
            raise
        return path, payload_sha256

    def _preflight_output_dir(self, params: Mapping[str, str]) -> Path:
        """Dedicated no-call output, separate from the measured run tree."""

        normalized = self._projection_params(params)
        condition = hashlib.sha256(
            json.dumps(
                normalized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()[:16]
        return self.results_root / "preflight" / f"builder-{condition}"

    def _validate_builder(self, params: Mapping[str, str]) -> dict[str, str]:
        """Mode-specific builder validation, keyed by form field.

        Mirrors the run_matrix admission gates so an invalid lane is rejected
        with a field-level explanation BEFORE any subprocess exists.  The CLI
        gates remain authoritative; this never weakens them.
        """

        errors: dict[str, str] = {}
        mode = params.get("mode", "measured")
        canary_dry = mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        api = self._split_list(params.get("api", ""))
        local = self._split_list(params.get("local", ""))
        corpora = self._split_list(params.get("corpora", ""))
        attackers = self._split_list(params.get("attackers", ""))
        judges_list = self._split_list(params.get("judges", ""))
        approximate_common_metrics = params.get("approximate_common_metrics", "")
        if approximate_common_metrics not in {"", "on"}:
            errors["approximate_common_metrics"] = (
                "the approximate-metrics opt-in must be an explicit checkbox"
            )
        approximate_common_metrics_enabled = approximate_common_metrics == "on"
        seeds = self._split_list(params.get("seeds", "") or "0")
        targets = len(api) + len(local)
        real_corpora = [arm for arm in corpora if arm != "synth"]
        att_rows: list[tuple[str, str]] = []
        for index in range(1, self._MAX_ATT_ROWS + 1):
            path = params.get(f"att_path{index}", "")
            sha = params.get(f"att_sha{index}", "")
            if path or sha:
                att_rows.append((path, sha))

        allowed_modes = {token for token, _flag, _desc in _BUILD_MODES}
        if mode not in allowed_modes:
            errors["mode"] = "select a supported execution mode"

        def reject_duplicates(field: str, values: list[str]) -> None:
            duplicates = sorted(value for value in set(values) if values.count(value) > 1)
            if duplicates:
                errors[field] = "entries must be unique; duplicates: " + ", ".join(duplicates)

        reject_duplicates("models", [*api, *local])
        reject_duplicates("corpora", corpora)
        reject_duplicates("attackers", attackers)
        reject_duplicates("judges", judges_list)
        harm_requirements: tuple[str, int, int, int] | None = None
        ideator_requirements: tuple[int, int] | None = None

        known_arms = {arm for arm, _mods, _reason in _ARM_CATALOG} | {"synth"}
        unknown_arms = sorted(set(corpora) - known_arms)
        if unknown_arms:
            errors["corpora"] = "unknown corpus arm(s): " + ", ".join(unknown_arms)
        unknown_attackers = sorted(set(attackers) - set(_ATTACKER_NAMES))
        if unknown_attackers:
            errors["attackers"] = "unknown attack framework(s): " + ", ".join(unknown_attackers)
        # Precomputed-only adapters without a Builder input for their required
        # prepared config remain rejected before any subprocess. IDEATOR is not
        # in this map because its verified manifest panel is handled below.
        for attacker in attackers:
            reason = _CLI_ONLY_ATTACKERS.get(attacker)
            if reason:
                errors["attackers"] = reason
                break
        # Judge the corpora the lane will actually run: a dry canary is
        # composed as --corpora synth regardless of the arm checkboxes (and
        # needs none), so it can never carry a source-restricted adapter.
        effective_corpora = ["synth"] if canary_dry else corpora
        for attacker in attackers:
            restriction = _SOURCE_RESTRICTED_ATTACKERS.get(attacker)
            if restriction is None:
                continue
            prefix, reason = restriction
            if not effective_corpora or any(
                not arm.startswith(prefix) for arm in effective_corpora
            ):
                errors.setdefault("attackers", reason)
        for attacker, error_field in (
            ("t3mp3st", "t3_replay"),
            ("harmbench", "harm_replay"),
            ("ideator", "ideator"),
            ("nanogcg", "nanogcg"),
        ):
            if attacker not in attackers:
                continue
            try:
                prepared = self._prepared_attacker_entries(
                    {**params, "attackers": attacker}
                )
                if attacker == "harmbench":
                    harm_requirements = self._harmbench_replay_requirements(params)
                elif attacker == "ideator":
                    ideator = prepared.get("ideator")
                    if not isinstance(ideator, Mapping):  # pragma: no cover - invariant
                        raise ValueError("prepared IDEATOR configuration is missing")
                    raw_pairs = ideator.get("seed_pairs")
                    pair_limit = ideator.get("pair_limit")
                    if not isinstance(raw_pairs, list) or not isinstance(pair_limit, int):
                        raise ValueError("prepared IDEATOR pair inventory is invalid")
                    ideator_requirements = (
                        len(raw_pairs),
                        len(raw_pairs) if pair_limit == 0 else pair_limit,
                    )
            except ValueError as exc:
                errors[error_field] = str(exc)
        unknown_judges = sorted(set(judges_list) - {"rules", "llm", "guardrail"})
        if unknown_judges:
            errors["judges"] = "unknown judge(s): " + ", ".join(unknown_judges)
        if params.get("defense", "none") not in {"none", "input", "output", "both"}:
            errors["defense"] = "select none, input, output, or both"
        if params.get("defense_guard", "rules") not in {"rules", "guardrail"}:
            errors["defense_guard"] = "select rules or guardrail"
        if params.get("dtype", "") not in {"", "auto", "bfloat16", "float16"}:
            errors["dtype"] = "select auto, bfloat16, or float16"

        model_options = self._model_options()
        target_mods = {(kind, value): set(mods) for value, _label, mods, kind in model_options}
        option_kind = {value: kind for value, _label, _mods, kind in model_options}
        local_options = {
            value for value, _label, _mods, kind in model_options if kind == "local"
        }
        api_catalog = self._load_registry(
            "api-targets.json", "rig/api-targets.example.json"
        )
        try:
            self._bind_selected_api_config_identity(params)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            errors["models"] = str(exc)
        try:
            self._bind_selected_source_config_identity(params)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            errors["corpora"] = str(exc)
        try:
            self._bind_selected_engine_runtime_config_identity(params)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            errors["engine_runtime_config"] = str(exc)
        local_catalog, _configured_local = self._local_entry_catalog()
        if "nanogcg" in attackers:
            if (
                params.get("nanogcg_model_id", "").strip()
                or params.get("nanogcg_model_revision", "").strip()
            ):
                errors["nanogcg"] = LIVE_NANOGCG_DISABLED_MESSAGE
            elif not params.get("nanogcg_suffix", "").strip():
                errors["nanogcg"] = (
                    "NanoGCG requires an exact precomputed suffix replay; "
                    + LIVE_NANOGCG_DISABLED_MESSAGE
                )
        hosted_identity_conditions = []
        for spec in api:
            selected_config = (
                api_catalog.get(spec)
                if isinstance(api_catalog.get(spec), Mapping)
                else None
            )
            identity = _hosted_model_identity(spec, selected_config)
            if identity is not None:
                hosted_identity_conditions.append((
                    identity,
                    _hosted_target_condition(spec, selected_config),
                ))
        hosted_target_identities = [
            identity for identity, _condition in hosted_identity_conditions
        ]
        seen_hosted_identity_keys: set[tuple[tuple[str, ...], str]] = set()
        duplicate_hosted_identity = False
        for identity_keys, condition in hosted_identity_conditions:
            condition_keys = {(identity, condition) for identity in identity_keys}
            if seen_hosted_identity_keys & condition_keys:
                duplicate_hosted_identity = True
            seen_hosted_identity_keys.update(condition_keys)
        if duplicate_hosted_identity:
            errors["models"] = (
                "hosted targets must be unique after provider-alias resolution "
                "and hosted-route identity resolution, including endpoint identity "
                "resolution"
            )
        local_identity_conditions = []
        for spec in local:
            entry = local_catalog.get(spec, {})
            identity = _local_model_identity(spec, entry)
            if identity is None:
                continue
            local_identity_conditions.append((
                identity,
                _local_target_condition(
                    spec,
                    entry,
                    quantization=(
                        params.get(f"quantization::{spec}", "").strip().lower()
                        or str(entry.get("quantization") or "")
                        or params.get("quantization", "").strip().lower()
                    ),
                    dtype=params.get("dtype", "").strip().lower(),
                ),
            ))
        local_target_identities = [
            identity for identity, _condition in local_identity_conditions
        ]
        if len(local_identity_conditions) != len(set(local_identity_conditions)):
            errors["models"] = (
                "local targets must be unique after immutable content-identity and "
                "execution-condition resolution"
            )
        precision_specs = {
            key.removeprefix("quantization::")
            for key in params
            if key.startswith("quantization::")
        }
        if precision_specs - local_options:
            errors["models"] = (
                "the request contains a per-model precision field for an "
                "unknown local model"
            )
        unknown_api = sorted(value for value in api if ("api", value) not in target_mods)
        unknown_local = sorted(value for value in local if ("local", value) not in target_mods)
        if unknown_api or unknown_local:
            details = []
            if unknown_api:
                details.append("hosted: " + ", ".join(unknown_api))
            if unknown_local:
                details.append("local: " + ", ".join(unknown_local))
            errors["models"] = "unknown target selection(s): " + "; ".join(details)
        if "ideator" in attackers:
            text_only_targets = [
                target
                for kind, target in (
                    [("api", value) for value in api]
                    + [("local", value) for value in local]
                )
                if (mods := target_mods.get((kind, target))) is not None
                and "image" not in mods
            ]
            if text_only_targets:
                errors["models"] = (
                    "IDEATOR seed-pair replay requires an image-capable target: "
                    + ", ".join(text_only_targets)
                )
        live_llm_judge = "llm" in judges_list and mode != "dry_run" and not canary_dry
        judge_model = params.get("judge_model", "").strip()
        judge_kind = option_kind.get(judge_model)
        hosted_judge_selected = live_llm_judge and judge_kind == "api"
        transfer_ack = params.get("ack_hosted_judge_data_transfer", "")
        if transfer_ack not in {"", "on"}:
            errors["ack_hosted_judge_data_transfer"] = (
                "the hosted-judge data-transfer acknowledgement must be an "
                "explicit checkbox"
            )
        elif hosted_judge_selected and transfer_ack != "on":
            errors["ack_hosted_judge_data_transfer"] = (
                "required: acknowledge that target responses and source/reference "
                "context may be sent to the selected hosted judge provider and "
                "handled under its retention terms"
            )
        elif not hosted_judge_selected and transfer_ack == "on":
            errors["ack_hosted_judge_data_transfer"] = (
                "this acknowledgement applies only to a live hosted LLM judge"
            )
        if judge_model and judge_model != "mock" and judge_kind is None:
            errors["judge_model"] = "unknown LLM judge model selection"
        elif judge_model and "llm" not in judges_list:
            errors["judge_model"] = (
                "the selected LLM judge model requires enabling the llm judge stage"
            )
        if live_llm_judge:
            if not judge_model:
                errors["judge_model"] = "choose an explicit hosted or local LLM judge model"
            elif judge_model == "mock":
                if real_corpora:
                    errors["judge_model"] = (
                        "a real-source live lane cannot use the mock LLM judge"
                    )
            elif judge_kind is None:
                errors.setdefault("judge_model", "unknown LLM judge model selection")
            elif judge_model in {*api, *local}:
                errors["judge_model"] = (
                    "the LLM judge must differ from every target model"
                )
            elif (
                judge_kind == "api"
                and (
                    judge_identity := _hosted_model_identity(
                        judge_model,
                        api_catalog.get(judge_model)
                        if isinstance(api_catalog.get(judge_model), Mapping)
                        else None,
                    )
                ) is not None
                and any(
                    judge_identity & target_identity
                    for target_identity in hosted_target_identities
                )
            ):
                errors["judge_model"] = (
                    "the LLM judge must differ from every target model after "
                    "provider-alias resolution and hosted-route identity resolution, "
                    "including endpoint identity resolution"
                )
            elif (
                judge_kind == "local"
                and (
                    judge_identity := _local_model_identity(
                        judge_model, local_catalog.get(judge_model, {})
                    )
                ) is not None
                and judge_identity in set(local_target_identities)
            ):
                errors["judge_model"] = (
                    "the LLM judge must differ from every target model after "
                    "immutable content-identity resolution"
                )
            elif (
                judge_kind == "local"
                and local
                and (
                    mode not in {
                        "attestation_probe",
                        "diagnostic_canary",
                        "measured",
                    }
                    or canary_dry
                    or "crescendo" in {name.lower() for name in attackers}
                )
            ):
                errors["judge_model"] = (
                    "a local target and a distinct local LLM judge require a "
                    "response-independent live probe, canary, or measured lane "
                    "so Runner can release the target before loading the judge"
                )
            else:
                durable_local_identities = self._catalog_local_identities()
                durable_judge = durable_local_identities.get(
                    judge_model,
                    judge_model,
                )
                durable_targets = {
                    durable_local_identities.get(spec, spec)
                    for spec in (*api, *local)
                }
                if durable_judge in durable_targets:
                    errors["judge_model"] = (
                        "the LLM judge must differ from every target model "
                        "after content-identity resolution"
                    )
        local_judge = (
            judge_model
            if live_llm_judge and judge_kind == "local" and judge_model not in local
            else ""
        )
        local_execution_specs = [*local, *([local_judge] if local_judge else [])]
        if (
            local_execution_specs
            and mode != "dry_run"
            and not canary_dry
            and not unknown_local
        ):
            from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

            catalog = local_catalog
            local_error_field = "judge_model" if local_judge and not local else "models"
            unknown_fit_without_precision = []
            incompatible = []
            for spec in local_execution_specs:
                entry = catalog.get(spec, {})
                if spec.startswith("ollama:"):
                    try:
                        self._validate_ollama_local_entry(spec, entry)
                    except ValueError as exc:
                        errors.setdefault(local_error_field, str(exc))
                    continue
                if not spec.startswith("vllm:"):
                    continue
                try:
                    self._validated_local_modalities(
                        spec, entry, project_richer=True
                    )
                    self._local_gpu_memory_utilization(spec, entry)
                    max_model_len = self._local_max_model_len(spec, entry)
                    max_tokens = self._local_max_tokens(spec, entry)
                    self._local_request_timeout(spec, entry)
                    fit = self._effective_local_profile(
                        spec,
                        entry,
                        default_quantization=params.get("quantization", ""),
                        model_quantization=params.get(f"quantization::{spec}", ""),
                    ).get("fits")
                except ValueError as exc:
                    errors.setdefault(local_error_field, str(exc))
                    continue
                if (
                    max_model_len is not None
                    and max_model_len > 0
                    and max_tokens is not None
                    and max_tokens > max_model_len
                ):
                    errors.setdefault(
                        local_error_field,
                        f"local target {spec!r} max_tokens must not exceed "
                        "max_model_len",
                    )
                    continue
                model_quantization = str(params.get(f"quantization::{spec}", "")).strip().lower()
                if fit is None:
                    if model_quantization in {"", "auto"}:
                        unknown_fit_without_precision.append(spec)
                elif fit is False:
                    incompatible.append(spec)
            if incompatible:
                errors.setdefault(
                    local_error_field,
                    "live local target is known incompatible with this "
                    "hardware: " + ", ".join(incompatible),
                )
            elif unknown_fit_without_precision:
                errors.setdefault(
                    local_error_field,
                    "live local target hardware fit is unknown; choose an "
                    "explicit per-model precision before running: "
                    + ", ".join(unknown_fit_without_precision),
                )
            unpinned = []
            for spec in local_execution_specs:
                entry = catalog.get(spec, {})
                revision = entry.get("revision")
                digest = entry.get("digest")
                revision_ok = (
                    isinstance(revision, str)
                    and re.fullmatch(
                        r"[0-9a-fA-F]{40,64}",
                        revision,
                    )
                    is not None
                )
                digest_ok = (
                    isinstance(digest, str)
                    and re.fullmatch(
                        r"[0-9a-fA-F]{64}",
                        digest,
                    )
                    is not None
                )
                backend, _separator, model = spec.partition(":")
                digest_identity = backend.lower() == "ollama" or (
                    backend.lower() == "vllm" and _is_explicit_local_path(model)
                )
                identity_ok = (
                    digest_ok and not revision if digest_identity else revision_ok and not digest
                )
                if not identity_ok:
                    unpinned.append(spec)
            if unpinned:
                errors.setdefault(
                    local_error_field,
                    "live hub vLLM targets require a 40-64 hex revision; "
                    "explicit local checkpoints and Ollama targets require a "
                    "64-hex digest: " + ", ".join(unpinned),
                )

        def require_int(field: str, *, positive: bool = False) -> int | None:
            raw = params.get(field, "")
            if not raw:
                return None
            try:
                value = int(raw)
            except ValueError:
                errors[field] = "must be an integer"
                return None
            if positive and value <= 0:
                errors[field] = "must be a positive integer"
                return None
            return value

        limit = require_int("limit")
        if limit is not None and limit < 0:
            errors["limit"] = "must be non-negative"
        group_raw = params.get("group", "")
        if group_raw:
            from experiments.run_matrix import _ALLOWED_GROUP_KEYS  # noqa: PLC0415

            group_keys = self._split_list(group_raw)
            unknown_group_keys = sorted(set(group_keys) - set(_ALLOWED_GROUP_KEYS))
            if not group_keys:
                errors["group"] = "must name at least one aggregation group key"
            elif len(set(group_keys)) != len(group_keys):
                errors["group"] = "group keys must be unique"
            elif unknown_group_keys:
                errors["group"] = (
                    "unsupported group key(s): "
                    + ", ".join(unknown_group_keys)
                    + "; allowed: "
                    + ", ".join(sorted(_ALLOWED_GROUP_KEYS))
                )
        if params.get("exclude_tool_conditioned", "") not in {"", "on"}:
            errors["exclude_tool_conditioned"] = (
                "the tool-conditioned exclusion must be an explicit checkbox"
            )
        elif (
            params.get("exclude_tool_conditioned") == "on"
            and mode != "dry_run"
        ):
            errors["exclude_tool_conditioned"] = (
                "tool-conditioned row exclusion is available only for a "
                "standalone dry run; probes, canaries, preflights, and measured "
                "lanes must retain every selected cluster row"
            )
        if params.get("verify_model_sha256", "") not in {"", "on"}:
            errors["verify_model_sha256"] = "full model SHA verification must be an explicit checkbox"
        reset_open_circuits = params.get("reset_open_circuits", "")
        if reset_open_circuits not in {"", "on"}:
            errors["reset_open_circuits"] = (
                "the open-circuit reset must be an explicit checkbox"
            )
        elif reset_open_circuits == "on" and mode != "measured":
            errors["reset_open_circuits"] = (
                "clearing open circuits is a measured-lane resume control "
                "(rerun the identical measured command after correcting the "
                "root cause); it is not available for dry runs, probes, or "
                "canaries"
            )
        require_int("lock_stale_seconds", positive=True)
        sample_seed_value = require_int("sample_seed")
        sampling_policy = params.get("sampling_policy", "")
        if sampling_policy and sampling_policy not in SAMPLING_POLICIES:
            errors["sampling_policy"] = (
                "must be one of the supported sampling policies"
            )
        max_queries_value = require_int("max_queries", positive=True)
        max_turns_value = require_int("max_turns", positive=True)
        target_answer_retries = require_int("target_answer_retries")
        if target_answer_retries is not None and not 0 <= target_answer_retries <= 10:
            errors["target_answer_retries"] = "must be an integer in [0, 10]"
        elif (
            target_answer_retries is not None
            and target_answer_retries != 0
            and api
        ):
            errors["target_answer_retries"] = (
                "paid hosted targets allow no answer-quality retries; set "
                "additional answer retries to 0"
            )
        if ideator_requirements is not None:
            available_pairs, selected_pairs = ideator_requirements
            effective_max_queries = 4 if max_queries_value is None else max_queries_value
            effective_max_turns = 4 if max_turns_value is None else max_turns_value
            if effective_max_queries < selected_pairs:
                errors["max_queries"] = (
                    f"IDEATOR selects {selected_pairs} of {available_pairs} verified "
                    "pairs; --max-queries must cover every selected pair"
                )
            if effective_max_turns < selected_pairs:
                errors["max_turns"] = (
                    f"IDEATOR selects {selected_pairs} of {available_pairs} verified "
                    "pairs; --max-turns must cover every selected pair"
                )
        local_budget_raw = params.get("local_budget_hours", "")
        require_int("local_budget_hours", positive=True)
        if local_budget_raw:
            if mode != "measured" or not local or api or hosted_judge_selected:
                errors["local_budget_hours"] = (
                    "the local process wall-time cap applies only to a measured "
                    "all-local lane with a local target and no hosted target or judge"
                )
        if harm_requirements is not None:
            captured_corpus, captured_limit, captured_seed, minimum = harm_requirements
            if corpora != [captured_corpus]:
                errors["corpora"] = (
                    "HarmBench replay requires exactly its captured corpus arm: " + captured_corpus
                )
            if limit != captured_limit:
                errors["limit"] = f"HarmBench replay requires its captured limit {captured_limit}"
            effective_seed = 0 if sample_seed_value is None else sample_seed_value
            if effective_seed != captured_seed:
                errors["sample_seed"] = (
                    f"HarmBench replay requires its captured sample seed {captured_seed}"
                )
            if max_queries_value is None or max_queries_value < minimum:
                errors["max_queries"] = (
                    f"HarmBench replay requires at least {minimum} queries "
                    "(methods x cases per method)"
                )
            if max_turns_value is None or max_turns_value < minimum:
                errors["max_turns"] = (
                    f"HarmBench replay requires at least {minimum} turns "
                    "(methods x cases per method)"
                )

        raw_seeds = params.get("seeds", "")
        if raw_seeds:
            seed_parts = self._split_list(raw_seeds)
            if not all(re.fullmatch(r"-?\d+", part) for part in seed_parts):
                errors["seeds"] = "must be a comma list of integers"
            elif len(set(seed_parts)) != len(seed_parts):
                errors["seeds"] = "seeds must be unique"
        scope_value = params.get("scope", "")
        if scope_value and re.search(r"\s", scope_value):
            errors["scope"] = "must not contain whitespace"

        def require_hex(field: str) -> None:
            raw = params.get(field, "")
            if raw and not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
                errors[field] = "must be an exact 64-hex SHA-256"

        require_hex("project_revision_sha")
        require_hex("source_conformance_sha")

        def env_or(field: str, env_name: str) -> bool:
            return bool(params.get(field, "") or os.environ.get(env_name, ""))

        has_project = env_or("project_revision", "URA_PROJECT_REVISION_MANIFEST") and env_or(
            "project_revision_sha", "URA_PROJECT_REVISION_SHA256"
        )
        has_source = env_or("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST") and env_or(
            "source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256"
        )

        def forbid_live_fields(reason: str) -> None:
            if params.get("scope", ""):
                errors["scope"] = reason
            if params.get("max_age", ""):
                errors["max_age"] = reason
            if att_rows:
                errors["att"] = reason

        def require_caps_and_deadline() -> None:
            for cap in ("cap_target", "cap_judge", "cap_http", "deadline"):
                value = require_int(cap, positive=True)
                if value is None and cap not in errors:
                    errors[cap] = "required: a finite positive ceiling before any non-dry run"

        def require_live_admission() -> None:
            if not params.get("scope", ""):
                errors["scope"] = "required for live execution"
            age = params.get("max_age", "")
            try:
                age_value = float(age) if age else 0.0
            except ValueError:
                age_value = 0.0
            if not 0 < age_value <= 8760:
                errors["max_age"] = "required: maximum attestation age in hours, in (0, 8760]"
            if not att_rows:
                errors["att"] = "at least one live-attestation receipt/digest pair is required"
            if not has_project:
                errors["project_revision"] = (
                    "required: validated project-revision receipt and digest "
                    "(field or campaign environment)"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = (
                    "required: validated source-conformance receipt and digest for real source arms"
                )
            require_caps_and_deadline()

        for path, sha in att_rows:
            if not path or not sha:
                errors["att"] = (
                    "every receipt row needs both the receipt path and its exact 64-hex digest"
                )
            elif not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                errors["att"] = "receipt digest must be an exact 64-hex SHA-256"

        if not params.get("out", ""):
            errors["out"] = "required: output directory for this run"
        if not corpora and not canary_dry:
            # A dry canary composes the synthetic corpus itself, so it needs
            # no arm checkbox; every other lane must select at least one arm.
            errors["corpora"] = "select at least one corpus arm"
        if not attackers:
            errors["attackers"] = "select at least one attack framework"
        if not judges_list:
            errors["judges"] = "select at least one judge"
        if len(local) > 1:
            errors.setdefault("models", (
                "one local target per process (vLLM/Ollama engines must not "
                "accumulate on the rig GPUs)"
            ))

        # -- exact modality + agentic + guardrail-separation admission --------
        # Server-side and complete: a target/attacker must serve EVERY modality
        # an arm carries (not merely share one), agentic arms are rejected, and
        # the scoring and defense guardrails must be distinct identities.  This
        # is the real gate; the client-side filter is only convenience.
        # Native-only attackers cannot be replayed through the common Runner
        # (run_matrix rejects them); reject before any subprocess with the real
        # action rather than letting the CLI fail after launch.
        native_selected = [a for a in attackers if a in _NATIVE_ONLY_ATTACKERS]
        if native_selected:
            errors["attackers"] = (
                f"{', '.join(native_selected)} "
                + ("is a" if len(native_selected) == 1 else "are")
                + " native-artifact integration(s); run_matrix cannot replay "
                "them through the common Runner. Import their native traces "
                "with the native_import command instead"
            )
        arm_mods = {arm: set(mods) for arm, mods, _r in _ARM_CATALOG}
        fw_mods = {fw: set(mods) for fw, _d, mods in _FRAMEWORKS}
        try:
            source_dispositions = self._source_conformance_arm_dispositions(params)
        except ValueError:
            # The Runner remains the authority for an invalid receipt. Do not
            # infer a disposition from bytes that failed exact validation.
            source_dispositions = {}
        for arm in real_corpora:
            disposition = source_dispositions.get(arm)
            if disposition is not None and disposition[0] == "blocked":
                errors["corpora"] = (
                    f"arm {arm} is blocked by the bound source receipt: "
                    f"{disposition[1]}"
                )
                continue
            if arm in _INELIGIBLE_ARMS:
                if not approximate_common_metrics_enabled:
                    errors["approximate_common_metrics"] = (
                        f"{arm} is common-metric-ineligible: "
                        f"{_INELIGIBLE_REASONS[arm]} Select the explicit "
                        "approximate common-security metrics opt-in to run "
                        "separate response proxies."
                    )
                    continue
            if arm in _SOURCE_METRIC_ARMS:
                metric, allowed = _SOURCE_METRIC_ARMS[arm]
                unsupported = [a for a in attackers if a not in allowed]
                if unsupported:
                    errors["attackers"] = (
                        f"arm {arm} is scored only by the implemented "
                        f"'{metric}' source metric, which run_matrix admits "
                        f"solely for the {'/'.join(allowed)} attacker; remove "
                        f"{', '.join(unsupported)} or the grid contains "
                        "unscored cells"
                    )
            needed = arm_mods.get(arm)
            if needed is None:
                continue  # unknown arm id: left to the CLI's own registry check
            if "tool" in needed:
                errors["corpora"] = (
                    f"arm {arm} converts to a text+tool source construct, but "
                    "the maintained Runner targets do not declare executable "
                    "tool-environment support. The approximate response-proxy "
                    "route therefore remains fail-closed; use a validated native "
                    "tool runtime/import instead"
                )
                continue
            for kind, target in [("api", value) for value in api] + [
                ("local", value) for value in local
            ]:
                have = target_mods.get((kind, target))
                if have is not None and not needed <= have:
                    errors["models"] = (
                        f"target {target} serves {sorted(have) or ['text']} but "
                        f"arm {arm} requires all of {sorted(needed)}"
                    )
            for attacker in attackers:
                can = fw_mods.get(attacker)
                if can is not None and not needed <= can:
                    errors["attackers"] = (
                        f"attacker {attacker} drives {sorted(can)} but arm "
                        f"{arm} requires all of {sorted(needed)}"
                    )
        if "guardrail" in judges_list and not params.get("guardrail_model", ""):
            errors["guardrail_model"] = "the scoring guardrail judge requires a guardrail model"
        scoring_guardrail = "guardrail" in judges_list
        defense_guardrail = params.get("defense_guard", "") == "guardrail" and params.get(
            "defense", ""
        ) not in ("", "none")
        if (
            scoring_guardrail
            and re.fullmatch(r"[0-9a-fA-F]{40,64}", params.get("guardrail_revision", "")) is None
        ):
            errors["guardrail_revision"] = (
                "the scoring guardrail requires an immutable 40-64 hex revision"
            )
        if defense_guardrail:
            if not params.get("defense_guardrail_model", ""):
                errors["defense_guardrail_model"] = (
                    "the defense guardrail requires a defense guardrail model"
                )
            if (
                re.fullmatch(
                    r"[0-9a-fA-F]{40,64}",
                    params.get("defense_guardrail_revision", ""),
                )
                is None
            ):
                errors["defense_guardrail_revision"] = (
                    "the defense guardrail requires an immutable 40-64 hex revision"
                )
            if not params.get("defense_guardrail_device", ""):
                errors["defense_guardrail_device"] = (
                    "the defense guardrail requires an explicit device"
                )
        scoring_g = params.get("guardrail_model", "")
        defense_g = params.get("defense_guardrail_model", "")
        if (
            scoring_guardrail
            and defense_guardrail
            and scoring_g
            and defense_g
            and scoring_g == defense_g
        ):
            errors["defense_guardrail_model"] = (
                "the scoring guard and the defense guard must be distinct "
                "models - a tested guard must never grade its own output"
            )
        if (
            mode != "dry_run"
            and not canary_dry
            and real_corpora
            and "llm" in judges_list
            and params.get("judge_model", "").strip().lower() == "mock"
        ):
            errors["judge_model"] = "a real-source live lane cannot use the mock LLM judge"

        no_call_mode = mode == "dry_run" or canary_dry
        if no_call_mode and scoring_guardrail:
            errors["judges"] = (
                "a no-call dry lane cannot load a model-backed scoring guardrail"
            )
        if no_call_mode and defense_guardrail:
            errors["defense_guard"] = (
                "a no-call dry lane cannot load a model-backed defense guardrail"
            )
        if (
            no_call_mode
            and "nanogcg" in attackers
            and not params.get("nanogcg_suffix", "").strip()
        ):
            errors["nanogcg"] = (
                "a no-call dry lane permits NanoGCG only as an exact precomputed "
                "suffix replay; live surrogate loading is forbidden"
            )

        if mode == "dry_run":
            forbid_live_fields("a diagnostic dry run cannot consume or produce live attestation")
        elif mode == "attestation_probe":
            if targets != 1:
                errors["models"] = "an attestation probe takes exactly one target"
            if len(corpora) != 1:
                errors["corpora"] = "an attestation probe takes exactly one corpus"
            if attackers != ["replay"]:
                errors["attackers"] = "an attestation probe uses exactly the replay attacker"
            if len(seeds) != 1:
                errors["seeds"] = "an attestation probe takes exactly one seed"
            if params.get("defense", "none") != "none":
                errors["defense"] = "an attestation probe requires defense none"
            if limit not in {1, 2}:
                errors["limit"] = "an attestation probe requires --limit 1 or 2"
            if params.get("max_queries", "") not in {"", "1"}:
                errors["max_queries"] = "an attestation probe uses one query"
            if params.get("max_turns", "") not in {"", "1"}:
                errors["max_turns"] = "an attestation probe uses one turn"
            if not params.get("scope", ""):
                errors["scope"] = "required: execution scope id"
            if not has_project:
                errors["project_revision"] = (
                    "required: validated project-revision receipt and digest"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = "required for a real-source probe corpus"
            if att_rows:
                errors["att"] = "an attestation probe cannot consume prior attestations"
            if params.get("max_age", ""):
                errors["max_age"] = "an attestation probe cannot consume prior attestations"
            require_caps_and_deadline()
        elif mode == "diagnostic_canary":
            if limit != 1:
                errors["limit"] = (
                    "a diagnostic canary requires exactly --limit 1 (all rows "
                    "in that source cluster are retained)"
                )
            if len(attackers) != 1:
                errors["attackers"] = "a diagnostic canary takes exactly one attacker"
            if len(seeds) != 1:
                errors["seeds"] = "a diagnostic canary takes exactly one seed"
            if canary_dry:
                # The dry canary is composed as offline-synthetic (corpora
                # synth, no targets, no receipts): the operator only picks the
                # attacker/seed/limit, so no arm or target selection is
                # required, and live-attestation fields are forbidden.
                forbid_live_fields("a dry canary cannot consume or produce live attestation")
            else:
                if len(corpora) != 1:
                    errors["corpora"] = "a live canary takes exactly one corpus"
                if targets != 1:
                    errors["models"] = "a live canary takes exactly one target model"
                require_live_admission()
        else:  # measured execution
            if targets < 1:
                errors["models"] = "select at least one target model"
            require_live_admission()
            paid_hosted_route = bool(api) or hosted_judge_selected
            if paid_hosted_route and limit is None:
                errors["limit"] = (
                    "hosted paid lanes must carry an explicit --limit: use a "
                    "positive pre-registered cluster bound, or 0 only for a "
                    "separately projected and approved full-corpus cohort"
                )
            if (
                paid_hosted_route
                and limit is not None
                and limit > 0
                and not params.get("sample_seed", "")
            ):
                errors["sample_seed"] = (
                    "hosted paid lanes must record --sample-seed (identical "
                    "subset only for the same logical arm, converted corpus "
                    "digest, limit and sample seed)"
                )
            elif limit is not None and limit > 0 and not params.get(
                "sample_seed", ""
            ):
                errors["sample_seed"] = (
                    "bounded measured lanes must record --sample-seed; the value "
                    "selects clusters independently within each selected arm"
                )
        return errors

    def _read_lane_projection(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, object] | None, str]:
        """The required target/judge/HTTP upper bounds from a no-call preflight.

        Only a successful console preflight carrying the same normalized grid
        parameters can authorize the preview. The three provisional planning
        caps may change to the preflight's printed totals; every other builder
        field remains exact. Its stdout names the content-addressed projection,
        which is validated before any bound is used.
        """

        from ura.lane_projection import validate_lane_projection  # noqa: PLC0415

        out_rel = params.get("out", "")
        if not out_rel:
            return None, "select an output directory and run the preflight"
        normalized = self._projection_params(params)
        preflights = sorted(
            (
                job
                for job in self.jobs.values()
                if "--preflight-only" in job.argv
                and self._projection_params(job.builder_params or {}) == normalized
                and job.state() == "complete"
            ),
            key=lambda job: job.started_at,
            reverse=True,
        )
        if not preflights:
            return None, (
                "no successful no-call preflight for these exact selections: "
                "run the preflight below"
            )
        prefix = "prospective no-call lane projection written: "
        for job in preflights:
            preflight_out = _argv_out_dir(job.argv)
            if not preflight_out:
                continue
            unresolved_out = Path(preflight_out)
            out_dir = (
                unresolved_out if unresolved_out.is_absolute() else self.repo_root / unresolved_out
            ).resolve()
            artifact = ""
            for line in reversed(self._log_tail(job, "stdout").splitlines()):
                if prefix not in line:
                    continue
                try:
                    announcement = json.loads(line.split(prefix, 1)[1])
                except (TypeError, ValueError):
                    continue
                if isinstance(announcement, Mapping):
                    artifact = str(announcement.get("artifact", ""))
                break
            if not artifact or Path(artifact).name != artifact:
                continue
            candidate = (out_dir / artifact).resolve()
            if candidate.parent != out_dir:
                continue
            try:
                doc = validate_lane_projection(json.loads(candidate.read_text(encoding="utf-8")))
            except (OSError, TypeError, ValueError):
                continue
            projection = doc["call_projection"]
            return {
                "projection_id": str(doc["projection_id"]),
                "call_projection": {
                    key: int(projection[key])
                    for key in ("target_calls", "judge_calls", "http_attempts")
                },
                "arms": [
                    {
                        key: arm[key]
                        for key in (
                            "logical_source_arm",
                            "total_records",
                            "selected_records",
                            "total_clusters",
                            "selected_clusters",
                            "limit",
                            "sample_seed",
                        )
                    }
                    for arm in doc["selection"]["arms"]
                ],
            }, ""
        return None, "the matching preflight's lane projection is missing or invalid"

    def _builder_model_acquisition_required(
        self,
        params: Mapping[str, str],
    ) -> bool:
        """Return whether this exact Builder lane has any Hub-backed role."""

        from ura.model_acquisition_runtime import (  # noqa: PLC0415
            collect_run_requirements,
        )

        targets = self._split_list(params.get("local", ""))
        judges = self._split_list(params.get("judges", ""))
        attackers = self._split_list(params.get("attackers", ""))
        judge_model = params.get("judge_model", "").strip()
        selected_local = list(targets)
        if judge_model.startswith("vllm:") and judge_model not in selected_local:
            selected_local.append(judge_model)
        catalog, _configured = self._local_entry_catalog()
        local_configs = {
            spec: catalog[spec]
            for spec in selected_local
            if spec in catalog
        }
        attacker_configs = self._prepared_attacker_entries(params)
        scoring_guardrail = "guardrail" in judges
        defense_guardrail = (
            params.get("defense_guard", "") == "guardrail"
            and params.get("defense", "") not in {"", "none"}
        )
        requirements = collect_run_requirements(
            target_specs=targets,
            local_configs=local_configs,
            judge_names=judges,
            judge_model=judge_model,
            attacker_names=attackers,
            attacker_configs=attacker_configs,
            guardrail_model=(
                params.get("guardrail_model", "") if scoring_guardrail else None
            ),
            guardrail_revision=(
                params.get("guardrail_revision", "") if scoring_guardrail else None
            ),
            defense_guardrail_model=(
                params.get("defense_guardrail_model", "")
                if defense_guardrail
                else None
            ),
            defense_guardrail_revision=(
                params.get("defense_guardrail_revision", "")
                if defense_guardrail
                else None
            ),
        )
        return bool(requirements.requirements)

    def _ceilings_card(self, params: Mapping[str, str]) -> tuple[str, bool]:
        """The call-ceiling summary shown before a non-dry job starts.

        Returns ``(html, caps_cover_projection)``: the boolean is true only
        when an exact, valid no-call projection exists and every entered
        ceiling covers it.
        """

        api = self._split_list(params.get("api", ""))
        local = self._split_list(params.get("local", ""))
        corpora = self._split_list(params.get("corpora", ""))
        attackers = self._split_list(params.get("attackers", ""))
        seeds = self._split_list(params.get("seeds", "") or "0")
        grid_cells = max(1, len(api) + len(local)) * max(1, len(corpora)) * max(1, len(attackers))
        shape = (
            f"{len(api) + len(local)} target(s) x {len(corpora)} corpus "
            f"arm(s) x {len(attackers)} attacker(s) x {len(seeds)} seed(s) "
            f"= {grid_cells * max(1, len(seeds))} planned cell-seed lanes"
        )
        rows = "".join(
            f"<tr><td><code>{html.escape(flag)}</code></td>"
            f"<td><strong>{html.escape(params.get(field, '') or '(unset)')}"
            "</strong></td><td>" + html.escape(note) + "</td></tr>"
            for field, flag, note in (
                (
                    "cap_target",
                    "--max-total-target-calls",
                    "hard circuit-breaker on model-under-test calls",
                ),
                (
                    "cap_judge",
                    "--max-total-judge-calls",
                    "hard circuit-breaker on model-backed judge calls (hosted or local)",
                ),
                (
                    "cap_http",
                    "--max-total-http-attempts",
                    "hard cap on transport attempts, retries included",
                ),
                (
                    "local_budget_hours",
                    "controller wall time",
                    "detached process wall-time cap in whole hours for the final "
                    "measured all-local run; independent of Runner's call-start window",
                ),
                (
                    "deadline",
                    "--deadline-seconds",
                    "durable call-start window from first invocation; not a "
                    "completion timeout and does not interrupt an admitted call",
                ),
                (
                    "limit",
                    "--limit",
                    "cluster subsample per corpus (cluster sibling rows are all "
                    "retained, so row counts can exceed this)",
                ),
                ("max_queries", "--max-queries", "target calls per datapoint and seed"),
                ("max_turns", "--max-turns", "conversation turns per datapoint and seed"),
                (
                    "target_answer_retries",
                    "--target-answer-retries",
                    "additional attempts for unusable output; default 1",
                ),
                (
                    "ideator_pair_limit",
                    "IDEATOR pair limit",
                    "0 selects the complete verified manifest; positive N selects "
                    "ordered_prefix_v1 and must fit both query and turn budgets",
                ),
            )
        )
        # No-call projection: the required upper bounds from the CLI preflight
        # (never estimated here).  Compare each entered ceiling against its
        # projected requirement; a shortfall blocks Start.
        projection, why = self._read_lane_projection(params)
        caps_ok = projection is not None
        if projection is not None:
            call_projection = projection.get("call_projection", projection)
            if not isinstance(call_projection, Mapping):
                raise ValueError("validated lane projection call inventory is invalid")
            proj_rows = []
            for label, cap_field, proj_key in (
                ("target calls", "cap_target", "target_calls"),
                ("judge calls", "cap_judge", "judge_calls"),
                ("HTTP attempts", "cap_http", "http_attempts"),
            ):
                required = int(call_projection[proj_key])
                entered_raw = params.get(cap_field, "")
                try:
                    entered = int(entered_raw) if entered_raw else None
                except ValueError:
                    entered = None
                covers = entered is not None and entered >= required
                if not covers:
                    caps_ok = False
                proj_rows.append(
                    f"<tr><td>{label}</td><td><strong>{required:,}</strong></td>"
                    f"<td>{html.escape(entered_raw) or '(unset)'}</td>"
                    "<td>"
                    + (
                        "<span class='badge green'>covers</span>"
                        if covers
                        else "<span class='badge red'>below required</span>"
                    )
                    + "</td></tr>"
                )
            projection_html = (
                "<h3>No-call projection (from the CLI preflight)</h3>"
                "<div class='scroll'><table><tr><th>Call kind</th>"
                "<th>Projected required</th><th>Your ceiling</th><th></th></tr>"
                + "".join(proj_rows)
                + "</table></div>"
                + (
                    ""
                    if caps_ok
                    else "<div class='notice red'><strong>A ceiling is below the "
                    "projected requirement.</strong><p class='note'>Raise the "
                    "flagged ceiling(s) to at least the projected upper bound "
                    "before starting; run_matrix would reject the lane "
                    "otherwise.</p></div>"
                )
            )
        else:
            projection_html = (
                "<h3>No-call projection</h3><p class='note'>" + html.escape(why) + ".</p>"
            )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Calculated call "
            "ceilings</h2>"
            f"<p><strong>{html.escape(shape)}</strong></p>"
            "<div class='scroll'><table><tr><th>Ceiling</th><th>Value</th>"
            "<th>Meaning</th></tr>"
            + rows
            + "</table></div>"
            + projection_html
            + "<p class='note'>The entered ceilings are the binding budget "
            "guards; run_matrix rejects the lane if they cannot cover its "
            "exact no-call projection. The projection above is computed by the "
            "CLI preflight from the real corpus (a call bound, not a price "
            "estimate), never estimated here.</p></div>"
        ), caps_ok

    def _preview_page(
        self,
        command: str,
        values: Mapping[str, str],
        params: Mapping[str, str],
    ) -> bytes:
        """Durable argv identity + ceilings confirmation before a paid start."""

        reviewed_params, execution_snapshot, _snapshot_sha256 = (
            self._capture_execution_config_snapshot(params)
        )
        (
            argv,
            _retained_params,
            _private_config,
            _private_api_config,
            _private_source_config,
            _private_attacker_config,
            _private_source_conformance,
            _private_evidence_files,
        ) = (
            self._durable_launch_state(
            command, values, reviewed_params
            )
        )
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in argv)
            + "</div>"
        )
        params = reviewed_params
        mode = params.get("mode", "measured")
        ceilings_html, caps_ok = self._ceilings_card(params)
        needs_acquisition = self._builder_model_acquisition_required(params)

        def ticket_input(token: str) -> str:
            return (
                "<input type='hidden' name='launch_ticket' value='"
                + html.escape(token)
                + "'>"
            )

        if needs_acquisition:
            preflight_hidden = ticket_input(self._new_launch_ticket(
                {**params, "_model_acquisition_next": "preflight"},
                purpose="acquisition_plan",
                execution_snapshot=execution_snapshot,
            ))
            start_hidden = ticket_input(self._new_launch_ticket(
                {**params, "_model_acquisition_next": "run"},
                purpose="acquisition_plan",
                execution_snapshot=execution_snapshot,
            ))
            preflight_action = "/build/model-acquisition/plan"
            start_action = "/build/model-acquisition/plan"
            preflight_extra = ""
            start_extra = ""
            acquisition_notice = (
                "<div class='notice blue'><strong>Sealed model acquisition is "
                "required.</strong><p class='note'>The next job derives a public, "
                "immutable plan without loading a model. After review, a dedicated "
                "acquisition job may transfer missing bytes. Measured and preflight "
                "runs remain offline and require the exact plan and receipt.</p></div>"
            )
            preflight_label = "Plan & acquire models for no-call preflight"
            start_label = "Plan & acquire models for this job"
        else:
            hidden = ticket_input(self._new_launch_ticket(
                params,
                execution_snapshot=execution_snapshot,
            ))
            preflight_hidden = hidden
            start_hidden = hidden
            preflight_action = "/build"
            start_action = "/build"
            preflight_extra = (
                "<input type='hidden' name='confirm' value='yes'>"
                "<input type='hidden' name='preflight_only' value='yes'>"
            )
            start_extra = "<input type='hidden' name='confirm' value='yes'>"
            acquisition_notice = ""
            preflight_label = "Run no-call preflight (projection, no calls)"
            start_label = "Start campaign run" if params.get("campaign_id") else "Start single run"
        # A "Run no-call preflight" action composes the SAME grid with
        # --preflight-only (no calls) so the operator can produce the projection
        # this page reads and compares against.
        preflight_form = (
            f"<form method='post' action='{preflight_action}'>"
            + preflight_hidden
            + preflight_extra
            + "<button type='submit' class='ghost' "
            "data-busy='Preparing the sealed model workflow...'>"
            + _icon("pulse", size=15)
            + html.escape(preflight_label)
            + "</button></form> "
        )
        start_button = (
            "<button type='submit'>"
            + _icon("play", size=15)
            + html.escape(start_label)
            + "</button>"
            if caps_ok
            else "<button type='submit' disabled>"
            + _icon("play", size=15)
            + "Start blocked: run preflight / cover its projection</button>"
        )
        body = (
            "<h1>" + _icon("play", size=22) + "Review execution</h1>"
            "<div class='notice amber'><strong>This execution makes real model calls. "
            "API calls may incur charges.</strong><p class='note'>Mode: "
            f"<code>{html.escape(mode)}</code>. Review the exact command and "
            "ceilings below; nothing has started yet.</p></div>"
            + acquisition_notice
            + self._campaign_banner(params.get("campaign_id", ""))
            + "<section class='card'><h2>Experiment</h2><dl class='builder-summary'>" + "".join(
                "<div><dt>" + label + "</dt><dd>" + html.escape(params.get(key) or "Not set") + "</dd></div>"
                for key, label in (("local", "Local models"), ("api", "API models"), ("corpora", "Arms / corpora"),
                    ("attackers", "Frameworks / attacks"), ("seeds", "Seeds"), ("sampling_policy", "Sampling"),
                    ("limit", "Per-arm limit"), ("judges", "Judges"), ("judge_model", "Judge model"))
            ) + "</dl></section>"
            + "<div class='card'><h2>"
            + _icon("terminal")
            + "Durable command identity</h2>"
            + argv_chips
            + "<p class='note'>Explicit workstation checkpoint locators are "
            "shown and retained only as their declared SHA-256 content identity. "
            "The launched child verifies that identity before model calls.</p>"
            + preflight_form
            + "</div>"
            + ceilings_html
            + f"<form method='post' action='{start_action}'>"
            + start_hidden
            + start_extra
            + "<div class='buildbar'>"
            + start_button
            + "</div></form><form method='post' action='/build/edit'>"
            "<input type='hidden' name='edit_ticket' value='"
            + self._new_launch_ticket(params, purpose="build-edit")
            + "'><button class='ghost'>Edit configuration</button></form>"
        )
        return _page("Confirm execution", body, active="Build")
