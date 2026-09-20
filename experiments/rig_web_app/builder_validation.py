"""Builder validation, projection, ceilings, and preview rendering."""

from __future__ import annotations


from .i18n import template as _ui_template, text as _ui_text

import hashlib
import html
import json
import os
import re
import secrets
import stat
import subprocess
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
            return _condition_sha256(
                {
                    "fixed_inherent_route_class": (
                        f"{built.__class__.__module__}.{built.__class__.__qualname__}"
                    ),
                    "provider": provider,
                    "model": model,
                }
            )
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
    condition = {key: value for key, value in entry.items() if key not in {"revision", "digest"}}
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
            raise ValueError(
                (f"{label}" + _ui_text("builder_validation.requires_a_path_and_exact_sha_256"))
            )
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
                    (
                        f"{label}"
                        + _ui_text(
                            "builder_validation.must_be_one_non_link_file_within_its_size_bound"
                        )
                    )
                )
            path = candidate.resolve(strict=True)
            resolved = path.lstat()
            if (
                path.is_symlink()
                or path.is_junction()
                or (resolved.st_dev, resolved.st_ino, resolved.st_mode)
                != (initial.st_dev, initial.st_ino, initial.st_mode)
            ):
                raise ValueError((f"{label}" + _ui_text("builder_validation.must_not_be_a_link")))
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != initial.st_size
                or (opened.st_dev, opened.st_ino, opened.st_mode)
                != (initial.st_dev, initial.st_ino, initial.st_mode)
            ):
                raise ValueError(
                    (f"{label}" + _ui_text("builder_validation.changed_while_being_opened"))
                )
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                descriptor = None
                raw = handle.read(max_bytes + 1)
                after = os.fstat(handle.fileno())
            final = path.lstat()
        except OSError as exc:
            raise ValueError(
                (f"{label}" + _ui_text("builder_validation.must_be_a_readable_regular_file"))
            ) from exc
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
            raise ValueError((f"{label}" + _ui_text("builder_validation.changed_while_being_read")))
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError(
                (f"{label}" + _ui_text("builder_validation.sha_256_does_not_match_the_file"))
            )
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
                raise ValueError(
                    _ui_text(
                        "builder_validation.api_target_registry_must_be_a_regular_non_symlink_file"
                    )
                )
            raw = path.read_bytes()
            if not raw or len(raw) > 1024 * 1024:
                raise ValueError(
                    _ui_text(
                        "builder_validation.api_target_registry_must_be_a_regular_1_mib_json_file"
                    )
                )

            def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, child in pairs:
                    if key in value:
                        raise ValueError(
                            (
                                _ui_text("builder_validation.api_target_registry_has_duplicate_key")
                                + f"{key!r}"
                            )
                        )
                    value[key] = child
                return value

            try:
                loaded = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    (
                        _ui_text("builder_validation.api_target_registry_is_invalid_utf_8_json")
                        + f"{exc}"
                    )
                ) from exc
            if not isinstance(loaded, dict):
                raise ValueError(
                    _ui_text("builder_validation.api_target_registry_must_be_a_json_object")
                )
            registry = loaded
            registry_sha256 = hashlib.sha256(raw).hexdigest()
            registry_relative = path.relative_to(self.repo_root).as_posix()
        elif api_specs:
            raise ValueError(
                _ui_text("builder_validation.selected_hosted_models_require_an_api_target_registry")
            )

        routes: list[dict[str, object]] = []
        runtime_configs: dict[str, dict[str, object]] = {}
        for spec in api_specs:
            entry = registry.get(spec)
            provider, model = canonical_api_target_identity(spec)
            if api_target_requires_config(spec):
                if not isinstance(entry, dict):
                    raise ValueError(
                        (
                            _ui_text(
                                "builder_validation.api_target_registry_is_missing_selected_generic_route"
                            )
                            + f"{spec!r}"
                        )
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
                declared = entry.get("modalities") if isinstance(entry, dict) else None
                if declared is not None and (
                    not isinstance(declared, list)
                    or any(not isinstance(item, str) for item in declared)
                    or tuple(declared) != tuple(built.modality_support)
                ):
                    raise ValueError(
                        (
                            _ui_text("builder_validation.fixed_api_route")
                            + f"{spec!r}"
                            + _ui_text(
                                "builder_validation.registry_modalities_must_exactly_match_the_authoritative_adapter"
                            )
                        )
                    )
                if isinstance(entry, dict) and set(entry) != {"modalities"}:
                    raise ValueError(
                        (
                            _ui_text("builder_validation.fixed_api_route")
                            + f"{spec!r}"
                            + _ui_text(
                                "builder_validation.must_not_advertise_mutable_execution_config"
                            )
                        )
                    )
                portable_config = {
                    "inherent_route": True,
                    "modalities": list(built.modality_support),
                }
                endpoint_identity = api_target_endpoint_identity(spec)
            routes.append(
                {
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
                }
            )
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

        _snapshot, digest, _relative, _configs = self._selected_api_config_snapshot(params)
        prior = params.get("_api_config_snapshot_sha256", "")
        if prior and prior != digest:
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_api_registry_config_changed_after_review_review_the_lane"
                )
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
        if params.get("mode") == "diagnostic_canary" and params.get("canary_dry") == "on":
            corpora = ["synth"]
        registry = self.repo_root / "experiments" / "source-instances.json"
        real_arms = [arm for arm in corpora if arm != "synth"]
        if real_arms and not registry.exists():
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_real_source_arms_require_the_executable_operator_registr"
                )
            )
        if registry.exists():
            if registry.is_symlink() or not registry.is_file():
                raise ValueError(
                    _ui_text(
                        "builder_validation.source_instance_registry_must_be_a_regular_non_symlink_file"
                    )
                )
            from experiments import run_matrix  # noqa: PLC0415

            configs, _artifact = run_matrix._load_source_config(  # noqa: SLF001
                str(registry), corpora
            )
        else:
            configs = (
                {"synth": {"converter": "synth", "synth": True}} if corpora == ["synth"] else {}
            )
        for arm in corpora:
            config = configs.get(arm)
            if not isinstance(config, dict):
                raise ValueError(
                    (_ui_text("builder_validation.source_registry_omits_selected_arm") + f"{arm!r}")
                )
            synthetic = config.get("synth") is True
            if arm == "synth":
                if not synthetic or config.get("converter") != "synth":
                    raise ValueError(
                        _ui_text(
                            "builder_validation.the_literal_synth_arm_must_use_converter_synth_and_synth_true"
                        )
                    )
            elif synthetic or config.get("converter") == "synth":
                raise ValueError(
                    (
                        _ui_text("builder_validation.real_source_arm")
                        + f"{arm!r}"
                        + _ui_text("builder_validation.cannot_be_reclassified_as_synthetic")
                    )
                )
        runtime_fields = {"converter", "path_env", "synth", "source_label", "split"}
        runtime_configs = {
            arm: {key: value for key, value in configs[arm].items() if key in runtime_fields}
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
                _ui_text(
                    "builder_validation.selected_source_registry_config_changed_after_review_review_the_l"
                )
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
            set(self._split_list(str(params.get("attackers", "")))) & RUNTIME_REQUIRED_ATTACKERS
        )
        path_value = str(params.get("engine_runtime_config", "")).strip()
        expected = str(params.get("engine_runtime_config_sha", "")).strip().lower()
        if not selected:
            if path_value or expected:
                raise ValueError(
                    _ui_text(
                        "builder_validation.engine_runtime_config_is_allowed_only_when_pyrit_deepteam_h4rm3l"
                    )
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
            label=_ui_text("builder_validation.engine_runtime_config"),
            max_bytes=4 * 1024 * 1024,
        )
        try:
            document = strict_json_loads(raw, max_nodes=100_000, max_depth=16)
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                _ui_text("builder_validation.engine_runtime_config_is_not_strict_json")
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "runtimes"}
            or document.get("schema") != ENGINE_RUNTIME_CONFIG_SCHEMA
            or not isinstance(document.get("runtimes"), dict)
            or set(document["runtimes"]) != set(selected)
        ):
            raise ValueError(
                _ui_text(
                    "builder_validation.engine_runtime_config_must_contain_exactly_the_selected_third_par"
                )
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
        _snapshot, digest, _raw, _actual = self._selected_engine_runtime_config_snapshot(params)
        prior = str(params.get("_engine_runtime_config_snapshot_sha256", ""))
        if prior and prior != digest:
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_engine_runtime_config_changed_after_review_review_the_la"
                )
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
            label=_ui_text("builder_validation.source_conformance"),
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
                _ui_text("builder_validation.source_conformance_is_not_a_valid_receipt")
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
            label=_ui_text("builder_validation.project_revision"),
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

        _api_snapshot, _api_digest, _relative, api_configs = self._selected_api_config_snapshot(
            bound
        )
        if api_configs:
            components["api_config"] = self._canonical_json_bytes(api_configs)

        _source_snapshot, _source_digest, source_configs = self._selected_source_config_snapshot(
            bound
        )
        if source_configs:
            components["source_config"] = self._canonical_json_bytes(source_configs)

        _attacker_snapshot, _attacker_digest, attacker_configs = (
            self._selected_prepared_attacker_snapshot(bound)
        )
        if attacker_configs:
            components["attacker_config"] = self._canonical_json_bytes(attacker_configs)
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
                    label=(
                        _ui_text("builder_validation.prepared")
                        + f"{attacker}"
                        + _ui_text("builder_validation.artifact")
                    ),
                    max_bytes=max_bytes,
                )
                components[f"attacker_artifact_{attacker}"] = raw
            ideator = attacker_configs.get("ideator")
            if isinstance(ideator, Mapping):
                manifest_path = ideator.get("seed_pair_manifest")
                manifest_sha256 = ideator.get("seed_pair_manifest_sha256")
                if not isinstance(manifest_path, str) or not isinstance(manifest_sha256, str):
                    raise ValueError(
                        _ui_text(
                            "builder_validation.prepared_ideator_manifest_identity_is_incomplete"
                        )
                    )
                raw_manifest, _manifest_actual = self._bounded_content_snapshot(
                    manifest_path,
                    manifest_sha256,
                    label=_ui_text("builder_validation.prepared_ideator_seed_pair_manifest"),
                    max_bytes=4 * 1024 * 1024,
                )
                components["attacker_artifact_ideator"] = raw_manifest
                seed_pairs = ideator.get("seed_pairs")
                if not isinstance(seed_pairs, list):
                    raise ValueError(
                        _ui_text(
                            "builder_validation.prepared_ideator_seed_pair_inventory_is_invalid"
                        )
                    )
                for index, pair in enumerate(seed_pairs):
                    if not isinstance(pair, Mapping):
                        raise ValueError(
                            _ui_text(
                                "builder_validation.prepared_ideator_seed_pair_inventory_is_invalid"
                            )
                        )
                    image_path = pair.get("image_path")
                    image_sha256 = pair.get("image_sha256")
                    if not isinstance(image_path, str) or not isinstance(image_sha256, str):
                        raise ValueError(
                            _ui_text(
                                "builder_validation.prepared_ideator_image_identity_is_incomplete"
                            )
                        )
                    raw_image, _image_actual = self._bounded_content_snapshot(
                        image_path,
                        image_sha256,
                        label=(_ui_text("builder_validation.prepared_ideator_image") + f"{index}"),
                        max_bytes=25 * 1024 * 1024,
                    )
                    components[f"attacker_artifact_ideator_image_{index:04d}"] = raw_image

        _engine_snapshot, _engine_digest, engine_raw, engine_actual = (
            self._selected_engine_runtime_config_snapshot(bound)
        )
        if engine_raw is not None:
            components["engine_runtime_config"] = engine_raw
            if engine_actual is None:  # pragma: no cover - tuple invariant
                raise ValueError(
                    _ui_text("builder_validation.engine_runtime_config_lacks_a_byte_identity")
                )
            bound["engine_runtime_config_sha"] = engine_actual

        mode = bound.get("mode", "measured")
        dry = mode == "dry_run" or (mode == "diagnostic_canary" and bound.get("canary_dry") == "on")
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
                    _ui_text(
                        "builder_validation.selected_local_registry_model_changed_after_review_review_the_lan"
                    )
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
                label=(_ui_text("builder_validation.live_attestation_row") + f"{index}"),
                max_bytes=4 * 1024 * 1024,
            )
            components[f"live_attestation_{index:02d}"] = raw
            bound[f"att_sha{index}"] = actual

        snapshot_sha256 = self._execution_snapshot_digest(bound, components)
        prior_snapshot = str(bound.get("_execution_snapshot_sha256", ""))
        if prior_snapshot and prior_snapshot != snapshot_sha256:
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_execution_snapshot_changed_after_review_review_the_lane"
                )
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
            raise ValueError(
                _ui_text(
                    "builder_validation.reviewed_execution_snapshot_has_unsupported_components"
                )
            )
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
        return hashlib.sha256(self._canonical_json_bytes(manifest)).hexdigest()

    def _validate_execution_snapshot(
        self,
        params: Mapping[str, str],
        components: Mapping[str, bytes],
    ) -> dict[str, bytes]:
        """Validate one controller-held byte snapshot without mutable re-reads."""

        snapshot = {str(name): bytes(payload) for name, payload in components.items()}
        expected = str(params.get("_execution_snapshot_sha256", "")).strip()
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError(
                _ui_text("builder_validation.reviewed_execution_snapshot_identity_is_missing")
            )
        actual = self._execution_snapshot_digest(params, snapshot)
        if not secrets.compare_digest(actual, expected):
            raise ValueError(
                _ui_text(
                    "builder_validation.reviewed_execution_snapshot_bytes_do_not_match_the_ticket"
                )
            )
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
                    raise ValueError(
                        _ui_text("builder_validation.prepared_ideator_manifest_path_is_missing")
                    )
                if (
                    not isinstance(manifest_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None
                ):
                    raise ValueError(
                        _ui_text(
                            "builder_validation.prepared_ideator_manifest_lacks_an_exact_content_digest"
                        )
                    )
                raw_pairs = entry.get("seed_pairs")
                if not isinstance(raw_pairs, list) or not raw_pairs:
                    raise ValueError(
                        _ui_text(
                            "builder_validation.prepared_ideator_seed_pair_inventory_is_invalid"
                        )
                    )
                pair_limit = entry.get("pair_limit")
                if (
                    isinstance(pair_limit, bool)
                    or not isinstance(pair_limit, int)
                    or not 0 <= pair_limit <= 256
                    or pair_limit > len(raw_pairs)
                ):
                    raise ValueError(
                        _ui_text("builder_validation.prepared_ideator_pair_limit_is_invalid")
                    )
                portable_pairs: list[dict[str, object]] = []
                for index, raw_pair in enumerate(raw_pairs):
                    if not isinstance(raw_pair, Mapping):
                        raise ValueError(
                            _ui_text(
                                "builder_validation.prepared_ideator_seed_pair_inventory_is_invalid"
                            )
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
                            (
                                _ui_text("builder_validation.prepared_ideator_seed_pair")
                                + f"{index}"
                                + _ui_text("builder_validation.is_invalid")
                            )
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
                if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise ValueError(
                        (
                            _ui_text("builder_validation.prepared")
                            + f"{name}"
                            + _ui_text("builder_validation.artifact_lacks_an_exact_content_digest")
                        )
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
                _ui_text(
                    "builder_validation.selected_prepared_attacker_config_changed_after_review_review_the"
                )
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
            "project_revision_sha256": str(params.get("project_revision_sha", "")).lower(),
            "source_conformance_sha256": str(params.get("source_conformance_sha", "")).lower(),
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
                _ui_text(
                    "builder_validation.selected_execution_config_changed_after_review_review_the_lane_ag"
                )
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
            raise ValueError(
                (
                    _ui_text("builder_validation.private")
                    + f"{filename_prefix}"
                    + _ui_text("builder_validation.directory_must_not_be_a_symlink")
                )
            )
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(
                (
                    _ui_text("builder_validation.private")
                    + f"{filename_prefix}"
                    + _ui_text("builder_validation.directory_must_be_a_directory")
                )
            )
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        path = directory / (f"selected-{filename_prefix}-{digest[:24]}-{os.urandom(8).hex()}.json")
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
                    _ui_text(
                        "builder_validation.selected_source_registry_config_changed_after_review_review_the_l"
                    )
                )
            if not configs:
                return None, None
            payload = self._canonical_json_bytes(configs)
        else:
            payload = bytes(snapshot_payload)
        try:
            snapshot_configs = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                _ui_text("builder_validation.reviewed_source_config_snapshot_is_invalid")
            ) from exc
        selected = self._split_list(params.get("corpora", ""))
        if params.get("mode") == "diagnostic_canary" and params.get("canary_dry") == "on":
            selected = ["synth"]
        if (
            not isinstance(snapshot_configs, dict)
            or set(snapshot_configs) != set(selected)
            or payload != self._canonical_json_bytes(snapshot_configs)
        ):
            raise ValueError(
                _ui_text(
                    "builder_validation.reviewed_source_config_snapshot_no_longer_matches_selection"
                )
            )
        for arm, config in snapshot_configs.items():
            if not isinstance(config, dict):
                raise ValueError(
                    _ui_text(
                        "builder_validation.reviewed_source_config_snapshot_contains_an_invalid_arm"
                    )
                )
            synthetic = config.get("synth") is True
            if arm == "synth":
                if not synthetic or config.get("converter") != "synth":
                    raise ValueError(
                        _ui_text(
                            "builder_validation.reviewed_synth_arm_is_not_the_exact_synthetic_fixture"
                        )
                    )
            elif synthetic or config.get("converter") == "synth":
                raise ValueError(
                    (
                        _ui_text("builder_validation.real_source_arm")
                        + f"{arm!r}"
                        + _ui_text("builder_validation.cannot_be_synthetic")
                    )
                )
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
            set(self._split_list(str(params.get("attackers", "")))) & RUNTIME_REQUIRED_ATTACKERS
        )
        expected = str(params.get("engine_runtime_config_sha", "")).strip().lower()
        if not selected:
            if snapshot_payload is not None:
                raise ValueError(
                    _ui_text(
                        "builder_validation.reviewed_engine_runtime_config_exists_without_a_selected_runtime"
                    )
                )
            return None, None
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError(
                _ui_text("builder_validation.engine_runtime_config_requires_an_exact_sha_256")
            )
        if snapshot_payload is None:
            _snapshot, digest, raw, actual = self._selected_engine_runtime_config_snapshot(params)
            if raw is None or actual is None:  # pragma: no cover - selection invariant
                raise ValueError(
                    _ui_text("builder_validation.selected_engine_runtime_config_is_missing")
                )
            payload = raw
        else:
            payload = bytes(snapshot_payload)
            actual = hashlib.sha256(payload).hexdigest()
            if not payload or len(payload) > 4 * 1024 * 1024 or actual != expected:
                raise ValueError(
                    _ui_text(
                        "builder_validation.reviewed_engine_runtime_config_bytes_do_not_match_the_ticket"
                    )
                )
            try:
                document = strict_json_loads(
                    payload,
                    max_nodes=100_000,
                    max_depth=16,
                )
            except (UnicodeError, ValueError) as exc:
                raise ValueError(
                    _ui_text("builder_validation.reviewed_engine_runtime_config_is_invalid")
                ) from exc
            if (
                not isinstance(document, dict)
                or set(document) != {"schema", "runtimes"}
                or document.get("schema") != ENGINE_RUNTIME_CONFIG_SCHEMA
                or not isinstance(document.get("runtimes"), dict)
                or set(document["runtimes"]) != set(selected)
            ):
                raise ValueError(
                    _ui_text(
                        "builder_validation.reviewed_engine_runtime_config_no_longer_matches_selection"
                    )
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
            raise ValueError(
                _ui_text("builder_validation.engine_runtime_config_sha_256_no_longer_matches")
            )
        if str(params.get("_engine_runtime_config_snapshot_sha256", "")) != digest:
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_engine_runtime_config_changed_after_review_review_the_la"
                )
            )
        path, materialized_digest = self._materialize_private_config(
            payload=payload,
            directory_name=".private-engine-runtime-configs",
            filename_prefix="engine-runtime",
        )
        if materialized_digest != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError(
                _ui_text(
                    "builder_validation.engine_runtime_config_digest_changed_while_materializing"
                )
            )
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
            raise ValueError(
                _ui_text(
                    "builder_validation.reviewed_source_conformance_snapshot_no_longer_matches"
                )
            )
        path, actual = self._materialize_private_config(
            payload=raw,
            directory_name=".private-source-conformance",
            filename_prefix="source-conformance",
        )
        if actual != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError(
                _ui_text("builder_validation.source_conformance_snapshot_digest_changed")
            )
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
            raise ValueError(
                _ui_text("builder_validation.reviewed_project_revision_snapshot_no_longer_matches")
            )
        # Catch the common saved-draft-after-deployment error before creating a
        # plan job. This reads only the small receipt and Git HEAD. Runner still
        # performs the complete receipt/source validation; no model is hashed.
        try:
            receipt = strict_json_loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            receipt = None
        repository = receipt.get("repository") if isinstance(receipt, dict) else None
        required_commit = (
            repository.get("expected_commit") if isinstance(repository, dict) else None
        )
        dry = params.get("mode") == "dry_run" or (
            params.get("mode") == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        if (
            not dry
            and isinstance(required_commit, str)
            and re.fullmatch(r"[0-9a-f]{40,64}", required_commit)
        ):
            try:
                head = subprocess.run(
                    ["git", "-C", str(self.repo_root), "rev-parse", "HEAD"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError) as exc:
                raise ValueError(
                    _ui_text(
                        "builder_validation.cannot_read_the_deployed_project_revision_no_job_was_started"
                    )
                ) from exc
            if head != required_commit:
                raise ValueError(
                    _ui_text(
                        "builder_validation.the_saved_project_receipt_belongs_to_an_older_or_different_softwa"
                    )
                )
        path, actual = self._materialize_private_config(
            payload=raw,
            directory_name=".private-project-revision",
            filename_prefix="project-revision",
        )
        if actual != expected:  # pragma: no cover - direct hash invariant
            path.unlink(missing_ok=True)
            raise ValueError(
                _ui_text("builder_validation.project_revision_snapshot_digest_changed")
            )
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
                        label=(_ui_text("builder_validation.live_attestation_row") + f"{index}"),
                        max_bytes=4 * 1024 * 1024,
                    )
                if hashlib.sha256(payload).hexdigest() != expected:
                    raise ValueError(
                        (
                            _ui_text("builder_validation.reviewed_live_attestation_row")
                            + f"{index}"
                            + _ui_text("builder_validation.no_longer_matches")
                        )
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

        _snapshot, digest, relative, _configs = self._selected_api_config_snapshot(params)
        if params.get("_api_config_snapshot_sha256", "") != digest:
            raise ValueError(
                _ui_text(
                    "builder_validation.selected_api_registry_config_changed_after_review_review_the_lane"
                )
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
            _snapshot, digest, _relative, configs = self._selected_api_config_snapshot(params)
            if params.get("_api_config_snapshot_sha256", "") != digest:
                raise ValueError(
                    _ui_text(
                        "builder_validation.selected_api_registry_config_changed_after_review_review_the_lane"
                    )
                )
            if not configs:
                return None, None
            payload = self._canonical_json_bytes(configs)
        else:
            payload = bytes(snapshot_payload)
        try:
            snapshot_configs = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                _ui_text("builder_validation.reviewed_api_config_snapshot_is_invalid")
            ) from exc
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
        expected_configured = {spec for spec in selected if api_target_requires_config(spec)}
        if (
            not isinstance(snapshot_configs, dict)
            or set(snapshot_configs) != expected_configured
            or payload != self._canonical_json_bytes(snapshot_configs)
        ):
            raise ValueError(
                _ui_text(
                    "builder_validation.reviewed_api_config_snapshot_no_longer_matches_selection"
                )
            )
        for spec, entry in snapshot_configs.items():
            if not isinstance(entry, dict):
                raise ValueError(
                    _ui_text(
                        "builder_validation.reviewed_api_config_snapshot_contains_an_invalid_route"
                    )
                )
            normalized = normalize_api_target_config(spec, entry)
            if normalized != entry:
                raise ValueError(
                    _ui_text("builder_validation.reviewed_api_config_snapshot_is_not_normalized")
                )
            build_api_target(spec, config=normalized)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        directory = self.state_dir / ".private-api-configs"
        if directory.is_symlink():
            raise ValueError(
                _ui_text("builder_validation.private_api_config_directory_must_not_be_a_symlink")
            )
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(
                _ui_text("builder_validation.private_api_config_directory_must_be_a_directory")
            )
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        path = directory / (f"selected-api-{payload_sha256[:24]}-{os.urandom(8).hex()}.json")
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

    def _validate_builder(
        self, params: Mapping[str, str], *, preparation: bool = False
    ) -> dict[str, str]:
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
            errors["approximate_common_metrics"] = _ui_text(
                "builder_validation.the_approximate_metrics_opt_in_must_be_an_explicit_checkbox"
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
            errors["mode"] = _ui_text("builder_validation.select_a_supported_execution_mode")

        def reject_duplicates(field: str, values: list[str]) -> None:
            duplicates = sorted(value for value in set(values) if values.count(value) > 1)
            if duplicates:
                errors[field] = _ui_text(
                    "builder_validation.entries_must_be_unique_duplicates"
                ) + ", ".join(duplicates)

        reject_duplicates("models", [*api, *local])
        reject_duplicates("corpora", corpora)
        reject_duplicates("attackers", attackers)
        reject_duplicates("judges", judges_list)
        harm_requirements: tuple[str, int, int, int] | None = None
        ideator_requirements: tuple[int, int] | None = None

        known_arms = {arm for arm, _mods, _reason in _ARM_CATALOG} | {"synth"}
        unknown_arms = sorted(set(corpora) - known_arms)
        if unknown_arms:
            errors["corpora"] = _ui_text("builder_validation.unknown_corpus_arm_s") + ", ".join(
                unknown_arms
            )
        unknown_attackers = sorted(set(attackers) - set(_ATTACKER_NAMES))
        if unknown_attackers:
            errors["attackers"] = _ui_text(
                "builder_validation.unknown_attack_framework_s"
            ) + ", ".join(unknown_attackers)
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
                prepared = self._prepared_attacker_entries({**params, "attackers": attacker})
                if attacker == "harmbench":
                    harm_requirements = self._harmbench_replay_requirements(params)
                elif attacker == "ideator":
                    ideator = prepared.get("ideator")
                    if not isinstance(ideator, Mapping):  # pragma: no cover - invariant
                        raise ValueError(
                            _ui_text("builder_validation.prepared_ideator_configuration_is_missing")
                        )
                    raw_pairs = ideator.get("seed_pairs")
                    pair_limit = ideator.get("pair_limit")
                    if not isinstance(raw_pairs, list) or not isinstance(pair_limit, int):
                        raise ValueError(
                            _ui_text(
                                "builder_validation.prepared_ideator_pair_inventory_is_invalid"
                            )
                        )
                    ideator_requirements = (
                        len(raw_pairs),
                        len(raw_pairs) if pair_limit == 0 else pair_limit,
                    )
            except ValueError as exc:
                errors[error_field] = str(exc)
        unknown_judges = sorted(set(judges_list) - {"rules", "llm", "guardrail"})
        if unknown_judges:
            errors["judges"] = _ui_text("builder_validation.unknown_judge_s") + ", ".join(
                unknown_judges
            )
        if params.get("defense", "none") not in {"none", "input", "output", "both"}:
            errors["defense"] = _ui_text("builder_validation.select_none_input_output_or_both")
        if params.get("defense_guard", "rules") not in {"rules", "guardrail"}:
            errors["defense_guard"] = _ui_text("builder_validation.select_rules_or_guardrail")
        if params.get("dtype", "") not in {"", "auto", "bfloat16", "float16"}:
            errors["dtype"] = _ui_text("builder_validation.select_auto_bfloat16_or_float16")

        model_options = self._model_options()
        target_mods = {(kind, value): set(mods) for value, _label, mods, kind in model_options}
        option_kind = {value: kind for value, _label, _mods, kind in model_options}
        local_options = {value for value, _label, _mods, kind in model_options if kind == "local"}
        api_catalog = self._load_registry("api-targets.json", "rig/api-targets.example.json")
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
                    _ui_text(
                        "builder_validation.nanogcg_requires_an_exact_precomputed_suffix_replay"
                    )
                    + LIVE_NANOGCG_DISABLED_MESSAGE
                )
        hosted_identity_conditions = []
        for spec in api:
            selected_config = (
                api_catalog.get(spec) if isinstance(api_catalog.get(spec), Mapping) else None
            )
            identity = _hosted_model_identity(spec, selected_config)
            if identity is not None:
                hosted_identity_conditions.append(
                    (
                        identity,
                        _hosted_target_condition(spec, selected_config),
                    )
                )
        hosted_target_identities = [identity for identity, _condition in hosted_identity_conditions]
        seen_hosted_identity_keys: set[tuple[tuple[str, ...], str]] = set()
        duplicate_hosted_identity = False
        for identity_keys, condition in hosted_identity_conditions:
            condition_keys = {(identity, condition) for identity in identity_keys}
            if seen_hosted_identity_keys & condition_keys:
                duplicate_hosted_identity = True
            seen_hosted_identity_keys.update(condition_keys)
        if duplicate_hosted_identity:
            errors["models"] = _ui_text(
                "builder_validation.hosted_targets_must_be_unique_after_provider_alias_resolution_and"
            )
        local_identity_conditions = []
        for spec in local:
            entry = local_catalog.get(spec, {})
            identity = _local_model_identity(spec, entry)
            if identity is None:
                continue
            local_identity_conditions.append(
                (
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
                )
            )
        local_target_identities = [identity for identity, _condition in local_identity_conditions]
        if len(local_identity_conditions) != len(set(local_identity_conditions)):
            errors["models"] = _ui_text(
                "builder_validation.local_targets_must_be_unique_after_immutable_content_identity_and"
            )
        precision_specs = {
            key.removeprefix("quantization::") for key in params if key.startswith("quantization::")
        }
        if precision_specs - local_options:
            errors["models"] = _ui_text(
                "builder_validation.the_request_contains_a_per_model_precision_field_for_an_unknown_l"
            )
        unknown_api = sorted(value for value in api if ("api", value) not in target_mods)
        unknown_local = sorted(value for value in local if ("local", value) not in target_mods)
        if unknown_api or unknown_local:
            details = []
            if unknown_api:
                details.append(_ui_text("builder_validation.hosted") + ", ".join(unknown_api))
            if unknown_local:
                details.append(_ui_text("builder_validation.local") + ", ".join(unknown_local))
            errors["models"] = _ui_text(
                "builder_validation.unknown_target_selection_s"
            ) + "; ".join(details)
        if "ideator" in attackers:
            text_only_targets = [
                target
                for kind, target in (
                    [("api", value) for value in api] + [("local", value) for value in local]
                )
                if (mods := target_mods.get((kind, target))) is not None and "image" not in mods
            ]
            if text_only_targets:
                errors["models"] = _ui_text(
                    "builder_validation.ideator_seed_pair_replay_requires_an_image_capable_target"
                ) + ", ".join(text_only_targets)
        live_llm_judge = "llm" in judges_list and mode != "dry_run" and not canary_dry
        judge_model = params.get("judge_model", "").strip()
        judge_kind = option_kind.get(judge_model)
        hosted_judge_selected = live_llm_judge and judge_kind == "api"
        transfer_ack = params.get("ack_hosted_judge_data_transfer", "")
        if transfer_ack not in {"", "on"}:
            errors["ack_hosted_judge_data_transfer"] = _ui_text(
                "builder_validation.the_hosted_judge_data_transfer_acknowledgement_must_be_an_explici"
            )
        elif hosted_judge_selected and transfer_ack != "on":
            errors["ack_hosted_judge_data_transfer"] = _ui_text(
                "builder_validation.required_acknowledge_that_target_responses_and_source_reference_c"
            )
        elif not hosted_judge_selected and transfer_ack == "on":
            errors["ack_hosted_judge_data_transfer"] = _ui_text(
                "builder_validation.this_acknowledgement_applies_only_to_a_live_hosted_llm_judge"
            )
        if judge_model and judge_model != "mock" and judge_kind is None:
            errors["judge_model"] = _ui_text("builder_validation.unknown_llm_judge_model_selection")
        elif judge_model and "llm" not in judges_list:
            errors["judge_model"] = _ui_text(
                "builder_validation.the_selected_llm_judge_model_requires_enabling_the_llm_judge_stag"
            )
        if live_llm_judge:
            if not judge_model:
                errors["judge_model"] = _ui_text(
                    "builder_validation.choose_an_explicit_hosted_or_local_llm_judge_model"
                )
            elif judge_model == "mock":
                if real_corpora:
                    errors["judge_model"] = _ui_text(
                        "builder_validation.a_real_source_live_lane_cannot_use_the_mock_llm_judge"
                    )
            elif judge_kind is None:
                errors.setdefault(
                    "judge_model", _ui_text("builder_validation.unknown_llm_judge_model_selection")
                )
            elif judge_model in {*api, *local}:
                errors["judge_model"] = _ui_text(
                    "builder_validation.the_llm_judge_must_differ_from_every_target_model"
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
                )
                is not None
                and any(
                    judge_identity & target_identity for target_identity in hosted_target_identities
                )
            ):
                errors["judge_model"] = _ui_text(
                    "builder_validation.the_llm_judge_must_differ_from_every_target_model_after_provider"
                )
            elif (
                judge_kind == "local"
                and (
                    judge_identity := _local_model_identity(
                        judge_model, local_catalog.get(judge_model, {})
                    )
                )
                is not None
                and judge_identity in set(local_target_identities)
            ):
                errors["judge_model"] = _ui_text(
                    "builder_validation.the_llm_judge_must_differ_from_every_target_model_after_immutable"
                )
            elif (
                judge_kind == "local"
                and local
                and (
                    mode
                    not in {
                        "attestation_probe",
                        "diagnostic_canary",
                        "measured",
                    }
                    or canary_dry
                    or "crescendo" in {name.lower() for name in attackers}
                )
            ):
                errors["judge_model"] = _ui_text(
                    "builder_validation.a_local_target_and_a_distinct_local_llm_judge_require_a_response"
                )
            else:
                durable_local_identities = self._catalog_local_identities()
                durable_judge = durable_local_identities.get(
                    judge_model,
                    judge_model,
                )
                durable_targets = {
                    durable_local_identities.get(spec, spec) for spec in (*api, *local)
                }
                if durable_judge in durable_targets:
                    errors["judge_model"] = _ui_text(
                        "builder_validation.the_llm_judge_must_differ_from_every_target_model_after_content_i"
                    )
        local_judge = (
            judge_model
            if live_llm_judge and judge_kind == "local" and judge_model not in local
            else ""
        )
        local_execution_specs = [*local, *([local_judge] if local_judge else [])]
        if local_execution_specs and mode != "dry_run" and not canary_dry and not unknown_local:
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
                    self._validated_local_modalities(spec, entry, project_richer=True)
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
                        (
                            _ui_text("builder_validation.local_target")
                            + f"{spec!r}"
                            + _ui_text(
                                "builder_validation.max_tokens_must_not_exceed_max_model_len"
                            )
                        ),
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
                    _ui_text(
                        "builder_validation.live_local_target_is_known_incompatible_with_this_hardware"
                    )
                    + ", ".join(incompatible),
                )
            elif unknown_fit_without_precision:
                errors.setdefault(
                    local_error_field,
                    _ui_text(
                        "builder_validation.live_local_target_hardware_fit_is_unknown_choose_an_explicit_per"
                    )
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
                    _ui_text(
                        "builder_validation.live_hub_vllm_targets_require_a_40_64_hex_revision_explicit_local"
                    )
                    + ", ".join(unpinned),
                )

        def require_int(field: str, *, positive: bool = False) -> int | None:
            raw = params.get(field, "")
            if not raw:
                return None
            try:
                value = int(raw)
            except ValueError:
                errors[field] = _ui_text("builder_validation.must_be_an_integer")
                return None
            if positive and value <= 0:
                errors[field] = _ui_text("builder_validation.must_be_a_positive_integer")
                return None
            return value

        limit = require_int("limit")
        if limit is not None and limit < 0:
            errors["limit"] = _ui_text("builder_validation.must_be_non_negative")
        group_raw = params.get("group", "")
        if group_raw:
            from experiments.run_matrix import _ALLOWED_GROUP_KEYS  # noqa: PLC0415

            group_keys = self._split_list(group_raw)
            unknown_group_keys = sorted(set(group_keys) - set(_ALLOWED_GROUP_KEYS))
            if not group_keys:
                errors["group"] = _ui_text(
                    "builder_validation.must_name_at_least_one_aggregation_group_key"
                )
            elif len(set(group_keys)) != len(group_keys):
                errors["group"] = _ui_text("builder_validation.group_keys_must_be_unique")
            elif unknown_group_keys:
                errors["group"] = (
                    _ui_text("builder_validation.unsupported_group_key_s")
                    + ", ".join(unknown_group_keys)
                    + _ui_text("builder_validation.allowed")
                    + ", ".join(sorted(_ALLOWED_GROUP_KEYS))
                )
        if params.get("exclude_tool_conditioned", "") not in {"", "on"}:
            errors["exclude_tool_conditioned"] = _ui_text(
                "builder_validation.the_tool_conditioned_exclusion_must_be_an_explicit_checkbox"
            )
        elif params.get("exclude_tool_conditioned") == "on" and mode != "dry_run":
            errors["exclude_tool_conditioned"] = _ui_text(
                "builder_validation.tool_conditioned_row_exclusion_is_available_only_for_a_standalone"
            )
        if params.get("verify_model_sha256", "") not in {"", "on"}:
            errors["verify_model_sha256"] = _ui_text(
                "builder_validation.full_model_sha_verification_must_be_an_explicit_checkbox"
            )
        reset_open_circuits = params.get("reset_open_circuits", "")
        if reset_open_circuits not in {"", "on"}:
            errors["reset_open_circuits"] = _ui_text(
                "builder_validation.the_open_circuit_reset_must_be_an_explicit_checkbox"
            )
        elif reset_open_circuits == "on" and mode != "measured":
            errors["reset_open_circuits"] = _ui_text(
                "builder_validation.clearing_open_circuits_is_a_measured_lane_resume_control_rerun_th"
            )
        require_int("lock_stale_seconds", positive=True)
        sample_seed_value = require_int("sample_seed")
        sampling_policy = params.get("sampling_policy", "")
        if sampling_policy and sampling_policy not in SAMPLING_POLICIES:
            errors["sampling_policy"] = _ui_text(
                "builder_validation.must_be_one_of_the_supported_sampling_policies"
            )
        max_queries_value = require_int("max_queries", positive=True)
        max_turns_value = require_int("max_turns", positive=True)
        target_answer_retries = require_int("target_answer_retries")
        if target_answer_retries is not None and not 0 <= target_answer_retries <= 10:
            errors["target_answer_retries"] = _ui_text(
                "builder_validation.must_be_an_integer_in_0_10"
            )
        elif target_answer_retries is not None and target_answer_retries != 0 and api:
            errors["target_answer_retries"] = _ui_text(
                "builder_validation.paid_hosted_targets_allow_no_answer_quality_retries_set_additiona"
            )
        if ideator_requirements is not None:
            available_pairs, selected_pairs = ideator_requirements
            effective_max_queries = 4 if max_queries_value is None else max_queries_value
            effective_max_turns = 4 if max_turns_value is None else max_turns_value
            if effective_max_queries < selected_pairs:
                errors["max_queries"] = (
                    _ui_text("builder_validation.ideator_selects")
                    + f"{selected_pairs}"
                    + _ui_text("builder_validation.of")
                    + f"{available_pairs}"
                    + _ui_text(
                        "builder_validation.verified_pairs_max_queries_must_cover_every_selected_pair"
                    )
                )
            if effective_max_turns < selected_pairs:
                errors["max_turns"] = (
                    _ui_text("builder_validation.ideator_selects")
                    + f"{selected_pairs}"
                    + _ui_text("builder_validation.of")
                    + f"{available_pairs}"
                    + _ui_text(
                        "builder_validation.verified_pairs_max_turns_must_cover_every_selected_pair"
                    )
                )
        local_budget_raw = params.get("local_budget_hours", "")
        require_int("local_budget_hours", positive=True)
        if local_budget_raw:
            if mode != "measured" or not local or api or hosted_judge_selected:
                errors["local_budget_hours"] = _ui_text(
                    "builder_validation.the_local_process_wall_time_cap_applies_only_to_a_measured_all_lo"
                )
        if harm_requirements is not None:
            captured_corpus, captured_limit, captured_seed, minimum = harm_requirements
            if corpora != [captured_corpus]:
                errors["corpora"] = (
                    _ui_text(
                        "builder_validation.harmbench_replay_requires_exactly_its_captured_corpus_arm"
                    )
                    + captured_corpus
                )
            if limit != captured_limit:
                errors["limit"] = (
                    _ui_text("builder_validation.harmbench_replay_requires_its_captured_limit")
                    + f"{captured_limit}"
                )
            effective_seed = 0 if sample_seed_value is None else sample_seed_value
            if effective_seed != captured_seed:
                errors["sample_seed"] = (
                    _ui_text(
                        "builder_validation.harmbench_replay_requires_its_captured_sample_seed"
                    )
                    + f"{captured_seed}"
                )
            if max_queries_value is None or max_queries_value < minimum:
                errors["max_queries"] = (
                    _ui_text("builder_validation.harmbench_replay_requires_at_least")
                    + f"{minimum}"
                    + _ui_text("builder_validation.queries_methods_x_cases_per_method")
                )
            if max_turns_value is None or max_turns_value < minimum:
                errors["max_turns"] = (
                    _ui_text("builder_validation.harmbench_replay_requires_at_least")
                    + f"{minimum}"
                    + _ui_text("builder_validation.turns_methods_x_cases_per_method")
                )

        raw_seeds = params.get("seeds", "")
        if raw_seeds:
            seed_parts = self._split_list(raw_seeds)
            if not all(re.fullmatch(r"-?\d+", part) for part in seed_parts):
                errors["seeds"] = _ui_text("builder_validation.must_be_a_comma_list_of_integers")
            elif len(set(seed_parts)) != len(seed_parts):
                errors["seeds"] = _ui_text("builder_validation.seeds_must_be_unique")
        scope_value = params.get("scope", "")
        if scope_value and re.search(r"\s", scope_value):
            errors["scope"] = _ui_text("builder_validation.must_not_contain_whitespace")

        def require_hex(field: str) -> None:
            raw = params.get(field, "")
            if raw and not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
                errors[field] = _ui_text("builder_validation.must_be_an_exact_64_hex_sha_256")

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
                    errors[cap] = _ui_text(
                        "builder_validation.required_a_finite_positive_ceiling_before_any_non_dry_run"
                    )

        def require_live_admission() -> None:
            if not params.get("scope", ""):
                errors["scope"] = _ui_text("builder_validation.required_for_live_execution")
            age = params.get("max_age", "")
            try:
                age_value = float(age) if age else 0.0
            except ValueError:
                age_value = 0.0
            if not 0 < age_value <= 8760:
                errors["max_age"] = _ui_text(
                    "builder_validation.required_maximum_attestation_age_in_hours_in_0_8760"
                )
            if not att_rows and not (preparation and params.get("setup_mode") == "automatic"):
                errors["att"] = (
                    _ui_text(
                        "builder_validation.no_matching_completed_transport_checks_are_available_for_this_sel"
                    )
                    if params.get("setup_mode") == "automatic"
                    else _ui_text(
                        "builder_validation.at_least_one_live_attestation_receipt_digest_pair_is_required"
                    )
                )
            if not has_project:
                errors["project_revision"] = _ui_text(
                    "builder_validation.required_validated_project_revision_receipt_and_digest_field_or_c"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = _ui_text(
                    "builder_validation.required_validated_source_conformance_receipt_and_digest_for_real"
                )
            require_caps_and_deadline()

        for path, sha in att_rows:
            if not path or not sha:
                errors["att"] = _ui_text(
                    "builder_validation.every_receipt_row_needs_both_the_receipt_path_and_its_exact_64_he"
                )
            elif not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                errors["att"] = _ui_text(
                    "builder_validation.receipt_digest_must_be_an_exact_64_hex_sha_256"
                )

        if not params.get("out", ""):
            errors["out"] = _ui_text("builder_validation.required_output_directory_for_this_run")
        if not corpora and not canary_dry:
            # A dry canary composes the synthetic corpus itself, so it needs
            # no arm checkbox; every other lane must select at least one arm.
            errors["corpora"] = _ui_text("builder_validation.select_at_least_one_corpus_arm")
        if not attackers:
            errors["attackers"] = _ui_text(
                "builder_validation.select_at_least_one_attack_framework"
            )
        if not judges_list:
            errors["judges"] = _ui_text("builder_validation.select_at_least_one_judge")
        if len(local) > 1:
            errors.setdefault(
                "models",
                (
                    _ui_text(
                        "builder_validation.one_local_target_per_process_vllm_ollama_engines_must_not_accumul"
                    )
                ),
            )

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
                + (_ui_text("builder_validation.is_a") if len(native_selected) == 1 else "are")
                + _ui_text(
                    "builder_validation.native_artifact_integration_s_run_matrix_cannot_replay_them_throu"
                )
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
                    _ui_text("builder_validation.arm")
                    + f"{arm}"
                    + _ui_text("builder_validation.is_blocked_by_the_bound_source_receipt")
                    + f"{disposition[1]}"
                )
                continue
            if arm in _INELIGIBLE_ARMS:
                if not approximate_common_metrics_enabled:
                    errors["approximate_common_metrics"] = (
                        f"{arm}"
                        + _ui_text("builder_validation.is_common_metric_ineligible")
                        + f"{_INELIGIBLE_REASONS[arm]}"
                        + _ui_text(
                            "builder_validation.select_the_explicit_approximate_common_security_metrics_opt_in_to"
                        )
                    )
                    continue
            if arm in _SOURCE_METRIC_ARMS:
                metric, allowed = _SOURCE_METRIC_ARMS[arm]
                unsupported = [a for a in attackers if a not in allowed]
                if unsupported:
                    errors["attackers"] = (
                        _ui_text("builder_validation.arm")
                        + f"{arm}"
                        + _ui_text("builder_validation.is_scored_only_by_the_implemented")
                        + f"{metric}"
                        + _ui_text(
                            "builder_validation.source_metric_which_run_matrix_admits_solely_for_the"
                        )
                        + f"{'/'.join(allowed)}"
                        + _ui_text("builder_validation.attacker_remove")
                        + f"{', '.join(unsupported)}"
                        + _ui_text("builder_validation.or_the_grid_contains_unscored_cells")
                    )
            needed = arm_mods.get(arm)
            if needed is None:
                continue  # unknown arm id: left to the CLI's own registry check
            if "tool" in needed:
                errors["corpora"] = (
                    _ui_text("builder_validation.arm")
                    + f"{arm}"
                    + _ui_text(
                        "builder_validation.converts_to_a_text_tool_source_construct_but_the_maintained_runne"
                    )
                )
                continue
            for kind, target in [("api", value) for value in api] + [
                ("local", value) for value in local
            ]:
                have = target_mods.get((kind, target))
                if have is not None and not needed <= have:
                    errors["models"] = (
                        _ui_text("builder_validation.target")
                        + f"{target}"
                        + _ui_text("builder_validation.serves")
                        + f"{sorted(have) or ['text']}"
                        + _ui_text("builder_validation.but_arm")
                        + f"{arm}"
                        + _ui_text("builder_validation.requires_all_of")
                        + f"{sorted(needed)}"
                    )
            for attacker in attackers:
                can = fw_mods.get(attacker)
                if can is not None and not needed <= can:
                    errors["attackers"] = (
                        _ui_text("builder_validation.attacker")
                        + f"{attacker}"
                        + _ui_text("builder_validation.drives")
                        + f"{sorted(can)}"
                        + _ui_text("builder_validation.but_arm")
                        + f"{arm}"
                        + _ui_text("builder_validation.requires_all_of")
                        + f"{sorted(needed)}"
                    )
        if "guardrail" in judges_list:
            from ura.guardrail_setup import resolve_scoring_settings, GuardrailSetupError

            try:
                params = resolve_scoring_settings(dict(params))
            except GuardrailSetupError as exc:
                errors["guardrail_model"] = str(exc)
                return errors
        scoring_guardrail = "guardrail" in judges_list
        defense_guardrail = params.get("defense_guard", "") == "guardrail" and params.get(
            "defense", ""
        ) not in ("", "none")
        if defense_guardrail:
            if not params.get("defense_guardrail_model", ""):
                errors["defense_guardrail_model"] = _ui_text(
                    "builder_validation.the_defense_guardrail_requires_a_defense_guardrail_model"
                )
            if (
                re.fullmatch(
                    r"[0-9a-fA-F]{40,64}",
                    params.get("defense_guardrail_revision", ""),
                )
                is None
            ):
                errors["defense_guardrail_revision"] = _ui_text(
                    "builder_validation.the_defense_guardrail_requires_an_immutable_40_64_hex_revision"
                )
            if not params.get("defense_guardrail_device", ""):
                errors["defense_guardrail_device"] = _ui_text(
                    "builder_validation.the_defense_guardrail_requires_an_explicit_device"
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
            errors["defense_guardrail_model"] = _ui_text(
                "builder_validation.the_scoring_guard_and_the_defense_guard_must_be_distinct_models_a"
            )
        if (
            mode != "dry_run"
            and not canary_dry
            and real_corpora
            and "llm" in judges_list
            and params.get("judge_model", "").strip().lower() == "mock"
        ):
            errors["judge_model"] = _ui_text(
                "builder_validation.a_real_source_live_lane_cannot_use_the_mock_llm_judge"
            )

        no_call_mode = mode == "dry_run" or canary_dry
        if no_call_mode and scoring_guardrail:
            errors["judges"] = _ui_text(
                "builder_validation.a_no_call_dry_lane_cannot_load_a_model_backed_scoring_guardrail"
            )
        if no_call_mode and defense_guardrail:
            errors["defense_guard"] = _ui_text(
                "builder_validation.a_no_call_dry_lane_cannot_load_a_model_backed_defense_guardrail"
            )
        if no_call_mode and "nanogcg" in attackers and not params.get("nanogcg_suffix", "").strip():
            errors["nanogcg"] = _ui_text(
                "builder_validation.a_no_call_dry_lane_permits_nanogcg_only_as_an_exact_precomputed_s"
            )

        if mode == "dry_run":
            forbid_live_fields(
                _ui_text(
                    "builder_validation.a_diagnostic_dry_run_cannot_consume_or_produce_live_attestation"
                )
            )
        elif mode == "attestation_probe":
            if targets != 1:
                errors["models"] = _ui_text(
                    "builder_validation.an_attestation_probe_takes_exactly_one_target"
                )
            if len(corpora) != 1:
                errors["corpora"] = _ui_text(
                    "builder_validation.an_attestation_probe_takes_exactly_one_corpus"
                )
            if attackers != ["replay"]:
                errors["attackers"] = _ui_text(
                    "builder_validation.an_attestation_probe_uses_exactly_the_replay_attacker"
                )
            if len(seeds) != 1:
                errors["seeds"] = _ui_text(
                    "builder_validation.an_attestation_probe_takes_exactly_one_seed"
                )
            if params.get("defense", "none") != "none":
                errors["defense"] = _ui_text(
                    "builder_validation.an_attestation_probe_requires_defense_none"
                )
            if limit not in {1, 2}:
                errors["limit"] = _ui_text(
                    "builder_validation.an_attestation_probe_requires_limit_1_or_2"
                )
            if params.get("max_queries", "") not in {"", "1"}:
                errors["max_queries"] = _ui_text(
                    "builder_validation.an_attestation_probe_uses_one_query"
                )
            if params.get("max_turns", "") not in {"", "1"}:
                errors["max_turns"] = _ui_text(
                    "builder_validation.an_attestation_probe_uses_one_turn"
                )
            if not params.get("scope", ""):
                errors["scope"] = _ui_text("builder_validation.required_execution_scope_id")
            if not has_project:
                errors["project_revision"] = _ui_text(
                    "builder_validation.required_validated_project_revision_receipt_and_digest"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = _ui_text(
                    "builder_validation.required_for_a_real_source_probe_corpus"
                )
            if att_rows:
                errors["att"] = _ui_text(
                    "builder_validation.an_attestation_probe_cannot_consume_prior_attestations"
                )
            if params.get("max_age", ""):
                errors["max_age"] = _ui_text(
                    "builder_validation.an_attestation_probe_cannot_consume_prior_attestations"
                )
            require_caps_and_deadline()
        elif mode == "diagnostic_canary":
            if limit != 1:
                errors["limit"] = _ui_text(
                    "builder_validation.a_diagnostic_canary_requires_exactly_limit_1_all_rows_in_that_sou"
                )
            if len(attackers) != 1:
                errors["attackers"] = _ui_text(
                    "builder_validation.a_diagnostic_canary_takes_exactly_one_attacker"
                )
            if len(seeds) != 1:
                errors["seeds"] = _ui_text(
                    "builder_validation.a_diagnostic_canary_takes_exactly_one_seed"
                )
            if canary_dry:
                # The dry canary is composed as offline-synthetic (corpora
                # synth, no targets, no receipts): the operator only picks the
                # attacker/seed/limit, so no arm or target selection is
                # required, and live-attestation fields are forbidden.
                forbid_live_fields(
                    _ui_text(
                        "builder_validation.a_dry_canary_cannot_consume_or_produce_live_attestation"
                    )
                )
            else:
                if len(corpora) != 1:
                    errors["corpora"] = _ui_text(
                        "builder_validation.a_live_canary_takes_exactly_one_corpus"
                    )
                if targets != 1:
                    errors["models"] = _ui_text(
                        "builder_validation.a_live_canary_takes_exactly_one_target_model"
                    )
                require_live_admission()
        else:  # measured execution
            if targets < 1:
                errors["models"] = _ui_text("builder_validation.select_at_least_one_target_model")
            require_live_admission()
            paid_hosted_route = bool(api) or hosted_judge_selected
            if paid_hosted_route and limit is None:
                errors["limit"] = _ui_text(
                    "builder_validation.hosted_paid_lanes_must_carry_an_explicit_limit_use_a_positive_pre"
                )
            if (
                paid_hosted_route
                and limit is not None
                and limit > 0
                and not params.get("sample_seed", "")
            ):
                errors["sample_seed"] = _ui_text(
                    "builder_validation.hosted_paid_lanes_must_record_sample_seed_identical_subset_only_f"
                )
            elif limit is not None and limit > 0 and not params.get("sample_seed", ""):
                errors["sample_seed"] = _ui_text(
                    "builder_validation.bounded_measured_lanes_must_record_sample_seed_the_value_selects"
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
            return None, _ui_text(
                "builder_validation.select_an_output_directory_and_run_the_preflight"
            )
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
                _ui_text(
                    "builder_validation.no_successful_no_call_preflight_for_these_exact_selections_run_th"
                )
            )
        prefix = _ui_text("builder_validation.prospective_no_call_lane_projection_written")
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
        return None, _ui_text(
            "builder_validation.the_matching_preflight_s_lane_projection_is_missing_or_invalid"
        )

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
        local_configs = {spec: catalog[spec] for spec in selected_local if spec in catalog}
        attacker_configs = self._prepared_attacker_entries(params)
        scoring_guardrail = "guardrail" in judges
        defense_guardrail = params.get("defense_guard", "") == "guardrail" and params.get(
            "defense", ""
        ) not in {"", "none"}
        requirements = collect_run_requirements(
            target_specs=targets,
            local_configs=local_configs,
            judge_names=judges,
            judge_model=judge_model,
            attacker_names=attackers,
            attacker_configs=attacker_configs,
            guardrail_model=(params.get("guardrail_model", "") if scoring_guardrail else None),
            guardrail_revision=(
                params.get("guardrail_revision", "") if scoring_guardrail else None
            ),
            defense_guardrail_model=(
                params.get("defense_guardrail_model", "") if defense_guardrail else None
            ),
            defense_guardrail_revision=(
                params.get("defense_guardrail_revision", "") if defense_guardrail else None
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
            f"{len(api) + len(local)}"
            + _ui_text("builder_validation.target_s_x")
            + f"{len(corpora)}"
            + _ui_text("builder_validation.corpus_arm_s_x")
            + f"{len(attackers)}"
            + _ui_text("builder_validation.attacker_s_x")
            + f"{len(seeds)}"
            + _ui_text("builder_validation.seed_s")
            + f"{grid_cells * max(1, len(seeds))}"
            + _ui_text("builder_validation.planned_cell_seed_lanes")
        )
        rows = "".join(
            f"<tr><td><code>{html.escape(flag)}</code></td>"
            f"<td><strong>{html.escape(params.get(field, '') or '(unset)')}"
            "</strong></td><td>" + html.escape(note) + "</td></tr>"
            for field, flag, note in (
                (
                    "cap_target",
                    "--max-total-target-calls",
                    _ui_text("builder_validation.hard_circuit_breaker_on_model_under_test_calls"),
                ),
                (
                    "cap_judge",
                    "--max-total-judge-calls",
                    _ui_text(
                        "builder_validation.hard_circuit_breaker_on_model_backed_judge_calls_hosted_or_local"
                    ),
                ),
                (
                    "cap_http",
                    "--max-total-http-attempts",
                    _ui_text("builder_validation.hard_cap_on_transport_attempts_retries_included"),
                ),
                (
                    "local_budget_hours",
                    _ui_text("builder_validation.controller_wall_time"),
                    _ui_text(
                        "builder_validation.detached_process_wall_time_cap_in_whole_hours_for_the_final_measu"
                    ),
                ),
                (
                    "deadline",
                    "--deadline-seconds",
                    _ui_text(
                        "builder_validation.durable_call_start_window_from_first_invocation_not_a_completion"
                    ),
                ),
                (
                    "limit",
                    "--limit",
                    _ui_text(
                        "builder_validation.cluster_subsample_per_corpus_cluster_sibling_rows_are_all_retaine"
                    ),
                ),
                (
                    "max_queries",
                    "--max-queries",
                    _ui_text("builder_validation.target_calls_per_datapoint_and_seed"),
                ),
                (
                    "max_turns",
                    "--max-turns",
                    _ui_text("builder_validation.conversation_turns_per_datapoint_and_seed"),
                ),
                (
                    "target_answer_retries",
                    "--target-answer-retries",
                    _ui_text(
                        "builder_validation.additional_attempts_for_unusable_output_default_1"
                    ),
                ),
                (
                    "ideator_pair_limit",
                    _ui_text("builder_validation.ideator_pair_limit"),
                    _ui_text(
                        "builder_validation.0_selects_the_complete_verified_manifest_positive_n_selects_order"
                    ),
                ),
            )
        )
        # No-call projection: the required upper bounds from the CLI preflight
        # (never estimated here).  Compare each entered ceiling against its
        # projected requirement; a shortfall blocks Start.
        projection, why = self._read_lane_projection(params)
        caps_ok = projection is not None and not (
            params.get("automatic_caps") == "on" and params.get("_caps_resolved") != "yes"
        )
        if projection is not None:
            call_projection = projection.get("call_projection", projection)
            if not isinstance(call_projection, Mapping):
                raise ValueError(
                    _ui_text(
                        "builder_validation.validated_lane_projection_call_inventory_is_invalid"
                    )
                )
            proj_rows = []
            for label, cap_field, proj_key in (
                (_ui_text("builder_validation.target_calls"), "cap_target", "target_calls"),
                (_ui_text("builder_validation.judge_calls"), "cap_judge", "judge_calls"),
                (_ui_text("builder_validation.http_attempts"), "cap_http", "http_attempts"),
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
                        _ui_template(
                            "<span class='badge green'>[[text:builder_validation.covers]]</span>"
                        )
                        if covers
                        else _ui_template(
                            "<span class='badge red'>[[text:builder_validation.below_required]]</span>"
                        )
                    )
                    + "</td></tr>"
                )
            projection_html = (
                _ui_template(
                    "<h3>[[text:builder_validation.no_call_projection_from_the_cli_preflight]]</h3><div class='scroll'><table><tr><th>[[text:builder_validation.call_kind]]</th><th>[[text:builder_validation.projected_required]]</th><th>[[text:builder_validation.your_ceiling]]</th><th></th></tr>"
                )
                + "".join(proj_rows)
                + "</table></div>"
                + (
                    ""
                    if caps_ok
                    else _ui_template(
                        "<div class='notice red'><strong>[[text:builder_validation.a_ceiling_is_below_the_projected_requirement]]</strong><p class='note'>[[text:builder_validation.raise_the_flagged_ceiling_s_to_at_least_the_projected_upper_bound]]</p></div>"
                    )
                )
            )
        else:
            projection_html = (
                _ui_template(
                    "<h3>[[text:builder_validation.no_call_projection]]</h3><p class='note'>"
                )
                + html.escape(why)
                + ".</p>"
            )
        from .direct_costs import forecast

        cost_card = forecast(self, params, projection)
        return (
            "<div class='card'><h2>"
            + _icon("coins")
            + (
                _ui_template("[[text:builder_validation.calculated_call_ceilings]]</h2><p><strong>")
                + f"{html.escape(shape)}"
                + _ui_template(
                    "</strong></p><div class='scroll'><table><tr><th>[[text:builder_validation.ceiling]]</th><th>[[text:builder_validation.value]]</th><th>[[text:builder_validation.meaning]]</th></tr>"
                )
            )
            + rows
            + "</table></div>"
            + projection_html
            + _ui_template(
                "<p class='note'>[[text:builder_validation.the_entered_ceilings_are_the_binding_budget_guards_run_matrix_rej]]</p></div>"
            )
            + cost_card
        ), caps_ok

    def _preview_page(
        self,
        command: str,
        values: Mapping[str, str],
        params: Mapping[str, str],
        *,
        prepared: bool = False,
        held_snapshot: Mapping[str, bytes] | None = None,
    ) -> bytes:
        """Durable argv identity + ceilings confirmation before a paid start."""

        if held_snapshot is not None:
            reviewed_params = dict(params)
            execution_snapshot = self._validate_execution_snapshot(params, held_snapshot)
        else:
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
        ) = self._durable_launch_state(command, values, reviewed_params)
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in argv)
            + "</div>"
        )
        params = reviewed_params
        mode = params.get("mode", "measured")
        offline = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        ceilings_html, caps_ok = (
            (
                _ui_template(
                    "<p class='notice blue'>[[text:builder_validation.offline_test_no_provider_calls_or_charges_mock_outputs_are_diagno]]</p>"
                ),
                True,
            )
            if offline
            else self._ceilings_card(params)
        )
        needs_acquisition = self._builder_model_acquisition_required(params)

        def ticket_input(token: str) -> str:
            return "<input type='hidden' name='launch_ticket' value='" + html.escape(token) + "'>"

        if needs_acquisition:
            preflight_hidden = ticket_input(
                self._new_launch_ticket(
                    {**params, "_model_acquisition_next": "preflight"},
                    purpose="acquisition_plan",
                    execution_snapshot=execution_snapshot,
                )
            )
            start_hidden = ticket_input(
                self._new_launch_ticket(
                    {**params, "_model_acquisition_next": "run"},
                    purpose="acquisition_plan",
                    execution_snapshot=execution_snapshot,
                )
            )
            preflight_action = "/build/model-acquisition/plan"
            start_action = "/build/model-acquisition/plan"
            preflight_extra = ""
            start_extra = ""
            acquisition_notice = _ui_template(
                "<div class='notice blue'><strong>[[text:builder_validation.sealed_model_acquisition_is_required]]</strong><p class='note'>[[text:builder_validation.the_next_job_derives_a_public_immutable_plan_without_loading_a_mo]]</p></div>"
            )
            preflight_label = _ui_text(
                "builder_validation.plan_acquire_models_for_no_call_preflight"
            )
            start_label = _ui_text("builder_validation.plan_acquire_models_for_this_job")
        else:
            hidden = ticket_input(
                self._new_launch_ticket(
                    params,
                    execution_snapshot=execution_snapshot,
                )
            )
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
            preflight_label = _ui_text(
                "builder_validation.run_no_call_preflight_projection_no_calls"
            )
            start_label = (
                _ui_text("builder_validation.start_campaign_run")
                if params.get("campaign_id")
                else _ui_text("builder_validation.start_single_run")
            )
        # A "Run no-call preflight" action composes the SAME grid with
        # --preflight-only (no calls) so the operator can produce the projection
        # this page reads and compares against.
        preflight_form = (
            f"<form method='post' action='{preflight_action}'>"
            + preflight_hidden
            + preflight_extra
            + _ui_template(
                "<button type='submit' class='ghost' data-busy='[[attr:builder_validation.preparing_the_sealed_model_workflow]]'>"
            )
            + _icon("pulse", size=15)
            + html.escape(preflight_label)
            + "</button></form> "
        )
        if offline:
            preflight_form = ""
        start_button = (
            "<button type='submit'>"
            + _icon("play", size=15)
            + html.escape(start_label)
            + "</button>"
            if caps_ok
            else "<button type='submit' disabled>"
            + _icon("play", size=15)
            + _ui_template(
                "[[text:builder_validation.start_blocked_run_preflight_cover_its_projection]]</button>"
            )
        )
        body = (
            "<h1>"
            + _icon("play", size=22)
            + _ui_template("[[text:builder_validation.review_execution]]</h1>")
            + (
                _ui_template(
                    "<div class='notice blue'><strong>[[text:builder_validation.this_is_an_offline_test]]</strong>"
                )
                if offline
                else _ui_template(
                    "<div class='notice amber'><strong>[[text:builder_validation.this_execution_makes_real_model_calls_api_calls_may_incur_charges]]</strong>"
                )
            )
            + (
                _ui_template("<p class='note'>[[text:builder_validation.mode]] <code>")
                + f"{html.escape(mode)}"
                + _ui_template(
                    "</code>[[text:builder_validation.review_the_exact_command_and_ceilings_below_nothing_has_started_y]]</p></div>"
                )
            )
            + acquisition_notice
            + self._campaign_banner(params.get("campaign_id", ""))
            + _ui_template(
                "<section class='card'><h2>[[text:builder_validation.experiment]]</h2><dl class='builder-summary'>"
            )
            + "".join(
                "<div><dt>"
                + label
                + "</dt><dd>"
                + html.escape(
                    (_retained_params or {}).get(key) or _ui_text("builder_validation.not_set")
                )
                + "</dd></div>"
                for key, label in (
                    ("local", _ui_text("builder_validation.local_models")),
                    ("api", _ui_text("builder_validation.api_models")),
                    ("corpora", _ui_text("builder_validation.arms_corpora")),
                    ("attackers", _ui_text("builder_validation.frameworks_attacks")),
                    ("seeds", _ui_text("builder_validation.seeds")),
                    ("sampling_policy", _ui_text("builder_validation.sampling")),
                    ("limit", _ui_text("builder_validation.per_arm_limit")),
                    ("judges", _ui_text("builder_validation.judges")),
                    ("judge_model", _ui_text("builder_validation.judge_model")),
                )
            )
            + "</dl></section>"
            + "<div class='card'><h2>"
            + _icon("terminal")
            + _ui_template("[[text:builder_validation.durable_command_identity]]</h2>")
            + argv_chips
            + _ui_template(
                "<p class='note'>[[text:builder_validation.explicit_workstation_checkpoint_locators_are_shown_and_retained_o]]</p>"
            )
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
            + _ui_template(
                "'><button class='ghost'>[[text:builder_validation.edit_configuration]]</button></form>"
            )
        )
        if not offline and not prepared:
            # The technical stages remain inspectable, not operator tasks.
            # Keep the existing endpoints for older reviewed jobs and advanced use.
            title_end = body.index("</h1>") + len("</h1>")
            preparation_ticket = ticket_input(
                self._new_launch_ticket(
                    params, purpose="automatic-preparation", execution_snapshot=execution_snapshot
                )
            )
            summary_start = body.index(
                _ui_template(
                    "<section class='card'><h2>[[text:builder_validation.experiment]]</h2>"
                )
            )
            summary_end = body.index("</section>", summary_start) + len("</section>")
            automatic = (
                self._campaign_banner(params.get("campaign_id", ""))
                + body[summary_start:summary_end]
                + _ui_template(
                    '<section class="card"><h2>[[text:builder_validation.prepare_this_run_automatically]]</h2><p>[[text:builder_validation.the_console_reuses_installed_models_checks_the_workload_and_prepa]]</p><form class="action-row" method="post" action="/build/prepare-automatic">'
                )
                + preparation_ticket
                + _ui_template(
                    '<button data-busy="[[attr:builder_validation.starting_automatic_preparation]]">[[text:builder_validation.prepare_and_review]]</button></form></section>'
                )
                + self._operation_links(params.get("campaign_id", ""))
            )
            body = (
                body[:title_end]
                + automatic
                + _ui_template(
                    '<details class="card"><summary>[[text:builder_validation.technical_preparation_details]]</summary>'
                )
                + body[title_end:]
                + "</details>"
            )
        return _page(
            _ui_text("builder_validation.confirm_execution"),
            body,
            active=_ui_text("builder_validation.build"),
        )
