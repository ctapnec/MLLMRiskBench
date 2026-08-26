"""Local model roster and prepared-attacker configuration helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Mapping

from ura.attacker_input_contract import media_input_identity
from ura.data_models import MediaRef
from ura.strict_json import strict_json_loads
from ura.adapters.nanogcg import LIVE_NANOGCG_DISABLED_MESSAGE
from ura.adapters.ideator_manifest import (
    FORMAT_VERSION as IDEATOR_MAPPED_FORMAT,
    materialize_runner_attacker_config,
    validate_manifest as validate_ideator_mapped_manifest,
)


_RUNNER_ATTACKER_CONFIG_MAX_BYTES = 1024 * 1024
_IDEATOR_SERIALIZED_TEXT_BUDGET_BYTES = (
    _RUNNER_ATTACKER_CONFIG_MAX_BYTES // 2
)


class BuilderModelsMixin:
    def _load_registry(self, name: str, example: str) -> dict[str, Any]:
        """Parse an operator-local registry, falling back to its example."""

        if name == "local-targets.json":
            # One resolution order for the local registry, shared with the CLI
            # listing, so the two surfaces cannot come to offer different
            # local targets for the same rig.
            from experiments.local_targets import load_local_registry  # noqa: PLC0415

            return dict(load_local_registry(self.repo_root))
        for candidate in (name, example):
            path = self.repo_root / "experiments" / candidate
            try:
                data = strict_json_loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return data
        return {}

    @staticmethod
    def _entry_modalities(entry: Any) -> tuple[str, ...]:
        if isinstance(entry, dict) and isinstance(entry.get("modalities"), list):
            mods = tuple(str(m) for m in entry["modalities"] if isinstance(m, str))
            if mods:
                return mods
        return ("text",)

    def _vllm_roster_version(self) -> str | None:
        try:
            from experiments.local_targets import roster_version  # noqa: PLC0415

            return roster_version(self.repo_root)
        except Exception:  # noqa: BLE001 - convenience metadata only
            return None

    def _ollama_roster_snapshot(self, *, force: bool = False) -> dict[str, object]:
        """Return exact daemon-backed candidates after vLLM de-duplication."""

        from experiments.local_targets import load_roster, _models_map  # noqa: PLC0415

        vllm = {
            str(spec): dict(entry)
            for spec, entry in _models_map(load_roster(self.repo_root)).items()
            if str(spec).startswith("vllm:") and isinstance(entry, dict)
        }
        return self.ollama.roster(vllm, force=force)

    def _ollama_overlap_warning(
        self, spec: str, entry: Mapping[str, object] | None = None
    ) -> str:
        """Explain a normalized manual Ollama/vLLM identity overlap."""

        if not spec.startswith("ollama:"):
            return ""
        from experiments.local_targets import load_roster, _models_map  # noqa: PLC0415
        from .ollama_service import ollama_overlap_specs, vllm_identity_index

        vllm = {
            str(candidate): dict(value)
            for candidate, value in _models_map(load_roster(self.repo_root)).items()
            if str(candidate).startswith("vllm:") and isinstance(value, dict)
        }
        identity_details: dict[str, object] = {}
        nested_details = (entry or {}).get("details")
        if isinstance(nested_details, Mapping):
            identity_details.update(nested_details)
        for key in ("architecture", "family", "families"):
            if key in (entry or {}):
                identity_details[key] = (entry or {})[key]
        overlaps = ollama_overlap_specs(
            spec.removeprefix("ollama:"),
            identity_details,
            vllm_identity_index(vllm),
        )
        if not overlaps:
            return ""
        return (
            "normalized Ollama identity overlaps vLLM roster: "
            + ", ".join(overlaps)
            + "; Ollama execution is disabled for this identity"
        )

    def _model_options(self) -> list[tuple[str, str, tuple[str, ...], str]]:
        """Selectable targets as (spec, label, modalities, kind).

        ``kind`` is 'api' for hosted routes (composed into --api) or 'local'
        for on-rig vLLM or Ollama targets (composed into --local). Modalities come from
        each roster entry so the builder can hide a target that cannot handle a
        selected modality. Local targets are the hand-configured local-targets
        registry plus the vLLM roster (the models the rig's vLLM can serve;
        Hub-backed choices require an explicit sealed acquisition job). The focal Anthropic/OpenAI
        pair are the inherent env adapters if exported.
        """

        from experiments.local_targets import roster_models  # noqa: PLC0415

        options: list[tuple[str, str, tuple[str, ...], str]] = []
        api_registry = self._load_registry("api-targets.json", "rig/api-targets.example.json")
        api_seen: set[str] = set()
        for env_name, label in (("FABLE", "Fable (focal)"), ("SOL", "Sol (focal)")):
            spec = os.environ.get(env_name, "").strip()
            if spec and spec not in api_seen:
                api_seen.add(spec)
                # If the focal route is also in the maintained registry, its
                # declared modalities are authoritative.  A blanket text+image
                # assumption can otherwise admit an impossible paid lane.
                entry = api_registry.get(spec)
                modalities = (
                    self._entry_modalities(entry)
                    if isinstance(entry, Mapping)
                    else ("text", "image")
                )
                options.append((spec, label, modalities, "api"))
        for key, entry in api_registry.items():
            if key in api_seen:  # a focal spec already listed: do not duplicate
                continue
            api_seen.add(key)
            options.append((key, key, self._entry_modalities(entry), "api"))
        local_seen: set[str] = set()
        for key, entry in self._load_registry(
            "local-targets.json", "rig/local-targets.example.json"
        ).items():
            local_seen.add(key)
            # The local harness currently renders text and image inputs. Keep
            # richer roster metadata in its source file, but advertise only
            # the physical modalities this target adapter can actually send.
            supported = tuple(
                modality
                for modality in self._entry_modalities(entry)
                if modality in {"text", "image"}
            )
            # Keep an explicitly configured but invalid row visible so Build
            # can disable it and explain the exact config error. Dropping it
            # would falsely claim that no local target was configured.
            options.append((key, key, supported or ("text",), "local"))
        try:
            # Keep the full roster in the document. The checked-by-default
            # compatibility filter hides non-fitting rows, and disabling them
            # keeps execution admission honest when the filter is opened.
            roster = roster_models(
                self.repo_root,
                self.gpu_hardware,
                include_unfit=True,
            )
        except Exception:  # noqa: BLE001 - roster is a convenience, never fatal
            roster = []
        for model in roster:
            spec = str(model["spec"])
            if spec in local_seen:
                continue
            local_seen.add(spec)
            mods = tuple(
                str(modality)
                for modality in model.get("modalities", ["text"])
                if str(modality) in {"text", "image"}
            )
            if mods:
                options.append((spec, spec, mods, "local"))
        live_ollama = self._ollama_roster_snapshot()
        for model in live_ollama.get("models", []):
            if not isinstance(model, dict):
                continue
            spec = str(model.get("spec", ""))
            if not spec.startswith("ollama:") or spec in local_seen:
                continue
            modalities = model.get("modalities")
            mods = (
                tuple(
                    str(modality)
                    for modality in modalities
                    if modality in {"text", "image"}
                )
                if isinstance(modalities, list)
                else ()
            )
            if mods:
                local_seen.add(spec)
                options.append((spec, spec, mods, "local"))
        return options

    def _local_entry_catalog(
        self,
    ) -> tuple[dict[str, dict[str, object]], set[str]]:
        """Merged vLLM catalog and specs explicitly maintained by the operator."""

        from experiments.local_targets import load_roster, _models_map  # noqa: PLC0415

        roster = _models_map(load_roster(self.repo_root))
        catalog = {
            str(spec): dict(entry) for spec, entry in roster.items() if isinstance(entry, dict)
        }
        configured = self._load_registry("local-targets.json", "rig/local-targets.example.json")
        explicit = {str(spec) for spec, entry in configured.items() if isinstance(entry, dict)}
        live_ollama = self._ollama_roster_snapshot()
        for model in live_ollama.get("models", []):
            if not isinstance(model, dict):
                continue
            spec = str(model.get("spec", ""))
            digest = model.get("digest")
            modalities = model.get("modalities")
            if (
                spec.startswith("ollama:")
                and isinstance(digest, str)
                and isinstance(modalities, list)
            ):
                catalog[spec] = {
                    "digest": digest,
                    "modalities": list(modalities),
                }
        for spec, entry in configured.items():
            if isinstance(entry, dict):
                catalog[str(spec)] = dict(entry)
        return catalog, explicit

    def _effective_local_profile(
        self,
        spec: str,
        entry: Mapping[str, object],
        *,
        default_quantization: str = "",
        model_quantization: str = "",
    ) -> dict[str, object]:
        """Resolve one model exactly as the generated local config does."""

        from experiments.local_targets import (  # noqa: PLC0415
            installed_vllm_version,
            model_hardware_profile,
        )

        profile_entry = dict(entry)
        if "quantization" in profile_entry:
            profile_entry["quantization"] = self._validated_local_quantization(
                spec,
                profile_entry["quantization"],
                label="configured quantization",
            )
        model_override = self._validated_local_quantization(
            spec, model_quantization, label="per-model quantization"
        )
        default_override = self._validated_local_quantization(
            spec, default_quantization, label="default quantization"
        )
        if model_override and model_override != "auto":
            profile_entry["quantization"] = model_override
        elif model_override == "auto":
            profile_entry.pop("quantization", None)
        return model_hardware_profile(
            spec,
            profile_entry,
            self.gpu_hardware,
            default_quantization=default_override,
            runtime_version=(installed_vllm_version() or self._vllm_roster_version()),
        )

    @staticmethod
    def _validated_local_quantization(
        spec: str,
        value: object,
        *,
        label: str,
    ) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if not isinstance(value, str) or normalized not in {
            "",
            "auto",
            "none",
            "fp8",
            "bitsandbytes",
            "awq",
            "gptq",
        }:
            raise ValueError(
                f"local target {spec!r} {label} must be auto, none, fp8, "
                "bitsandbytes, awq, or gptq"
            )
        return normalized

    @staticmethod
    def _local_max_model_len(
        spec: str, entry: Mapping[str, object]
    ) -> int | None:
        """Validate an optional per-model vLLM context/KV allocation cap."""

        if "max_model_len" not in entry:
            return None
        from ura.targets.local import validate_vllm_max_model_len  # noqa: PLC0415

        try:
            return validate_vllm_max_model_len(entry["max_model_len"])
        except ValueError as exc:
            raise ValueError(f"local target {spec!r} {exc}") from exc

    @staticmethod
    def _local_max_tokens(spec: str, entry: Mapping[str, object]) -> int:
        """Validate the vLLM generation cap with the shared CLI contract."""

        from ura.targets.local import validate_vllm_max_tokens  # noqa: PLC0415

        try:
            return validate_vllm_max_tokens(entry.get("max_tokens", 512))
        except ValueError as exc:
            raise ValueError(f"local target {spec!r} {exc}") from exc

    @staticmethod
    def _local_gpu_memory_utilization(
        spec: str, entry: Mapping[str, object]
    ) -> float:
        """Validate the vLLM allocation fraction with the shared CLI bounds."""

        value = entry.get("gpu_memory_utilization", 0.90)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0.1 <= float(value) <= 0.95
        ):
            raise ValueError(
                f"local target {spec!r} gpu_memory_utilization must be in "
                "[0.1, 0.95]"
            )
        return float(value)

    @staticmethod
    def _validated_local_modalities(
        spec: str,
        entry: Mapping[str, object],
        *,
        project_richer: bool = False,
    ) -> list[str]:
        """Return the strict text/image declaration consumed by the Runner.

        The maintained vLLM roster may truthfully declare capabilities, such
        as audio, that this harness cannot send. In that case ``project_richer``
        keeps the source declaration valid but returns only the supported
        text/image intersection. Ollama's operator config is already the exact
        measured contract, so it may not contain unsupported modalities.
        """

        modalities = entry.get("modalities")
        if (
            not isinstance(modalities, list)
            or not modalities
            or any(not isinstance(item, str) for item in modalities)
            or len(set(modalities)) != len(modalities)
        ):
            raise ValueError(
                f"local target {spec!r} config requires unique declared "
                "text[/image] modalities"
            )
        supported = [item for item in modalities if item in {"text", "image"}]
        if "text" not in supported or (not project_richer and supported != modalities):
            raise ValueError(
                f"local target {spec!r} config requires unique declared "
                "text[/image] modalities"
            )
        return supported

    @staticmethod
    def _validate_ollama_local_entry(
        spec: str, entry: Mapping[str, object]
    ) -> None:
        """Match the measured Ollama identity and modality CLI contract."""

        from ura.targets.local import (  # noqa: PLC0415
            OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS,
        )

        forbidden = sorted(set(entry) & OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS)
        if forbidden:
            raise ValueError(
                f"local target {spec!r} Ollama config forbids vLLM fields: "
                + ", ".join(forbidden)
            )
        digest = entry.get("digest")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            raise ValueError(
                f"local target {spec!r} Ollama config requires a 64-hex digest"
            )
        BuilderModelsMixin._validated_local_modalities(spec, entry)
        if "allow_vllm_overlap" in entry:
            raise ValueError(
                f"local target {spec!r} manual overlap override is not supported"
            )

    def _selected_local_config_payload(
        self,
        specs: list[str],
        *,
        default_quantization: str = "",
        quantization_overrides: Mapping[str, str] | None = None,
        require_live_ollama: bool = False,
    ) -> bytes:
        """Return canonical bytes for the exact selected local execution subset."""

        catalog, _explicitly_configured = self._local_entry_catalog()
        live_ollama: dict[str, Mapping[str, object]] = {}
        if require_live_ollama and any(spec.startswith("ollama:") for spec in specs):
            snapshot = self._ollama_roster_snapshot(force=True)
            if snapshot.get("available") is not True:
                reason = str(snapshot.get("error") or "daemon discovery unavailable")
                raise ValueError(
                    "selected Ollama targets require a current exact live roster: "
                    + reason
                )
            for section in ("models", "excluded"):
                rows = snapshot.get(section)
                if not isinstance(rows, list):
                    raise ValueError("live Ollama roster has malformed candidate sections")
                for row in rows:
                    if not isinstance(row, Mapping):
                        raise ValueError("live Ollama roster contains a malformed row")
                    live_spec = str(row.get("spec", ""))
                    if not live_spec.startswith("ollama:") or live_spec in live_ollama:
                        raise ValueError("live Ollama roster contains an ambiguous model spec")
                    live_ollama[live_spec] = row
        selected: dict[str, dict[str, object]] = {}
        allowed = {
            "revision",
            "digest",
            "modalities",
            "tensor_parallel_size",
            "gpu_memory_utilization",
            "max_tokens",
            "max_model_len",
            "parameter_count_b",
            "multi_gpu_compatible",
            "quantization",
        }
        for spec in specs:
            entry = catalog.get(spec)
            if entry is None:
                raise ValueError(
                    f"local target {spec!r} is not in the local target catalog"
                )
            if spec.startswith("ollama:"):
                self._validate_ollama_local_entry(spec, entry)
                live_entry = live_ollama.get(spec) if require_live_ollama else None
                if require_live_ollama:
                    if live_entry is None:
                        raise ValueError(
                            f"local target {spec!r} is absent from the current exact "
                            "Ollama daemon roster; refresh or pull it before starting"
                        )
                    try:
                        self._validate_ollama_local_entry(spec, live_entry)
                    except ValueError as exc:
                        raise ValueError(
                            f"local target {spec!r} live daemon row is invalid: {exc}"
                        ) from exc
                    configured_modalities = self._validated_local_modalities(spec, entry)
                    live_modalities = self._validated_local_modalities(spec, live_entry)
                    if (
                        str(entry["digest"]).lower()
                        != str(live_entry["digest"]).lower()
                        or configured_modalities != live_modalities
                    ):
                        raise ValueError(
                            f"local target {spec!r} configured digest/modalities do "
                            "not match current live Ollama discovery"
                        )
                # The daemon's show details can reveal an upstream/family
                # overlap that is absent from a minimal manual config. Never
                # discard that stronger live identity evidence.
                warning = self._ollama_overlap_warning(spec, live_entry or entry)
                if warning:
                    raise ValueError(
                        f"local target {spec!r} is unavailable: {warning}; "
                        "a manual overlap override is not supported"
                    )
                selected[spec] = {
                    "digest": str((live_entry or entry)["digest"]).lower(),
                    "modalities": self._validated_local_modalities(
                        spec, live_entry or entry
                    ),
                }
                continue
            model_override = str((quantization_overrides or {}).get(spec, "")).strip().lower()
            profile = self._effective_local_profile(
                spec,
                entry,
                default_quantization=default_quantization,
                model_quantization=model_override,
            )
            max_model_len = self._local_max_model_len(spec, entry)
            max_tokens = self._local_max_tokens(spec, entry)
            gpu_memory_utilization = self._local_gpu_memory_utilization(spec, entry)
            resolved = {key: value for key, value in entry.items() if key in allowed}
            for identity_key in ("revision", "digest"):
                identity_value = resolved.get(identity_key)
                if isinstance(identity_value, str):
                    resolved[identity_key] = identity_value.lower()
            resolved["modalities"] = self._validated_local_modalities(
                spec, entry, project_richer=True
            )
            resolved["gpu_memory_utilization"] = gpu_memory_utilization
            if max_model_len is not None:
                resolved["max_model_len"] = max_model_len
                if max_tokens > max_model_len:
                    raise ValueError(
                        f"local target {spec!r} max_tokens must not exceed "
                        "max_model_len"
                    )
            resolved["parameter_count_b"] = profile["parameter_count_b"]
            # Preserve the evidence boundary: an absent roster declaration stays
            # absent here.  The shared CLI resolver will apply the requested
            # default-true assumption and record its basis as ``assumed``.
            if not isinstance(entry.get("multi_gpu_compatible"), bool):
                resolved.pop("multi_gpu_compatible", None)
            resolved["quantization"] = profile["recommended_quantization"]
            if profile.get("fits") is None and model_override not in {"", "auto"}:
                # The operator has explicitly chosen the precision for a model
                # whose size is unknown. The CLI re-checks this opt-in before run.
                resolved["allow_unknown_fit"] = True
            # Hardware-auto TP: persist exactly what the model row displays.
            resolved["tensor_parallel_size"] = profile["recommended_tensor_parallel_size"]
            selected[spec] = resolved
        return (
            json.dumps(
                selected,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _local_config_snapshot_digests(
        payload: bytes,
        specs: list[str],
    ) -> tuple[str, str]:
        """Return exact-byte and path-independent local-config identities."""

        try:
            document = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("selected local config snapshot is invalid") from exc
        if not isinstance(document, dict) or set(document) != set(specs):
            raise ValueError("selected local config snapshot does not match selected models")
        identities: dict[str, str] = {}
        for spec in specs:
            if not spec.startswith("vllm:"):
                continue
            model = spec.removeprefix("vllm:")
            if not (Path(model).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", model)):
                continue
            entry = document.get(spec)
            digest = entry.get("digest") if isinstance(entry, dict) else None
            if not isinstance(digest, str) or re.fullmatch(
                r"[0-9a-fA-F]{64}", digest
            ) is None:
                raise ValueError(
                    "an explicit local checkpoint requires a 64-hex content digest"
                )
            identities[spec] = f"vllm:local-checkpoint@sha256:{digest.lower()}"
        durable = {
            identities.get(str(spec), str(spec)): entry
            for spec, entry in document.items()
        }
        if len(durable) != len(document):
            raise ValueError(
                "selected local configs collapse to a duplicate content identity"
            )
        durable_payload = (
            json.dumps(
                durable,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        return (
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(durable_payload).hexdigest(),
        )

    def _materialize_selected_local_config(
        self,
        specs: list[str],
        *,
        default_quantization: str = "",
        quantization_overrides: Mapping[str, str] | None = None,
        require_live_ollama: bool = False,
        snapshot_payload: bytes | None = None,
    ) -> Path:
        """Write one read-once local config, optionally from a reviewed snapshot."""

        payload = (
            bytes(snapshot_payload)
            if snapshot_payload is not None
            else self._selected_local_config_payload(
                specs,
                default_quantization=default_quantization,
                quantization_overrides=quantization_overrides,
                require_live_ollama=require_live_ollama,
            )
        )
        if not payload or len(payload) > 1024 * 1024:
            raise ValueError("selected local config snapshot must be a non-empty <=1 MiB file")
        try:
            parsed = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("selected local config snapshot is invalid") from exc
        if not isinstance(parsed, dict) or set(parsed) != set(specs):
            raise ValueError("selected local config snapshot does not match selected models")
        canonical = (
            json.dumps(
                parsed,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if canonical != payload:
            raise ValueError("selected local config snapshot is not canonical")
        digest = hashlib.sha256(payload).hexdigest()
        # This file carries the runtime checkpoint locator and is therefore a
        # one-shot private launch input, not a durable console artifact. Each
        # composition gets a unique name so concurrent preview/start requests
        # cannot delete one another's config. run_matrix removes it immediately
        # after its bounded startup read; lifecycle handles early failures.
        directory = self.state_dir / ".private-local-configs"
        if directory.is_symlink():
            raise ValueError("private local-config directory must not be a symlink")
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("private local-config directory must be a directory")
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass  # Windows inherits the state directory's operator ACL.
        path = directory / f"selected-{digest[:24]}-{secrets.token_hex(8)}.json"
        tmp = path.with_suffix(".tmp")
        with tmp.open("xb") as handle:
            handle.write(payload)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        return path

    def _prepared_file(self, raw: str, *, label: str) -> Path:
        """Resolve one builder-produced artifact inside the results tree."""

        if not raw:
            raise ValueError(f"{label} path is required")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        if candidate.is_symlink():
            raise ValueError(f"{label} must be a regular non-symlink file")
        try:
            path = candidate.resolve(strict=True)
            path.relative_to(self.results_root.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError(f"{label} must be an existing file under the results root") from exc
        if not path.is_file():
            raise ValueError(f"{label} must be a regular non-symlink file")
        return path

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _strict_json_object(path: Path, *, max_bytes: int) -> dict[str, Any]:
        if path.stat().st_size > max_bytes:
            raise ValueError(f"{path.name} exceeds the accepted size limit")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, child in pairs:
                if key in value:
                    raise ValueError(f"duplicate JSON key {key!r}")
                value[key] = child
            return value

        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant {constant}")
                ),
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"{path.name} is not strict UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path.name} must contain a JSON object")
        return value

    def _prepared_attacker_entries(
        self,
        params: Mapping[str, str],
        *,
        verify_digest: bool = True,
    ) -> dict[str, dict[str, object]]:
        """Load and normalize prepared and immutable attacker configurations."""

        selected = set(self._split_list(params.get("attackers", "")))
        entries: dict[str, dict[str, object]] = {}
        if "t3mp3st" in selected:
            artifact = self._prepared_file(
                params.get("t3_artifact", ""),
                label="T3MP3ST plan bundle",
            )
            expected = params.get("t3_artifact_sha", "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise ValueError("T3MP3ST bundle SHA-256 must be exact 64-hex")
            if verify_digest and self._file_sha256(artifact) != expected:
                raise ValueError("T3MP3ST bundle SHA-256 does not match the file")
            bundle = self._strict_json_object(
                artifact,
                max_bytes=256 * 1024 * 1024,
            )
            if bundle.get("format_version") != "ura-t3mp3st-plan-bundle/1":
                raise ValueError("T3MP3ST artifact is not a ura-t3mp3st-plan-bundle/1 bundle")
            revision = bundle.get("upstream_revision")
            provider = bundle.get("source_provider")
            model = bundle.get("source_model")
            if (
                not isinstance(revision, str)
                or re.fullmatch(
                    r"[0-9a-fA-F]{40}",
                    revision,
                )
                is None
            ):
                raise ValueError("T3MP3ST bundle has no exact upstream revision")
            if not isinstance(provider, str) or not provider.strip():
                raise ValueError("T3MP3ST bundle has no source provider")
            if not isinstance(model, str) or not model.strip():
                raise ValueError("T3MP3ST bundle has no source model")
            entries["t3mp3st"] = {
                "upstream_revision": revision.lower(),
                "source_provider": provider.strip(),
                "source_model": model.strip(),
                # Runtime-only path: run_matrix replaces it with a content
                # identity before persisting the experiment configuration.
                "response_artifact": str(artifact),
                "response_artifact_sha256": expected,
            }
        if "harmbench" in selected:
            config_path = self._prepared_file(
                params.get("harm_config", ""),
                label="HarmBench capture config",
            )
            document = self._strict_json_object(
                config_path,
                max_bytes=1024 * 1024,
            )
            config = document.get("harmbench")
            if set(document) != {"harmbench"} or not isinstance(config, dict):
                raise ValueError("HarmBench capture config must contain only a harmbench object")
            expected_keys = {
                "methods",
                "experiment",
                "upstream_revision",
                "replay_artifact",
                "replay_artifact_sha256",
            }
            if set(config) != expected_keys:
                raise ValueError("HarmBench capture config fields are incomplete")
            methods = config.get("methods")
            if (
                not isinstance(methods, list)
                or not methods
                or any(not isinstance(method, str) or not method.strip() for method in methods)
            ):
                raise ValueError("HarmBench capture config methods are invalid")
            revision = config.get("upstream_revision")
            if (
                not isinstance(revision, str)
                or re.fullmatch(
                    r"[0-9a-fA-F]{40}",
                    revision,
                )
                is None
            ):
                raise ValueError("HarmBench capture config revision is invalid")
            artifact_sha = config.get("replay_artifact_sha256")
            if (
                not isinstance(artifact_sha, str)
                or re.fullmatch(
                    r"[0-9a-fA-F]{64}",
                    artifact_sha,
                )
                is None
            ):
                raise ValueError("HarmBench replay artifact SHA-256 is invalid")
            replay_artifact = self._prepared_file(
                str(config.get("replay_artifact", "")),
                label="HarmBench replay artifact",
            )
            artifact_sha = artifact_sha.lower()
            if verify_digest and self._file_sha256(replay_artifact) != artifact_sha:
                raise ValueError("HarmBench replay artifact SHA-256 does not match the file")
            bundle = self._strict_json_object(
                replay_artifact,
                max_bytes=64 * 1024 * 1024,
            )
            if bundle.get("format_version") != "ura-harmbench-transfer-replay/1":
                raise ValueError(
                    "HarmBench artifact is not a ura-harmbench-transfer-replay/1 bundle"
                )
            if (
                bundle.get("methods") != methods
                or bundle.get("experiment") != config.get("experiment")
                or str(bundle.get("upstream_revision", "")).lower() != revision.lower()
            ):
                raise ValueError("HarmBench capture config does not match its replay bundle")
            entries["harmbench"] = {
                **config,
                "upstream_revision": revision.lower(),
                # Runtime-only path: run_matrix replaces it with a content
                # identity before persisting the experiment configuration.
                "replay_artifact": str(replay_artifact),
                "replay_artifact_sha256": artifact_sha,
            }
        if "ideator" in selected:
            manifest = self._prepared_file(
                params.get("ideator_manifest", ""),
                label="IDEATOR seed-pair manifest",
            )
            expected = params.get("ideator_manifest_sha", "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise ValueError("IDEATOR manifest SHA-256 must be exact 64-hex")
            if verify_digest and self._file_sha256(manifest) != expected:
                raise ValueError("IDEATOR manifest SHA-256 does not match the file")
            document = self._strict_json_object(manifest, max_bytes=4 * 1024 * 1024)
            format_version = document.get("format_version")
            source_bindings: list[dict[str, object]] | None = None
            if format_version == "ura-ideator-seed-pairs/1":
                if set(document) != {"format_version", "seed_pairs"}:
                    raise ValueError(
                        "IDEATOR v1 manifest must contain only format_version and "
                        "seed_pairs"
                    )
            elif format_version == IDEATOR_MAPPED_FORMAT:
                document = validate_ideator_mapped_manifest(document)
            else:
                raise ValueError(
                    "IDEATOR manifest is not a supported seed-pair artifact"
                )
            raw_pairs = document.get("seed_pairs")
            if not isinstance(raw_pairs, list) or not raw_pairs:
                raise ValueError("IDEATOR manifest seed_pairs must be a non-empty list")
            if len(raw_pairs) > 256:
                raise ValueError("IDEATOR manifest exceeds the 256 seed-pair limit")
            raw_pair_limit = str(params.get("ideator_pair_limit", "")).strip() or "0"
            if re.fullmatch(r"[0-9]+", raw_pair_limit) is None:
                raise ValueError("IDEATOR pair limit must be an integer from 0 to 256")
            pair_limit = int(raw_pair_limit)
            if pair_limit > 256:
                raise ValueError("IDEATOR pair limit must be an integer from 0 to 256")
            if pair_limit > len(raw_pairs):
                raise ValueError(
                    "IDEATOR pair limit exceeds the verified manifest inventory"
                )
            if format_version == IDEATOR_MAPPED_FORMAT:
                shared_config = materialize_runner_attacker_config(
                    document,
                    manifest_sha256=expected,
                    pair_limit=pair_limit,
                    image_resolver=lambda path, index: self._prepared_file(
                        path,
                        label=f"IDEATOR seed-pair image {index}",
                    ),
                )
                source_bindings = shared_config["ideator"][
                    "seed_pair_source_bindings"
                ]  # type: ignore[assignment]
            pairs: list[dict[str, object]] = []
            total_image_bytes = 0
            for index, raw_pair in enumerate(raw_pairs):
                expected_pair_fields = (
                    {"text", "image_path", "image_sha256"}
                    if format_version == "ura-ideator-seed-pairs/1"
                    else {
                        "text", "image_path", "image_sha256", "source_id",
                        "source_text_sha256", "upstream_split", "upstream_index",
                        "upstream_record_sha256", "upstream_image_path",
                    }
                )
                if not isinstance(raw_pair, dict) or set(raw_pair) != expected_pair_fields:
                    raise ValueError(
                        f"IDEATOR seed_pairs[{index}] has invalid fields"
                    )
                text = raw_pair.get("text")
                image_path = raw_pair.get("image_path")
                image_sha256 = raw_pair.get("image_sha256")
                if not isinstance(text, str) or not text.strip():
                    raise ValueError(
                        f"IDEATOR seed_pairs[{index}].text must be non-blank"
                    )
                if not isinstance(image_path, str) or not image_path.strip():
                    raise ValueError(
                        f"IDEATOR seed_pairs[{index}].image_path must be non-blank"
                    )
                if not isinstance(image_sha256, str) or re.fullmatch(
                    r"[0-9a-fA-F]{64}", image_sha256
                ) is None:
                    raise ValueError(
                        f"IDEATOR seed_pairs[{index}].image_sha256 must be exact 64-hex"
                    )
                image = self._prepared_file(
                    image_path,
                    label=f"IDEATOR seed-pair image {index}",
                )
                normalized_sha256 = image_sha256.lower()
                try:
                    identity = media_input_identity(
                        MediaRef(
                            modality="image",
                            path=str(image),
                            sha256=normalized_sha256,
                            mime="image/png",
                        ),
                        origin="attacker_generated",
                        require_declared_sha256=True,
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"IDEATOR seed-pair image {index} is not the declared PNG: {exc}"
                    ) from exc
                total_image_bytes += identity.bytes
                if total_image_bytes > 256 * 1024 * 1024:
                    raise ValueError(
                        "IDEATOR seed-pair images exceed the 256 MiB snapshot limit"
                    )
                pairs.append({
                    "text": text,
                    "image_path": str(image),
                    "image_sha256": normalized_sha256,
                    "image_bytes": identity.bytes,
                })
            projected_text_payload = self._canonical_json_bytes({
                "ideator": {
                    "seed_pairs": [
                        [str(pair["text"]), ""] for pair in pairs
                    ],
                    "seed_pair_source_bindings": source_bindings,
                }
            })
            if len(projected_text_payload) > _IDEATOR_SERIALIZED_TEXT_BUDGET_BYTES:
                raise ValueError(
                    "IDEATOR serialized seed text exceeds its 512 KiB share "
                    "of Runner's 1 MiB attacker-config bound"
                )
            entries["ideator"] = {
                "seed_pair_manifest": str(manifest),
                "seed_pair_manifest_sha256": expected,
                "seed_pairs": pairs,
                "pair_limit": pair_limit,
                **(
                    {"seed_pair_source_bindings": source_bindings}
                    if source_bindings is not None
                    else {}
                ),
            }
        if "nanogcg" in selected:
            suffix = str(params.get("nanogcg_suffix", "")).strip()
            suffix_source = str(params.get("nanogcg_suffix_source", "")).strip()
            model_id = str(params.get("nanogcg_model_id", "")).strip()
            revision = str(params.get("nanogcg_model_revision", "")).strip()
            if model_id or revision:
                raise ValueError(LIVE_NANOGCG_DISABLED_MESSAGE)
            if not suffix:
                raise ValueError(
                    "NanoGCG requires an exact precomputed suffix replay; "
                    + LIVE_NANOGCG_DISABLED_MESSAGE
                )
            if not suffix_source:
                raise ValueError(
                    "NanoGCG precomputed suffix replay requires an exact suffix source"
                )
            entries["nanogcg"] = {
                "suffix": suffix,
                "suffix_source": suffix_source,
            }
        return entries

    def _harmbench_replay_requirements(
        self,
        params: Mapping[str, str],
    ) -> tuple[str, int, int, int]:
        """Return corpus, limit, seed, and minimum queries/turns from capture."""

        config_path = self._prepared_file(
            params.get("harm_config", ""),
            label="HarmBench capture config",
        )
        document = self._strict_json_object(config_path, max_bytes=1024 * 1024)
        config = document.get("harmbench")
        if not isinstance(config, dict):
            raise ValueError("HarmBench capture config has no harmbench object")
        replay = self._prepared_file(
            str(config.get("replay_artifact", "")),
            label="HarmBench replay artifact",
        )
        bundle = self._strict_json_object(replay, max_bytes=64 * 1024 * 1024)
        selection = bundle.get("selection")
        methods = bundle.get("methods")
        cases = bundle.get("cases_per_method")
        if (
            not isinstance(selection, dict)
            or not isinstance(methods, list)
            or not methods
            or isinstance(cases, bool)
            or not isinstance(cases, int)
            or cases <= 0
        ):
            raise ValueError("HarmBench replay bundle has invalid capture metadata")
        corpus = selection.get("corpus_name")
        limit = selection.get("limit")
        seed = selection.get("sample_seed")
        if (
            not isinstance(corpus, str)
            or not corpus
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 0
            or isinstance(seed, bool)
            or not isinstance(seed, int)
        ):
            raise ValueError("HarmBench replay bundle has invalid selection metadata")
        return corpus, limit, seed, len(methods) * cases

    def _materialize_prepared_attacker_config(
        self,
        params: Mapping[str, str],
        *,
        snapshot_payload: bytes | None = None,
        artifact_snapshots: Mapping[str, bytes] | None = None,
    ) -> Path | None:
        prior = str(params.get("_attacker_config_snapshot_sha256", ""))
        if snapshot_payload is None:
            _snapshot, digest, entries = self._selected_prepared_attacker_snapshot(
                params
            )
            if prior and prior != digest:
                raise ValueError(
                    "selected prepared attacker config changed after review; "
                    "review the lane again"
                )
            payload = self._canonical_json_bytes(entries)
        else:
            payload = bytes(snapshot_payload)
            try:
                loaded = strict_json_loads(payload.decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise ValueError("reviewed attacker config snapshot is invalid") from exc
            if not isinstance(loaded, dict):
                raise ValueError("reviewed attacker config snapshot must be an object")
            entries = {
                str(name): dict(entry)
                for name, entry in loaded.items()
                if isinstance(name, str) and isinstance(entry, dict)
            }
            expected_names = set(self._split_list(params.get("attackers", ""))) & {
                "t3mp3st",
                "harmbench",
                "ideator",
                "nanogcg",
            }
            if set(entries) != expected_names or len(entries) != len(loaded):
                raise ValueError(
                    "reviewed attacker config snapshot no longer matches selection"
                )
            portable = self._portable_prepared_attacker_entries(entries)
            digest = hashlib.sha256(json.dumps(
                {
                    "schema": "ura-builder-selected-attacker-config/1",
                    "attackers": portable,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")).hexdigest()
            if not prior or prior != digest:
                raise ValueError(
                    "reviewed attacker config snapshot identity does not match"
                )
        if not entries:
            return None
        try:
            snapshot_entries = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("reviewed attacker config snapshot is invalid") from exc
        if snapshot_entries != entries or payload != self._canonical_json_bytes(entries):
            raise ValueError("reviewed attacker config snapshot no longer matches selection")
        runtime_entries = {
            str(name): dict(entry)
            for name, entry in snapshot_entries.items()
            if isinstance(name, str) and isinstance(entry, dict)
        }
        materialized_artifacts: list[Path] = []
        try:
            for attacker, path_field, digest_field in (
                ("t3mp3st", "response_artifact", "response_artifact_sha256"),
                ("harmbench", "replay_artifact", "replay_artifact_sha256"),
            ):
                entry = runtime_entries.get(attacker)
                if entry is None or path_field not in entry:
                    continue
                artifact_payload = (artifact_snapshots or {}).get(
                    f"attacker_artifact_{attacker}"
                )
                if artifact_payload is None:
                    continue
                expected = str(entry.get(digest_field, "")).lower()
                if hashlib.sha256(artifact_payload).hexdigest() != expected:
                    raise ValueError(
                        f"reviewed {attacker} artifact snapshot no longer matches"
                    )
                artifact_path, _artifact_digest = self._materialize_private_config(
                    payload=bytes(artifact_payload),
                    directory_name=".private-attacker-artifacts",
                    filename_prefix=f"{attacker}-artifact",
                )
                materialized_artifacts.append(artifact_path)
                entry[path_field] = str(artifact_path)
            ideator = runtime_entries.get("ideator")
            if ideator is not None:
                manifest_sha256 = str(
                    ideator.get("seed_pair_manifest_sha256", "")
                ).lower()
                if re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
                    raise ValueError(
                        "reviewed IDEATOR manifest lacks an exact content digest"
                    )
                if snapshot_payload is not None:
                    manifest_payload = (artifact_snapshots or {}).get(
                        "attacker_artifact_ideator"
                    )
                    if (
                        manifest_payload is None
                        or hashlib.sha256(manifest_payload).hexdigest()
                        != manifest_sha256
                    ):
                        raise ValueError(
                            "reviewed IDEATOR manifest snapshot no longer matches"
                        )
                raw_pairs = ideator.get("seed_pairs")
                if not isinstance(raw_pairs, list) or not raw_pairs:
                    raise ValueError("reviewed IDEATOR seed-pair snapshot is invalid")
                source_bindings = ideator.get("seed_pair_source_bindings")
                if source_bindings is not None and (
                    not isinstance(source_bindings, list)
                    or len(source_bindings) != len(raw_pairs)
                    or any(not isinstance(item, dict) for item in source_bindings)
                ):
                    raise ValueError("reviewed IDEATOR source-binding snapshot is invalid")
                pair_limit = ideator.get("pair_limit")
                if (
                    isinstance(pair_limit, bool)
                    or not isinstance(pair_limit, int)
                    or not 0 <= pair_limit <= 256
                    or pair_limit > len(raw_pairs)
                ):
                    raise ValueError("reviewed IDEATOR pair limit is invalid")
                runtime_pairs: list[list[str]] = []
                runtime_image_sha256: list[str] = []
                for index, raw_pair in enumerate(raw_pairs):
                    if not isinstance(raw_pair, dict):
                        raise ValueError("reviewed IDEATOR seed-pair snapshot is invalid")
                    text = raw_pair.get("text")
                    image_path = raw_pair.get("image_path")
                    image_sha256 = raw_pair.get("image_sha256")
                    if (
                        not isinstance(text, str)
                        or not text.strip()
                        or not isinstance(image_path, str)
                        or not image_path
                        or not isinstance(image_sha256, str)
                        or re.fullmatch(r"[0-9a-f]{64}", image_sha256) is None
                    ):
                        raise ValueError(
                            "reviewed IDEATOR seed-pair snapshot is invalid"
                        )
                    artifact_payload = (artifact_snapshots or {}).get(
                        f"attacker_artifact_ideator_image_{index:04d}"
                    )
                    if snapshot_payload is not None and artifact_payload is None:
                        raise ValueError(
                            f"reviewed IDEATOR image {index} snapshot is missing"
                        )
                    runtime_image_path = image_path
                    if artifact_payload is not None:
                        if hashlib.sha256(artifact_payload).hexdigest() != image_sha256:
                            raise ValueError(
                                f"reviewed IDEATOR image {index} snapshot no longer matches"
                            )
                        private_image, _image_digest = self._materialize_private_config(
                            payload=bytes(artifact_payload),
                            directory_name=".private-attacker-artifacts",
                            filename_prefix=f"ideator-image-{index:04d}",
                        )
                        materialized_artifacts.append(private_image)
                        runtime_image_path = str(private_image)
                    runtime_pairs.append([text, runtime_image_path])
                    runtime_image_sha256.append(image_sha256)
                runtime_entries["ideator"] = {
                    "seed_pairs": runtime_pairs,
                    "seed_pair_image_sha256": runtime_image_sha256,
                    "pair_limit": pair_limit,
                    **(
                        {"seed_pair_source_bindings": source_bindings}
                        if source_bindings is not None
                        else {}
                    ),
                }
            runtime_payload = self._canonical_json_bytes(runtime_entries)
            if len(runtime_payload) > _RUNNER_ATTACKER_CONFIG_MAX_BYTES:
                raise ValueError(
                    "prepared attacker config exceeds Runner's 1 MiB bound"
                )
            path, _payload_sha256 = self._materialize_private_config(
                payload=runtime_payload,
                directory_name=".private-attacker-configs",
                filename_prefix="attacker",
            )
            return path
        except BaseException:
            for artifact_path in materialized_artifacts:
                artifact_path.unlink(missing_ok=True)
            raise

    #: How many repeatable live-attestation rows the builder form accepts.
    _MAX_ATT_ROWS = 12
    #: A no-call projection is independent of the operator's provisional call
    #: ceilings. RUN_AND_RETURN explicitly permits replacing those three
    #: planning values with the exact totals printed by the preflight.
    _PROJECTION_CAP_FIELDS = frozenset({"cap_target", "cap_judge", "cap_http"})
    #: Operational resume/diagnostic controls that never change the planned
    #: grid (no row, target, attacker, or judge selection), so a successful
    #: no-call preflight stays valid when only they change.
    _PROJECTION_OPERATIONAL_FIELDS = frozenset({
        "reset_open_circuits",
        "lock_stale_seconds",
    })
