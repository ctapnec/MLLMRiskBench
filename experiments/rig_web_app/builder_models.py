"""Local model roster and prepared-attacker configuration helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


class BuilderModelsMixin:
    def _load_registry(self, name: str, example: str) -> dict[str, Any]:
        """Parse an operator-local registry, falling back to its example."""

        for candidate in (name, example):
            path = self.repo_root / "experiments" / candidate
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
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

    def _model_options(self) -> list[tuple[str, str, tuple[str, ...], str]]:
        """Selectable targets as (spec, label, modalities, kind).

        ``kind`` is 'api' for hosted routes (composed into --api) or 'local'
        for on-rig vLLM targets (composed into --local). Modalities come from
        each roster entry so the builder can hide a target that cannot handle a
        selected modality. Local targets are the hand-configured local-targets
        registry plus the vLLM roster (the models the rig's vLLM can serve;
        vLLM downloads a chosen one on first run). The focal Anthropic/OpenAI
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
            if supported:
                options.append((key, key, supported, "local"))
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

        from experiments.local_targets import model_hardware_profile  # noqa: PLC0415

        profile_entry = dict(entry)
        model_override = str(model_quantization).strip().lower()
        if model_override and model_override != "auto":
            profile_entry["quantization"] = model_override
        elif model_override == "auto":
            profile_entry.pop("quantization", None)
        return model_hardware_profile(
            spec,
            profile_entry,
            self.gpu_hardware,
            default_quantization=str(default_quantization).strip().lower(),
        )

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
    def _validate_ollama_local_entry(
        spec: str, entry: Mapping[str, object]
    ) -> None:
        """Reject vLLM-only execution fields before Web can strip them."""

        from ura.targets.local import (  # noqa: PLC0415
            OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS,
        )

        forbidden = sorted(set(entry) & OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS)
        if forbidden:
            raise ValueError(
                f"local target {spec!r} Ollama config forbids vLLM fields: "
                + ", ".join(forbidden)
            )

    def _materialize_selected_local_config(
        self,
        specs: list[str],
        *,
        default_quantization: str = "",
        quantization_overrides: Mapping[str, str] | None = None,
    ) -> Path:
        """Write the exact selected vLLM execution subset under console state."""

        catalog, explicitly_configured = self._local_entry_catalog()
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
                raise ValueError(f"local target {spec!r} is not in the vLLM roster")
            if spec.startswith("ollama:"):
                self._validate_ollama_local_entry(spec, entry)
                selected[spec] = {
                    key: value for key, value in entry.items() if key in {"digest", "modalities"}
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
            resolved = {key: value for key, value in entry.items() if key in allowed}
            if max_model_len is not None:
                resolved["max_model_len"] = max_model_len
                if max_tokens > max_model_len:
                    raise ValueError(
                        f"local target {spec!r} max_tokens must not exceed "
                        "max_model_len"
                    )
            raw_modalities = resolved.get("modalities")
            if isinstance(raw_modalities, list):
                resolved["modalities"] = [
                    modality for modality in raw_modalities if modality in {"text", "image"}
                ]
            if "text" not in resolved.get("modalities", []):
                raise ValueError(
                    f"local target {spec!r} has no text/image modality supported "
                    "by the local Runner adapter"
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
        payload = (
            json.dumps(selected, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        directory = self.state_dir / "generated-local-configs"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"selected-{digest[:24]}.json"
        if not path.is_file():
            tmp = path.with_suffix(".tmp")
            tmp.write_text(payload, encoding="utf-8")
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
        """Load and normalize the two capture-first attacker configurations."""

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
    ) -> Path | None:
        entries = self._prepared_attacker_entries(params)
        if not entries:
            return None
        payload = (
            json.dumps(
                entries,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        directory = self.state_dir / "generated-attacker-configs"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"prepared-{digest[:24]}.json"
        if not path.is_file():
            tmp = path.with_suffix(".tmp")
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, path)
        return path

    #: How many repeatable live-attestation rows the builder form accepts.
    _MAX_ATT_ROWS = 12
    #: A no-call projection is independent of the operator's provisional call
    #: ceilings. RUN_AND_RETURN explicitly permits replacing those three
    #: planning values with the exact totals printed by the preflight.
    _PROJECTION_CAP_FIELDS = frozenset({"cap_target", "cap_judge", "cap_http"})
