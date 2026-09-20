"""Command allowlist, builder catalogs, and shared presentation metadata."""

from __future__ import annotations

from .i18n import text as _ui_text
from .display_labels import label as _ui_label

import html
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ura.sampling import SAMPLING_POLICIES

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAX_RENDER_BYTES = 4 * 1024 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_CSV_PREVIEW_ROWS = 200
_INVENTORY_MAX_ENTRIES = 8000
_INVENTORY_MAX_DEPTH = 4
_WARNINGS_FILE = "console-warnings.json"
_WARNINGS_MAX = 40
_WARNING_TONES = {"error": "red", "warning": "amber", "info": "blue"}


@dataclass(frozen=True)
class CommandParam:
    flag: str
    kind: str  # str | int | float | path | flag
    required: bool = False
    help: str = ""
    #: Strict value enumeration mirroring the CLI's argparse choices; renders
    #: as a select. Empty means free-form.
    choices: tuple[str, ...] = ()
    #: Name of a suggestion list (rendered as a datalist; free text stays
    #: allowed). Presentation only - build_argv validation is unchanged.
    suggest: str = ""
    #: Mirrors ``action="append"`` CLI flags: the form may send ``flag`` plus
    #: ``flag#1``, ``flag#2``, ... rows, emitted as one repeated flag per
    #: value, in index order.  Non-repeatable flags reject ``#`` suffixes.
    repeat: bool = False


#: Per-flag help text shown as field tooltips and inline hints on the Run
#: page.  Presentation only; the CLI's own --help remains authoritative.
_PARAM_HELP: dict[str, str] = {
    "--dry-run": _ui_text(
        "catalog.use_mocktarget_and_the_offline_mock_llm_only_no_provider_calls_no"
    ),
    "--diagnostic-canary": _ui_text(
        "catalog.run_a_small_real_slice_under_real_attack_and_judge_conditions_to"
    ),
    "--attestation-probe": _ui_text(
        "catalog.one_bounded_real_call_per_model_to_confirm_the_served_identity_an"
    ),
    "--exclude-tool-conditioned": _ui_text(
        "catalog.drop_tool_conditioned_source_rows_no_runner_attacker_can_execute"
    ),
    "--api": _ui_text("catalog.comma_list_of_hosted_target_ids_from_api_targets_json_e_g_the_fab"),
    "--local": _ui_text(
        "catalog.comma_list_of_backend_model_specs_for_local_gpu_lanes_local_lanes"
    ),
    "--corpora": _ui_text(
        "catalog.comma_list_of_source_arm_ids_from_source_instances_json_or_synth"
    ),
    "--attackers": _ui_text(
        "catalog.comma_list_of_attack_engines_replay_sends_the_corpus_prompt_as_is"
    ),
    "--judges": _ui_text(
        "catalog.judge_stages_rules_is_the_deterministic_rule_scorer_free_llm_adds"
    ),
    "--judge-model": _ui_text(
        "catalog.configured_hosted_or_local_target_id_used_by_the_llm_judge_mock_i"
    ),
    "--ack-hosted-judge-data-transfer": _ui_text(
        "catalog.explicit_acknowledgement_that_a_hosted_judge_receives_target_outp"
    ),
    "--approximate-common-metrics": _ui_text(
        "catalog.explicit_opt_in_for_separate_supplementary_common_security_respon"
    ),
    "--limit": _ui_text(
        "catalog.maximum_unique_source_clusters_applied_independently_to_each_sele"
    ),
    "--sample-seed": _ui_text(
        "catalog.seed_for_each_arm_scoped_pseudorandom_cluster_shuffle_without_rep"
    ),
    "--seeds": _ui_text(
        "catalog.comma_list_of_trajectory_seeds_attack_stochasticity_distinct_from"
    ),
    "--sampling-policy": _ui_text(
        "catalog.whole_cluster_prefix_policy_the_seeded_pseudorandom_policy_is_the"
    ),
    "--max-queries": _ui_text("catalog.max_target_queries_per_trajectory_turn_budget_upper_bound"),
    "--max-turns": _ui_text("catalog.max_conversation_turns_per_trajectory"),
    "--target-answer-retries": _ui_text(
        "catalog.additional_attempts_after_an_empty_malformed_binary_control_like"
    ),
    "--recovery-completed-prefix": _ui_text(
        "catalog.validated_create_only_recovery_selection_that_removes_only_exact"
    ),
    "--recovery-completed-prefix-sha256": _ui_text(
        "catalog.exact_byte_sha_256_paired_with_the_recovery_completed_prefix_arti"
    ),
    "--max-total-target-calls": _ui_text(
        "catalog.hard_circuit_breaker_abort_the_lane_after_this_many_target_calls"
    ),
    "--max-total-judge-calls": _ui_text(
        "catalog.hard_circuit_breaker_on_model_backed_judge_calls_hosted_or_local"
    ),
    "--max-total-http-attempts": _ui_text(
        "catalog.hard_cap_on_total_http_attempts_across_the_lane_retries_included"
    ),
    "--deadline-seconds": _ui_text(
        "catalog.durable_call_start_admission_window_measured_from_the_matrix_s_fi"
    ),
    "--source-config": _ui_text(
        "catalog.path_to_the_source_registry_experiments_source_instances_json_bou"
    ),
    "--api-config": _ui_text(
        "catalog.path_to_the_hosted_target_registry_experiments_api_targets_json"
    ),
    "--api-config-sha256": _ui_text(
        "catalog.exact_byte_sha_256_for_a_read_once_selected_hosted_config"
    ),
    "--local-config-sha256": _ui_text(
        "catalog.exact_byte_sha_256_for_a_read_once_selected_local_config"
    ),
    "--profile-registry": _ui_text(
        "catalog.machine_local_registry_that_retains_identity_bound_local_model_re"
    ),
    "--out": _ui_text("catalog.output_directory_under_the_rig_results_root_for_this_run_s_artifa"),
    "--expected-revision": _ui_text(
        "catalog.the_exact_40_hex_project_commit_this_checkout_must_match_for_the"
    ),
    "--validate": _ui_text(
        "catalog.path_to_an_existing_artifact_to_re_validate_with_sha256_instead_o"
    ),
    "--scaffold": _ui_text(
        "catalog.pre_fill_the_mechanical_receipt_fields_from_bounded_observations"
    ),
    "--selftest-sleep": _ui_text("catalog.ui_diagnostic_only_sleep_this_many_seconds_and_exit"),
    "--models": _ui_text(
        "catalog.comma_list_of_model_names_resolved_through_the_hosted_and_local_t"
    ),
    "--preflight-only": _ui_text(
        "catalog.validate_and_project_the_complete_grid_without_any_model_or_judge"
    ),
    "--project-revision": _ui_text(
        "catalog.path_to_the_validated_ura_project_revision_1_receipt_required_for"
    ),
    "--project-revision-sha256": _ui_text(
        "catalog.exact_byte_sha_256_paired_with_project_revision_the_cli_defaults"
    ),
    "--source-conformance": _ui_text(
        "catalog.path_to_the_validated_ura_source_conformance_1_receipt_required_w"
    ),
    "--source-conformance-sha256": _ui_text(
        "catalog.exact_byte_sha_256_paired_with_source_conformance_the_cli_default"
    ),
    "--quantization": _ui_text(
        "catalog.default_vllm_override_bitsandbytes_awq_gptq_fp8_none_per_model_co"
    ),
    "--dtype": _ui_text("catalog.vllm_dtype_for_local_models_auto_bfloat16_float16"),
    "--lock-stale-seconds": _ui_text(
        "catalog.diagnostic_stale_age_metadata_for_cell_locks_locks_are_never_remo"
    ),
    "--reset-open-circuits": _ui_text(
        "catalog.operator_acknowledgement_clear_the_durable_provider_judge_circuit"
    ),
    "--group": _ui_text(
        "catalog.comma_list_of_aggregation_group_keys_from_the_cli_s_allowed_set_m"
    ),
    "--live-attestation": _ui_text(
        "catalog.repeatable_one_content_addressed_ura_live_attestation_2_receipt_p"
    ),
    "--live-attestation-sha256": _ui_text(
        "catalog.repeatable_the_exact_byte_digest_for_the_same_numbered_live_attes"
    ),
    "--live-attestation-max-age-hours": _ui_text(
        "catalog.maximum_receipt_age_at_measured_grid_admission_must_be_in_0_8760"
    ),
    "--right-attacker": _ui_text(
        "catalog.enables_the_replay_vs_adaptive_comparison_attacker_is_the_left_ar"
    ),
    "--minimum-unique-clusters": _ui_text(
        "catalog.minimum_source_prompt_intent_clusters_per_estimable_transfer_cell"
    ),
    "--bootstrap": _ui_text("catalog.cluster_bootstrap_resamples_for_the_analysis_clis"),
    "--bootstrap-resamples": _ui_text(
        "catalog.labels_analysis_only_bootstrap_resamples_for_the_human_audit_this"
    ),
    "--prepared-rating-form": _ui_text(
        "catalog.exact_controller_prepared_blank_two_rater_form_that_the_completed"
    ),
    "--prepared-rating-form-sha256": _ui_text(
        "catalog.authorized_lowercase_sha_256_of_the_exact_prepared_rating_form"
    ),
    "--alpha": _ui_text("catalog.labels_analysis_only_two_sided_significance_level_in_0_1"),
    "--seed": _ui_text("catalog.labels_analysis_only_deterministic_resampling_seed_preparation_us"),
    "--allow-single-rater": _ui_text(
        "catalog.exploratory_labels_analysis_only_the_resulting_report_remains_ine"
    ),
}

#: Builder-owned process wall-time ceiling for long local measured lanes. It is
#: deliberately separate from Runner's ``--deadline-seconds`` call-start gate.
_LOCAL_BUDGET_HELP = _ui_text(
    "catalog.final_measured_all_local_process_only_whole_hours_become_a_detach"
)


#: The physical modalities a scored campaign arm carries. Multimodal arms
#: pair a text channel with an image/audio/video channel, so they belong to
#: BOTH modalities - a text+image arm is selected by the text chip and the
#: image chip alike (no arm is forced into a single bucket).
_MODALITIES = ("text", "image", "audio", "video", "tool")


#: The complete maintained source-arm catalogue: (arm id, physical modalities,
#: disabled reason).  All 45 registry arms are listed.  There are THREE kinds,
#: mirroring ``ura.eligibility`` and ``ura.source_metrics`` exactly:
#:   * empty reason, NOT in _SOURCE_METRIC_ARMS - a common-runner SCORED lane
#:     (``common_metrics_eligible: True``), scored by common harmful-ASR/FRR.
#:   * empty reason, IN _SOURCE_METRIC_ARMS - ``common_metrics_eligible: False``
#:     but its exact (source, required_metric) evaluator IS implemented in
#:     ``ura.source_metrics``, so run_matrix scores it as a source-metric lane
#:     (restricted to the attacker(s) its converter declares).  RUNNABLE.
#:   * non-empty reason - ``common_metrics_eligible: False`` and NO implemented
#:     source evaluator. Default admission fails before any target call; an
#:     explicit approximate-common-metrics opt-in permits only separately
#:     labelled, non-authoritative response proxies. This is NOT a native_import
#:     target: native_import canonicalises the upstream end-to-end engines.
def _ineligible(metric: str) -> str:
    return (
        _ui_text("catalog.this_source_requires_the_source_specific")
        + f"{metric}"
        + _ui_text("catalog.metric_not_common_harmful_asr_but_that_evaluator_is_not_integrate")
    )


def _tool_ineligible(metric: str) -> str:
    return (
        _ui_text("catalog.this_source_requires_the_source_specific_2")
        + f"{metric!r}"
        + _ui_text("catalog.metric_and_an_executable_tool_environment_no_maintained_runner_ta")
    )


_ARM_CATALOG: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("strongreject_official", ("text",), ""),
    ("advbench_harmful", ("text",), ""),
    ("jailbreakbench_harmful", ("text",), ""),
    ("jailbreakbench_benign", ("text",), ""),
    ("harmbench_text", ("text",), ""),
    ("saladbench_base", ("text",), ""),
    ("decodingtrust_stereotype", ("text",), ""),
    ("airbench_full", ("text",), ""),
    ("xstest_full", ("text",), ""),
    ("simplesafetytests_full", ("text",), ""),
    ("cyberseceval_mitre", ("text",), ""),
    ("cyberseceval_interpreter", ("text",), ""),
    ("cyberseceval_insecure_coding", ("text",), ""),
    (
        "cyberseceval_prompt_injection",
        ("text",),
        _ineligible("cyberseceval_prompt_injection_judge_question"),
    ),
    ("mmsafety_official", ("text", "image"), ""),
    ("jailbreakv_full", ("text", "image"), ""),
    ("harmbench_multimodal", ("text", "image"), ""),
    ("vlsbench_release", ("text", "image"), ""),
    ("mossbench_official", ("text", "image"), ""),
    ("siuo_release", ("text", "image"), ""),
    ("figstep_full", ("text", "image"), ""),
    ("mllmguard_privacy", ("text", "image"), ""),
    ("mllmguard_bias", ("text", "image"), ""),
    ("mllmguard_toxicity", ("text", "image"), ""),
    ("mllmguard_legality", ("text", "image"), ""),
    (
        "mllmguard_position_swapping",
        ("text", "image"),
        _ineligible("mllmguard_position_swapping_truthfulness"),
    ),
    (
        "mllmguard_noise_injection",
        ("text", "image"),
        _ineligible("mllmguard_noise_injection_truthfulness"),
    ),
    (
        "mllmguard_hallucination",
        ("text", "image"),
        _ineligible("mllmguard_hallucination_truthfulness"),
    ),
    ("gptgeochat_release", ("text", "image"), ""),
    ("holisafe_full", ("text", "image"), ""),
    ("jalmbench_audio", ("text", "audio"), ""),
    ("videosafetybench_benign_query", ("text", "video"), ""),
    ("videosafetybench_harmful_query", ("text", "video"), ""),
    ("agentharm_benign", ("text", "tool"), _tool_ineligible("official_agentharm_tool_grading")),
    ("agentharm_harmful", ("text", "tool"), _tool_ineligible("official_agentharm_tool_grading")),
    ("bipia_test_abstract", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_code", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_email", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_qa", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_table", ("text",), _ineligible("indirect_injection_task_success")),
    (
        "injecagent_direct_harm_base",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_direct_harm_enhanced",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_data_stealing_base",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_data_stealing_enhanced",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    ("rjudge_release", ("text",), ""),
)
#: Common-metric-ineligible arms whose exact (source, required_metric) evaluator
#: IS implemented in ``ura.source_metrics._IMPLEMENTED_SOURCE_EVALUATORS``, so
#: run_matrix scores them as source-metric lanes.  Each maps to (required_metric,
#: allowed attackers), mirroring the converter's ``source_metric_attackers``.
#: These are RUNNABLE, not disabled; a parity test asserts this set matches the
#: implemented-evaluator registry so the console can never drift from execution.
_SOURCE_METRIC_ARMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "rjudge_release": ("rjudge_safety_judgment", ("replay",)),
    "gptgeochat_release": ("gptgeochat_binary_moderation", ("replay",)),
}
#: Scored arms for modality checks - common lanes AND source-metric lanes both
#: run in run_matrix and carry real modality requirements (empty reason).
_ARM_MODALITIES: tuple[tuple[str, tuple[str, ...]], ...] = tuple(
    (arm, mods) for arm, mods, reason in _ARM_CATALOG if not reason
)
#: Common-metric-ineligible arms with NO implemented source evaluator: shown
#: disabled and rejected before a scored lane.  Excludes the source-metric arms.
_INELIGIBLE_ARMS: frozenset[str] = frozenset(arm for arm, _mods, reason in _ARM_CATALOG if reason)
_INELIGIBLE_REASONS: dict[str, str] = {arm: reason for arm, _mods, reason in _ARM_CATALOG if reason}

#: Arms drawn from unified / multi-benchmark AGGREGATOR sources (each itself
#: pools or spans many upstream safety corpora). Tagged with an "aggregator"
#: badge in the builder so the operator can see the aggregator-class sources at a
#: glance; this is display metadata only and does not change admission.
_AGGREGATOR_ARMS: frozenset[str] = frozenset(
    {
        "saladbench_base",
        "airbench_full",
        "xstest_full",
        "simplesafetytests_full",
        "holisafe_full",
        "decodingtrust_stereotype",
    }
)

#: Attack frameworks (engines) offered in the builder, mirroring the harness
#: registry in src/ura/adapters/engines.py, with the modalities each can drive.
#: replay/crescendo are modality-agnostic (they carry whatever the corpus
#: datapoint holds); the external text-jailbreak adapters are text-first.
_ALL_MODALITIES = ("text", "image", "audio", "video")
#: The 20 registered attacker names.  This mirrors the single source of truth
#: ``ura.adapters.engines.ATTACKER_NAMES``; importing that module eagerly would
#: pull in every heavy engine dependency just to list names, so the console
#: keeps a light mirror and a parity test asserts the two never drift.
_ATTACKER_NAMES: tuple[str, ...] = (
    "replay",
    "crescendo",
    "pyrit",
    "garak",
    "deepteam",
    "promptfoo",
    "t3mp3st",
    "petri",
    "fuzzyai",
    "nanogcg",
    "autodan",
    "agentdojo",
    "giskard",
    "easyjailbreak",
    "h4rm3l",
    "spikee",
    "ideator",
    "purplellama",
    "asb",
    "harmbench",
)
#: Attackers whose ``runner_replay_eligible`` is False - native-artifact
#: integrations (own their target/trajectory or evaluator) that run_matrix
#: REJECTS in the common runner ("cannot be replayed through Runner").  They are
#: shown disabled with their real action (the native-import path), never as
#: selectable common-runner frameworks.  A parity test asserts this matches the
#: harness registry.
_NATIVE_ONLY_ATTACKERS: frozenset[str] = frozenset(
    {
        "garak",
        "promptfoo",
        "petri",
        "fuzzyai",
        "autodan",
        "agentdojo",
        "giskard",
        "easyjailbreak",
        "asb",
    }
)
#: Every registered adapter is visible in Build. T3MP3ST and HarmBench use the
#: explicit prepare/capture controls rendered beside the normal lane builder.
_BUILDER_OMITTED_ATTACKERS: frozenset[str] = frozenset()
#: Precomputed-only adapters whose required prepared input still has no Builder
#: control. IDEATOR is intentionally absent: Build accepts its exact
#: content-addressed seed-pair manifest and snapshots every selected PNG.
_CLI_ONLY_ATTACKERS: dict[str, str] = {}
#: Adapters that replay only rows of one upstream source family (the adapter
#: raises for any other DataPoint.source).  Maps attacker -> (arm id prefix,
#: reason); mirrored in builder validation so the lane is rejected before a
#: subprocess exists.
_SOURCE_RESTRICTED_ATTACKERS: dict[str, tuple[str, str]] = {
    "purplellama": (
        "cyberseceval_",
        _ui_text("catalog.purplellama_replays_only_source_authentic_cyberseceval_rows_datap"),
    ),
}
#: Mirror of ``experiments.run_matrix._ALLOWED_GROUP_KEYS`` (a parity test
#: asserts the two never drift); importing run_matrix at page-render time
#: would pull in the whole harness just to list keys.
_GROUP_KEYS: tuple[str, ...] = (
    "model",
    "target",
    "attacker",
    "strategy",
    "source",
    "risk",
    "risk_category",
    "risk_subtype",
    "modality",
    "effective_modality",
    "is_multimodal",
    "expected_behavior",
    "attack_family",
    "seed",
    "source_policy_id",
    "source_policy_version",
)
#: The run_matrix argparse default for --group.  experiments.level2_report
#: refuses any aggregate whose group_by lacks these eight keys, so every
#: documented measured/preflight lane (RUN_AND_RETURN sections 9-13) passes
#: exactly this value and Build defaults to it; a parity test pins both the
#: parser default and the level-2 requirement to this string.
_CLI_DEFAULT_GROUP = (
    "model,source,risk,effective_modality,expected_behavior,attacker,"
    "source_policy_id,source_policy_version"
)
#: The runbook's measured/preflight --group value: the CLI default, written
#: out explicitly so a console lane aggregates exactly like the documented
#: CLI lane and its cells reach the Level-2 export.
_RUNBOOK_GROUP = _CLI_DEFAULT_GROUP
#: Every registered attacker (mirrors ura.adapters.engines.ATTACKER_NAMES, the
#: shared registry - a parity test asserts the two match). replay/crescendo are
#: modality-agnostic (they carry whatever the corpus datapoint holds); the
#: prepared external adapters below are text-first.
_FRAMEWORK_DESCRIPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "replay": (_ui_text("catalog.send_the_corpus_prompt_as_is_single_turn"), _ALL_MODALITIES),
    "crescendo": (_ui_text("catalog.escalate_the_request_over_multiple_turns"), _ALL_MODALITIES),
    "pyrit": (_ui_text("catalog.microsoft_pyrit_0_14_0_in_its_own_explicit_venv"), ("text",)),
    "garak": (_ui_text("catalog.nvidia_garak_probes"), ("text",)),
    "deepteam": (_ui_text("catalog.deepteam_1_0_7_in_its_own_explicit_venv"), ("text",)),
    "promptfoo": (_ui_text("catalog.promptfoo_adapter"), ("text",)),
    "t3mp3st": (_ui_text("catalog.prepared_t3mp3st_safe_probe_replay"), ("text",)),
    "petri": (_ui_text("catalog.petri_adapter"), ("text",)),
    "fuzzyai": (_ui_text("catalog.fuzzyai_adapter"), ("text",)),
    "nanogcg": (
        _ui_text("catalog.precomputed_nanogcg_suffix_replay_live_generation_disabled"),
        ("text",),
    ),
    "autodan": (_ui_text("catalog.autodan_turbo_adapter"), ("text",)),
    "agentdojo": (_ui_text("catalog.agentdojo_adapter"), ("text",)),
    "giskard": (_ui_text("catalog.giskard_scan_adapter"), ("text",)),
    "easyjailbreak": (_ui_text("catalog.easyjailbreak_adapter"), ("text",)),
    "h4rm3l": (_ui_text("catalog.h4rm3l_0_2_4_in_its_own_explicit_venv"), ("text",)),
    "spikee": (_ui_text("catalog.spikee_0_9_1_in_its_own_explicit_venv"), ("text",)),
    "ideator": (
        _ui_text("catalog.ideator_verified_precomputed_text_image_seed_pair_replay"),
        ("text",),
    ),
    "purplellama": (
        _ui_text("catalog.purplellama_source_identity_replay_cyberseceval_arms_only"),
        ("text",),
    ),
    "asb": (_ui_text("catalog.agent_security_bench_adapter"), ("text",)),
    "harmbench": (_ui_text("catalog.prepared_harmbench_case_transfer_replay"), ("text",)),
}
_FRAMEWORKS: tuple[tuple[str, str, tuple[str, ...]], ...] = tuple(
    (
        name,
        _FRAMEWORK_DESCRIPTIONS.get(name, ("adapter", ("text",)))[0],
        _FRAMEWORK_DESCRIPTIONS.get(name, ("adapter", ("text",)))[1],
    )
    for name in _ATTACKER_NAMES
)

#: Builder execution modes -> the run_matrix flag they set (empty = measured).
_BUILD_MODES: tuple[tuple[str, str, str], ...] = (
    ("dry_run", "--dry-run", _ui_text("catalog.offline_dry_run_mocktarget_no_calls_no_spend")),
    (
        "attestation_probe",
        "--attestation-probe",
        _ui_text("catalog.attestation_probe_one_real_call_per_model_usage_baseline"),
    ),
    (
        "diagnostic_canary",
        "--diagnostic-canary",
        _ui_text("catalog.diagnostic_canary_small_live_slice_observed_usage_only"),
    ),
    ("measured", "", _ui_text("catalog.measured_lane_real_calls_produces_campaign_evidence")),
)


#: Files the console may edit in place.  Strict allowlist keyed by a short
#: token; each is an operator-local registry read fresh by run_matrix, so an
#: edit here takes effect on the next job.  Value is
#: (relative_target, relative_example, description).  No path outside this map
#: is ever writable, and only JSON content that parses is accepted.
_EDITABLE_CONFIGS: dict[str, tuple[str, str, str]] = {
    "api-targets": (
        "experiments/api-targets.json",
        "experiments/rig/api-targets.example.json",
        _ui_text("catalog.hosted_target_roster_exact_provider_model_ids_with_modalities_max"),
    ),
    "source-instances": (
        "experiments/source-instances.json",
        "experiments/rig/source-instances.example.json",
        _ui_text("catalog.source_arm_registry_logical_arm_id_converter_path_env_split_add_a"),
    ),
    "local-targets": (
        "experiments/local-targets.json",
        "experiments/rig/local-targets.example.json",
        _ui_text("catalog.local_vllm_target_registry_vllm_org_model_pinned_revision_modalit"),
    ),
    "budgets": (
        "experiments/budgets.json",
        "experiments/rig/budgets.example.json",
        _ui_text("catalog.budget_dashboard_help"),
    ),
    "pricing": (
        "experiments/pricing.json",
        "experiments/rig/pricing.example.json",
        _ui_text("catalog.effective_dated_per_model_price_table_used_to_calculate_monetary"),
    ),
}


#: Static suggestion lists.  The attacker suggestions are derived from the
#: shared registry mirror ``_ATTACKER_NAMES`` (all 20), so a new engine appears
#: automatically and none is silently omitted.
_SUGGEST_STATIC: dict[str, tuple[str, ...]] = {
    # Only campaign-usable common-runner attackers are suggested. Native-only
    # integrations use native_import; explicit non-campaign adapters stay CLI-only.
    "attackers": (
        "replay,crescendo",
        *(
            attacker
            for attacker in _ATTACKER_NAMES
            if attacker not in _NATIVE_ONLY_ATTACKERS
            and attacker not in _BUILDER_OMITTED_ATTACKERS
            and attacker not in _CLI_ONLY_ATTACKERS
        ),
    ),
    "judges": ("rules,llm", "rules", "llm", "rules,guardrail", "guardrail"),
    # Only the full default grouping is offered: Level-2 export rejects any
    # narrower grouping, and a blank field inherits the same CLI default.
    "group": (_RUNBOOK_GROUP,),
    "seeds": ("0", "0,1", "0,1,2"),
}


@dataclass(frozen=True)
class Command:
    name: str
    module: str
    description: str
    params: tuple[CommandParam, ...]


#: Complete matrix-driver surface. One entry per real ``run_matrix`` argparse
#: option (asserted by interface-parity tests). The argv-forwarding preflight
#: derives its subset below because it always adds ``--preflight-only``.
_MATRIX_PARAMS = (
    CommandParam("--dry-run", "flag"),
    CommandParam("--preflight-only", "flag"),
    CommandParam("--diagnostic-canary", "flag"),
    CommandParam("--attestation-probe", "flag"),
    CommandParam("--exclude-tool-conditioned", "flag"),
    CommandParam("--models", "str", suggest="api"),
    CommandParam("--api", "str", suggest="api"),
    CommandParam("--local", "str"),
    CommandParam("--corpora", "str", suggest="arms"),
    CommandParam("--attackers", "str", suggest="attackers"),
    CommandParam("--judges", "str", suggest="judges"),
    CommandParam("--judge-model", "str", suggest="api"),
    CommandParam("--ack-hosted-judge-data-transfer", "flag"),
    CommandParam("--approximate-common-metrics", "flag"),
    CommandParam("--defense", "str", choices=("none", "input", "output", "both")),
    CommandParam("--defense-guard", "str", choices=("rules", "guardrail")),
    CommandParam("--guardrail-model", "str"),
    CommandParam("--guardrail-revision", "str"),
    CommandParam("--guardrail-device", "str"),
    CommandParam("--defense-guardrail-model", "str"),
    CommandParam("--defense-guardrail-revision", "str"),
    CommandParam("--defense-guardrail-device", "str"),
    CommandParam("--group", "str", suggest="group"),
    CommandParam("--attacker-config", "path"),
    CommandParam("--attacker-config-sha256", "str"),
    CommandParam("--engine-runtime-config", "path"),
    CommandParam("--engine-runtime-config-sha256", "str"),
    CommandParam("--reset-open-circuits", "flag"),
    CommandParam("--verify-model-sha256", "flag"),
    CommandParam("--model-acquisition-plan-only", "flag"),
    CommandParam("--model-acquisition-plan-dir", "path"),
    CommandParam("--model-acquisition-plan", "path"),
    CommandParam("--model-acquisition-plan-sha256", "str"),
    CommandParam("--model-acquisition-receipt", "path"),
    CommandParam("--model-acquisition-receipt-sha256", "str"),
    CommandParam("--model-acquisition-store", "path"),
    CommandParam("--source-config", "path"),
    CommandParam("--source-config-sha256", "str"),
    CommandParam("--api-config", "path"),
    CommandParam("--api-config-sha256", "str"),
    CommandParam("--local-config", "path"),
    CommandParam("--local-config-sha256", "str"),
    CommandParam("--project-revision", "path"),
    CommandParam("--project-revision-sha256", "str"),
    CommandParam("--source-conformance", "path"),
    CommandParam("--source-conformance-sha256", "str"),
    CommandParam("--quantization", "str"),
    CommandParam("--dtype", "str"),
    CommandParam("--limit", "int"),
    CommandParam("--sample-seed", "int"),
    CommandParam("--sampling-policy", "str", choices=tuple(sorted(SAMPLING_POLICIES))),
    CommandParam("--seeds", "str", suggest="seeds"),
    CommandParam("--max-queries", "int"),
    CommandParam("--max-turns", "int"),
    CommandParam("--target-answer-retries", "int"),
    CommandParam("--recovery-completed-prefix", "path"),
    CommandParam("--recovery-completed-prefix-sha256", "str"),
    CommandParam("--max-total-target-calls", "int"),
    CommandParam("--max-total-judge-calls", "int"),
    CommandParam("--max-total-http-attempts", "int"),
    CommandParam("--deadline-seconds", "int"),
    CommandParam("--lock-stale-seconds", "int"),
    CommandParam("--execution-scope-id", "str"),
    CommandParam("--live-attestation", "path", repeat=True),
    CommandParam("--live-attestation-sha256", "str", repeat=True),
    CommandParam("--live-attestation-max-age-hours", "float"),
    CommandParam("--out", "path"),
)

# rig_check always appends --preflight-only. The standalone-dry-only exclusion
# can therefore never be valid on that forwarding surface, even when the form
# also supplies --dry-run.
_RIG_CHECK_PARAMS = tuple(
    param for param in _MATRIX_PARAMS if param.flag != "--exclude-tool-conditioned"
)


def _commands() -> dict[str, Command]:
    common_out = (
        CommandParam("--out", "path", help=_ui_text("catalog.output_directory_under_the_rig_root")),
    )
    # Same field where the module's argparse marks --out required; the Run
    # page renders the required marker from this (a parity test derives the
    # set from each module's real parser).
    required_out = (
        CommandParam(
            "--out",
            "path",
            required=True,
            help=_ui_text("catalog.output_directory_under_the_rig_root"),
        ),
    )
    entries = [
        Command(
            "project_revision",
            "experiments.project_revision",
            _ui_text("catalog.create_or_validate_the_ura_project_revision_1_receipt"),
            (
                CommandParam("--expected-revision", "str"),
                CommandParam("--out", "path"),
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
            ),
        ),
        Command(
            "source_conformance",
            "experiments.source_conformance",
            _ui_text("catalog.scaffold_or_validate_the_compact_source_acquisition_receipt"),
            (
                CommandParam("--scaffold", "flag"),
                CommandParam("--arm", "str", repeat=True),
                CommandParam("--observation", "str", repeat=True),
                CommandParam("--out", "path"),
                CommandParam("--manifest", "path"),
                CommandParam("--sha256", "str"),
                CommandParam("--source-config", "path", required=True),
            ),
        ),
        Command(
            "capture_t3mp3st",
            "experiments.capture_t3mp3st",
            _ui_text("catalog.capture_a_validated_t3mp3st_planning_bundle_for_measured_replay"),
            (
                CommandParam("--corpus", "str"),
                CommandParam("--input", "path"),
                CommandParam("--source-config", "path"),
                CommandParam("--limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--endpoint", "str"),
                CommandParam("--upstream-revision", "str", required=True),
                CommandParam("--framework-lock", "path"),
                CommandParam("--framework-env-root", "path"),
                CommandParam("--framework-state-root", "path"),
                CommandParam("--source-provider", "str", required=True),
                CommandParam("--source-model", "str", required=True),
                CommandParam("--timeout-seconds", "float"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "harmbench_capture",
            "experiments.harmbench_capture",
            _ui_text("catalog.prepare_a_content_addressed_harmbench_case_bundle_for_measured_re"),
            (
                CommandParam("--repo", "path", required=True),
                CommandParam("--revision", "str", required=True),
                CommandParam("--source", "path", required=True),
                CommandParam("--corpus-name", "str"),
                CommandParam("--method", "str", repeat=True, required=True),
                CommandParam("--experiment", "str"),
                CommandParam("--limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--cases-per-method", "int"),
                CommandParam("--artifact-out", "path", required=True),
                CommandParam("--attacker-config-out", "path", required=True),
                CommandParam("--python", "path"),
                CommandParam("--credential-env", "str", repeat=True),
                CommandParam("--timeout-seconds", "float"),
            ),
        ),
        Command(
            "rig_check",
            "experiments.rig_check",
            _ui_text("catalog.no_call_preflight_for_a_planned_grid"),
            _RIG_CHECK_PARAMS,
        ),
        Command(
            "run_matrix",
            "experiments.run_matrix",
            _ui_text("catalog.execute_or_dry_run_one_experiment_matrix_lane"),
            _MATRIX_PARAMS,
        ),
        Command(
            "live_attestation",
            "experiments.live_attestation",
            _ui_text("catalog.derive_a_typed_transport_receipt_from_a_completed_probe"),
            (
                CommandParam("--probe-root", "path"),
                CommandParam("--execution-scope-id", "str"),
                *common_out,
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
            ),
        ),
        Command(
            "lane_canary",
            "experiments.lane_canary",
            _ui_text("catalog.summarize_one_typed_diagnostic_canary_completion"),
            (
                CommandParam("--results", "path", required=True),
                CommandParam("--eligibility", "path", required=True),
                CommandParam("--out-dir", "path"),
            ),
        ),
        Command(
            "level1_evidence",
            "experiments.level1_evidence",
            _ui_text("catalog.build_the_level_1_lifecycle_json_csv_for_one_cohort"),
            (
                CommandParam("--eligibility", "path", repeat=True),
                CommandParam("--results", "path", repeat=True),
                CommandParam("--live-attestation", "path", repeat=True),
                CommandParam("--live-attestation-sha256", "str", repeat=True),
                CommandParam("--out-json", "path", required=True),
                CommandParam("--out-csv", "path", required=True),
            ),
        ),
        Command(
            "suite_summary",
            "experiments.suite_summary",
            _ui_text("catalog.build_the_no_pooling_suite_evidence_inventory"),
            (
                CommandParam("--results", "path", repeat=True),
                CommandParam("--native", "path", repeat=True),
                CommandParam("--eligibility", "path", repeat=True),
                CommandParam("--source-config", "path"),
                *required_out,
            ),
        ),
        Command(
            "level2_report",
            "experiments.level2_report",
            _ui_text("catalog.export_deterministic_level_2_json_csv_markdown_broad_tables"),
            (
                CommandParam("--results", "path", repeat=True),
                CommandParam(
                    "--historical-code-repository",
                    "path",
                    help=_ui_text(
                        "catalog.repository_containing_the_original_source_revisions_for_retained"
                    ),
                ),
                CommandParam("--native", "path", repeat=True),
                CommandParam("--out-json", "path", required=True),
                CommandParam("--out-csv", "path", required=True),
                CommandParam("--out-md", "path", required=True),
            ),
        ),
        Command(
            "human_review_campaign",
            "experiments.human_review_campaign",
            _ui_text("catalog.prepare_or_analyse_saved_campaign_outputs_for_independent_review"),
            (
                CommandParam("--database", "path"),
                CommandParam("--campaign", "str"),
                CommandParam("--results-root", "path"),
                CommandParam("--mode", "str"),
                CommandParam("--clusters", "int"),
                CommandParam("--media-index", "path"),
                CommandParam("--snapshot", "path"),
                CommandParam("--prepared-rating-form", "path"),
                CommandParam("--labels", "path"),
                CommandParam("--bootstrap-resamples", "int"),
                CommandParam("--output", "path", required=True),
                CommandParam("--acknowledge-sensitive-content", "flag"),
            ),
        ),
        Command(
            "human_audit",
            "experiments.human_audit",
            _ui_text("catalog.prepare_or_analyse_the_human_audit_frames"),
            (
                CommandParam("--results", "path", required=True),
                CommandParam("--media-index", "path"),
                CommandParam("--historical-code-repository", "path"),
                CommandParam("--judge-configuration-sha256", "str"),
                CommandParam("--prepare", "int"),
                CommandParam("--prepare-source-task", "int"),
                CommandParam("--labels", "path"),
                CommandParam("--source-task-labels", "path"),
                CommandParam("--prepared-rating-form", "path"),
                CommandParam("--prepared-rating-form-sha256", "str"),
                CommandParam("--output", "path"),
                CommandParam("--acknowledge-sensitive-content", "flag"),
                CommandParam("--allow-single-rater", "flag"),
                CommandParam("--bootstrap-resamples", "int"),
                CommandParam("--alpha", "float"),
                CommandParam("--seed", "int"),
            ),
        ),
        Command(
            "figures",
            "experiments.figures",
            _ui_text("catalog.render_figure_previews_or_measured_focal_figures"),
            (
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--synth", "flag"),
                CommandParam("--results", "path"),
                CommandParam("--left-model", "str"),
                CommandParam("--right-model", "str"),
                CommandParam("--human-audit", "path"),
                CommandParam("--human-audit-sha256", "str"),
                CommandParam("--strongreject-corpus", "str"),
                CommandParam("--mmsafety-corpus", "str"),
                CommandParam("--mossbench-corpus", "str"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                *common_out,
            ),
        ),
        Command(
            "paired_compare",
            "experiments.paired_compare",
            _ui_text("catalog.paired_cluster_comparison_between_two_exact_conditions"),
            (
                CommandParam("--results", "path", required=True),
                CommandParam(
                    "--historical-code-repository",
                    "path",
                    help=_ui_text(
                        "catalog.repository_containing_the_original_source_revisions_for_retained"
                    ),
                ),
                CommandParam("--left-model", "str", required=True),
                CommandParam("--right-model", "str", required=True),
                CommandParam("--left-defense", "str"),
                CommandParam("--right-defense", "str"),
                CommandParam("--attacker", "str"),
                CommandParam("--right-attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--mode", "str", choices=("auto", "static", "live")),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                CommandParam("--permutations", "int"),
                CommandParam("--alpha", "float"),
                CommandParam("--assume-exchangeable", "flag"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "judge_sensitivity",
            "experiments.judge_sensitivity",
            _ui_text("catalog.same_response_judge_stage_sensitivity_analysis"),
            (
                CommandParam("--results", "path", required=True),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "kappa",
            "experiments.kappa",
            _ui_text("catalog.pairwise_judge_agreement_diagnostics"),
            (
                CommandParam("--results", "path", required=True),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
            ),
        ),
        Command(
            "transfer_matrix",
            "experiments.transfer_matrix",
            _ui_text("catalog.support_qualified_descriptive_transfer_analysis"),
            (
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--results", "path", required=True),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--minimum-unique-clusters", "int"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                CommandParam("--alpha", "float"),
            ),
        ),
        Command(
            "export_jalmbench",
            "experiments.export_jalmbench",
            _ui_text("catalog.export_the_official_jalmbench_parquet_release_for_the_converter"),
            (
                CommandParam("--source", "path", required=True),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *required_out,
            ),
        ),
        Command(
            "export_vlsbench",
            "experiments.export_vlsbench",
            _ui_text("catalog.export_the_official_vlsbench_parquet_release_for_the_converter"),
            (
                CommandParam("--source", "path", required=True),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *required_out,
            ),
        ),
        Command(
            "export_aggregators",
            "experiments.export_aggregators",
            _ui_text("catalog.acquire_one_or_all_aggregator_corpora_into_the_converter_layout"),
            (
                CommandParam(
                    "--source",
                    "str",
                    required=True,
                    choices=(
                        "saladbench",
                        "airbench",
                        "xstest",
                        "simplesafetytests",
                        "decodingtrust",
                        "holisafe",
                        "all",
                    ),
                    help=_ui_text("catalog.which_aggregator_corpus_to_prepare_or_all_six"),
                ),
                CommandParam(
                    "--out-root",
                    "path",
                    required=True,
                    help=_ui_text(
                        "catalog.corpora_root_the_exported_ura_corpora_each_source_writes_under_it"
                    ),
                ),
            ),
        ),
        Command(
            "native_import",
            "experiments.native_import",
            _ui_text("catalog.validate_and_canonicalize_a_native_artifact_family"),
            (
                CommandParam("--config", "path"),
                CommandParam("--validate", "path"),
                *common_out,
            ),
        ),
        Command(
            "syn_compat",
            "experiments.syn_compat",
            _ui_text("catalog.synthetic_compatibility_corpus_generate_check_evaluate_rule_fidel"),
            (
                CommandParam("--generate", "flag"),
                CommandParam("--check", "flag"),
                CommandParam("--evaluate", "flag"),
                CommandParam("--cases", "path"),
                CommandParam("--metadata", "path"),
                CommandParam("--out", "path"),
                CommandParam("--seed", "int"),
                CommandParam("--perturbations-per-template", "int"),
            ),
        ),
        Command(
            "response_svm",
            "experiments.response_svm",
            _ui_text("catalog.retained_response_classifiers_harmful_compliance_over_refusal_and"),
            (
                CommandParam("--export", "flag"),
                CommandParam("--evaluate", "flag"),
                CommandParam("--package", "flag"),
                CommandParam("--predict", "flag"),
                CommandParam("--study", "flag"),
                CommandParam("--source-campaign", "str"),
                CommandParam("--database", "path"),
                CommandParam("--candidates", "path"),
                CommandParam("--source-root", "path", repeat=True),
                CommandParam("--run-id", "str", repeat=True),
                CommandParam("--campaign", "str", repeat=True),
                CommandParam("--matched-campaign", "str"),
                CommandParam("--judge-condition", "str"),
                CommandParam("--exclude-model", "str", repeat=True),
                CommandParam("--dataset", "path"),
                CommandParam("--study-result", "path"),
                CommandParam("--study-predictions", "path"),
                CommandParam(
                    "--models",
                    "path",
                    help=_ui_text("catalog.trusted_fitted_models_joblib_from_this_tool_only"),
                ),
                CommandParam(
                    "--features", "str", choices=("prompt", "response", "prompt_response")
                ),
                CommandParam("--out", "path", required=True),
                CommandParam("--seed", "int"),
                CommandParam("--max-feature-characters", "int"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--holdout-model", "str", repeat=True),
                CommandParam("--holdout-corpus", "str", repeat=True),
            ),
        ),
        Command(
            "local_targets",
            "experiments.local_targets",
            _ui_text("catalog.list_or_refresh_the_vllm_local_target_roster_version_matched"),
            (
                CommandParam("--refresh", "flag"),
                CommandParam("--vllm-version", "str"),
                CommandParam("--repo-root", "str"),
            ),
        ),
        Command(
            "campaign_assess",
            "experiments.campaign_assess",
            _ui_text("catalog.prepare_or_resume_missing_local_haiku_verdicts_on_indexed_campaig"),
            (
                CommandParam("--execute", "flag"),
                CommandParam("--database", "path", required=True),
                CommandParam("--campaign", "str"),
                CommandParam("--results-root", "path"),
                CommandParam("--kind", "str", choices=("local", "haiku")),
                CommandParam("--judge-model", "str"),
                CommandParam("--api-config", "path"),
                CommandParam("--pricing-config", "path"),
                CommandParam("--max-cost-microusd", "int"),
                CommandParam("--model-store", "path"),
                CommandParam("--limit", "int"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "local_model_readiness",
            "experiments.local_model_readiness",
            _ui_text("catalog.profile_one_vllm_or_ollama_target_with_the_seeded_10_text_5_image"),
            (
                CommandParam("--local", "str"),
                CommandParam(
                    "--context-ceiling",
                    "int",
                    help=_ui_text(
                        "catalog.optional_context_ceiling_tested_by_readiness_leave_empty_for_hard"
                    ),
                ),
                CommandParam("--local-config", "path"),
                CommandParam("--local-config-sha256", "str"),
                CommandParam("--model-acquisition-plan-only", "flag"),
                CommandParam("--model-acquisition-plan-dir", "path"),
                CommandParam("--model-acquisition-plan", "path"),
                CommandParam("--model-acquisition-plan-sha256", "str"),
                CommandParam("--model-acquisition-receipt", "path"),
                CommandParam("--model-acquisition-receipt-sha256", "str"),
                CommandParam("--model-acquisition-store", "path"),
                CommandParam("--out", "path"),
                CommandParam("--profile-registry", "path"),
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
                CommandParam("--expected-spec", "str"),
            ),
        ),
        Command(
            "retained_local_sources",
            "experiments.retained_local_sources",
            _ui_text("catalog.select_saved_local_runs_for_input_matched_follow_on_preparation_w"),
            (
                CommandParam(
                    "--source-root",
                    "path",
                    required=True,
                    repeat=True,
                    help=_ui_text(
                        "catalog.completed_runner_results_directories_select_narrow_job_directorie"
                    ),
                ),
                CommandParam(
                    "--run-id",
                    "str",
                    repeat=True,
                    help=_ui_text(
                        "catalog.optional_exact_run_ids_blank_selects_all_completed_local_runs_in"
                    ),
                ),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_retained_inputs",
            "experiments.hosted_retained_inputs",
            _ui_text("catalog.prepare_an_input_matched_hosted_subset_from_saved_local_runs_with"),
            (
                CommandParam(
                    "--local-inventory",
                    "path",
                    required=True,
                    help=_ui_text(
                        "catalog.inventory_produced_by_select_saved_local_runs_historical_inventor"
                    ),
                ),
                CommandParam("--local-inventory-sha256", "str", required=True),
                CommandParam(
                    "--runner-view",
                    "path",
                    help=_ui_text(
                        "catalog.historical_inventories_only_omit_for_selected_local_source_direct"
                    ),
                ),
                CommandParam("--budget", "path", required=True),
                CommandParam("--budget-sha256", "str", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--target", "str", required=True),
                CommandParam("--global-input-cap", "int"),
                CommandParam(
                    "--media-index",
                    "path",
                    help=_ui_text(
                        "catalog.optional_for_selected_local_sources_original_converted_inputs_and"
                    ),
                ),
                CommandParam("--media-index-sha256", "str"),
                CommandParam("--materialize-corpus", "str"),
                CommandParam(
                    "--source-corpora",
                    "path",
                    help=_ui_text(
                        "catalog.optional_for_selected_local_sources_reconstructs_the_recorded_ori"
                    ),
                ),
                CommandParam("--source-corpora-sha256", "str"),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_prepare",
            "experiments.hosted_campaign_prepare",
            _ui_text("catalog.count_selected_requests_and_prepare_shared_target_and_judging_all"),
            (
                CommandParam("--request", "path", required=True),
                CommandParam("--request-sha256", "str", required=True),
                CommandParam("--out-root", "path", required=True),
                CommandParam(
                    "--count-cache",
                    "path",
                    help=_ui_text("catalog.reuse_exact_token_count_receipts_after_interruption"),
                ),
                CommandParam("--shared-budget-root", "path"),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam(
                    "--allow-network-counts",
                    "flag",
                    help=_ui_text(
                        "catalog.allow_provider_token_count_endpoints_only_this_does_not_enable_an"
                    ),
                ),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_selected_replays",
            "experiments.hosted_selected_replays",
            _ui_text("catalog.prepare_all_selected_models_matched_replay_inputs_from_saved_sour"),
            (
                CommandParam("--local-inventory", "path", required=True),
                CommandParam("--local-inventory-sha256", "str", required=True),
                CommandParam("--budget", "path", required=True),
                CommandParam("--budget-sha256", "str", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--out-root", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_program_runtime",
            "experiments.hosted_program_runtime",
            _ui_text("catalog.bind_an_untouched_hosted_program_to_installed_models_without_call"),
            (
                CommandParam("--program", "path", required=True),
                CommandParam("--program-sha256", "str", required=True),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--project-root", "path", required=True),
                CommandParam("--expected-commit", "str", required=True),
                CommandParam(
                    "--store",
                    "path",
                    help=_ui_text(
                        "catalog.existing_managed_model_store_no_downloads_are_performed"
                    ),
                ),
                CommandParam(
                    "--out",
                    "path",
                    required=True,
                    help=_ui_text(
                        "catalog.new_or_matching_interrupted_runtime_preparation_directory"
                    ),
                ),
                CommandParam("--max-age-hours", "float"),
                CommandParam("--verify-model-sha256", "flag"),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_execute",
            "experiments.hosted_campaign_execute",
            _ui_text("catalog.collect_prepared_hosted_programs_in_parallel_judge_retained_answe"),
            (
                CommandParam(
                    "--program",
                    "path",
                    required=True,
                    repeat=True,
                    help=_ui_text(
                        "catalog.exact_prepared_attested_program_files_one_per_selected_model_cond"
                    ),
                ),
                CommandParam(
                    "--program-sha256",
                    "str",
                    required=True,
                    repeat=True,
                    help=_ui_text(
                        "catalog.matching_program_digests_in_the_same_order_as_the_program_files"
                    ),
                ),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--project-root", "path", required=True),
                CommandParam("--expected-commit", "str", required=True),
                CommandParam("--out", "path", required=True),
                CommandParam(
                    "--prepare-runtime",
                    "flag",
                    help=_ui_text(
                        "catalog.bind_installed_models_and_complete_the_selected_funded_transport"
                    ),
                ),
                CommandParam(
                    "--model-store",
                    "path",
                    help=_ui_text(
                        "catalog.existing_resolved_managed_model_store_defaults_to_ura_model_store"
                    ),
                ),
                CommandParam(
                    "--workers-per-provider",
                    "int",
                    help=_ui_text(
                        "catalog.independent_target_workers_per_provider_default_2_maximum_8_provi"
                    ),
                ),
                CommandParam(
                    "--resume-from",
                    "path",
                    help=_ui_text(
                        "catalog.previous_collection_control_directory_keep_its_programs_and_budge"
                    ),
                ),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_budget",
            "experiments.hosted_campaign_budget",
            _ui_text("catalog.project_the_sealed_hosted_target_and_haiku_judge_budget_without_c"),
            (
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--pricing-config-sha256", "str", required=True),
                CommandParam("--budgets", "path", required=True),
                CommandParam("--budgets-sha256", "str", required=True),
                CommandParam("--pricing-as-of", "str", required=True),
                CommandParam(
                    "--route-configuration",
                    "path",
                    help=_ui_text(
                        "catalog.selected_models_with_their_own_request_and_output_token_caps_omit"
                    ),
                ),
                CommandParam("--route-configuration-sha256", "str"),
                CommandParam(
                    "--reservation-policy",
                    "str",
                    choices=("first_attempts_upfront", "per_attempt"),
                    help=_ui_text(
                        "catalog.per_attempt_checks_queue_the_full_selected_inventory_under_shared"
                    ),
                ),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_native_judge_prepare",
            "experiments.retained_native_judge_prepare",
            _ui_text("catalog.prepare_local_judging_of_saved_api_answers_without_generating_or"),
            (
                CommandParam("--program", "path", required=True, repeat=True),
                CommandParam("--program-sha256", "str", required=True, repeat=True),
                CommandParam(
                    "--job",
                    "str",
                    repeat=True,
                    help=_ui_text(
                        "catalog.optional_exact_job_names_blank_selects_all_supplied_jobs"
                    ),
                ),
                CommandParam(
                    "--include-incomplete",
                    "flag",
                    help=_ui_text(
                        "catalog.include_saved_outputs_from_interrupted_jobs_unsaved_inputs_remain"
                    ),
                ),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "retained_native_judge_execute",
            "experiments.retained_native_judge_execute",
            _ui_text("catalog.judge_saved_api_answers_locally_resuming_verdicts_without_target"),
            (
                CommandParam("--preparation", "path", required=True),
                CommandParam("--preparation-sha256", "str", required=True),
                CommandParam(
                    "--out",
                    "path",
                    required=True,
                    help=_ui_text("catalog.reuse_the_same_directory_to_resume_saved_judgments"),
                ),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--verify-model-sha256", "flag"),
            ),
        ),
        Command(
            "retained_response_judge_pair",
            "experiments.retained_response_judge_pair",
            _ui_text("catalog.select_matched_retained_local_and_hosted_outputs_for_bounded_haik"),
            (
                CommandParam(
                    "--api-config",
                    "path",
                    help=_ui_text("catalog.needed_with_an_existing_campaign_judging_budget"),
                ),
                CommandParam("--shared-budget-root", "path"),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam("--program", "path", repeat=True),
                CommandParam("--program-sha256", "str", repeat=True),
                CommandParam("--local-runner-view", "path", required=True),
                CommandParam("--hosted-runner-view", "path", required=True),
                CommandParam("--source-receipt", "path", required=True),
                CommandParam("--source-receipt-sha256", "str", required=True),
                CommandParam("--judge-model", "str", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--pricing-config-sha256", "str", required=True),
                CommandParam("--pricing-as-of", "str", required=True),
                CommandParam("--pair-limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--max-cost-microusd", "int"),
                CommandParam("--ack-hosted-judge-data-transfer", "flag", required=True),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_judge_inventory",
            "experiments.retained_judge_inventory",
            _ui_text("catalog.inventory_every_local_and_hosted_answer_on_the_same_inputs_withou"),
            (
                CommandParam("--local-view", "path", required=True, repeat=True),
                CommandParam("--hosted-view", "path", required=True, repeat=True),
                CommandParam(
                    "--input-limit",
                    "int",
                    help=_ui_text(
                        "catalog.zero_keeps_every_hosted_input_including_missing_answers"
                    ),
                ),
                CommandParam("--sample-seed", "int"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_inventory_judge_items",
            "experiments.retained_inventory_judge_items",
            _ui_text("catalog.prepare_all_matching_saved_answers_under_existing_judging_funding"),
            (
                CommandParam("--inventory", "path", required=True),
                CommandParam("--local-view", "path", required=True, repeat=True),
                CommandParam("--hosted-view", "path", required=True, repeat=True),
                CommandParam("--budget-root", "path", required=True, repeat=True),
                CommandParam("--budget-plan-sha256", "str", required=True, repeat=True),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_inventory_judging",
            "experiments.retained_inventory_judging",
            _ui_text("catalog.prepare_or_resume_all_funded_saved_output_haiku_judgments_under_e"),
            (
                CommandParam("--items-root", "path"),
                CommandParam("--judge-model", "str"),
                CommandParam("--api-config", "path"),
                CommandParam("--pricing-config", "path"),
                CommandParam("--pricing-as-of", "str"),
                CommandParam("--allow-token-counts", "flag"),
                CommandParam("--preparation", "path"),
                CommandParam("--execute", "flag"),
                CommandParam("--ack-paid-execution", "flag"),
                CommandParam("--workers", "int"),
                CommandParam("--matching-workspace-id", "str"),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_hosted_judge_items",
            "experiments.retained_hosted_judge_items",
            _ui_text("catalog.prepare_saved_hosted_answers_for_their_existing_haiku_funding_wit"),
            (
                CommandParam("--preparation", "path", required=True),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_response_judge_pair_execute",
            "experiments.retained_response_judge_pair_execute",
            _ui_text("catalog.execute_one_sealed_matched_local_and_hosted_haiku_judging_plan"),
            (
                CommandParam(
                    "--shared-budget-root",
                    "path",
                    help=_ui_text("catalog.existing_campaign_judging_allocation"),
                ),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam(
                    "--shared-requests",
                    "path",
                    help=_ui_text("catalog.saved_output_specific_funded_haiku_requests"),
                ),
                CommandParam("--shared-requests-sha256", "str"),
                CommandParam(
                    "--matching-workspace-id",
                    "str",
                    help=_ui_text(
                        "catalog.the_other_campaign_id_owning_matched_outputs_the_selected_campaig"
                    ),
                ),
                CommandParam("--retain-invalid-verdicts", "flag"),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--plan", "path", required=True),
                CommandParam("--local-runner-view", "path", required=True),
                CommandParam("--hosted-runner-view", "path", required=True),
                CommandParam("--source-receipt", "path", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--out", "path", required=True),
                CommandParam("--ack-paid-execution", "flag", required=True),
            ),
        ),
        Command(
            "ollama_pull",
            "experiments.ollama_pull",
            _ui_text("catalog.pull_one_model_through_the_fixed_loopback_ollama_daemon"),
            (
                CommandParam("--model", "str", required=True),
                CommandParam("--base-url", "str"),
                CommandParam("--models-path", "path", required=True),
                CommandParam("--owned-pid", "int", required=True),
                CommandParam("--owned-process-identity", "str", required=True),
                CommandParam("--timeout-seconds", "float"),
            ),
        ),
        Command(
            "model_acquire",
            "experiments.model_acquire",
            _ui_text("catalog.acquire_one_reviewed_immutable_hugging_face_model_plan"),
            (
                CommandParam("--verify-model-sha256", "flag"),
                CommandParam("--plan", "path", required=True),
                CommandParam("--plan-sha256", "str", required=True),
                CommandParam("--store", "path", required=True),
                CommandParam("--receipts-dir", "path", required=True),
                CommandParam("--transport-cache", "path"),
                CommandParam("--max-download-bytes", "int", required=True),
                CommandParam("--min-free-bytes", "int", required=True),
                CommandParam("--deadline-seconds", "float", required=True),
                CommandParam("--activity-event", "path"),
                CommandParam("--activity-job-id", "str"),
            ),
        ),
        Command(
            "webui_selftest",
            "experiments.rig_web",
            _ui_text("catalog.ui_diagnostic_only_sleep_briefly_and_exit"),
            (CommandParam("--selftest-sleep", "float", required=True),),
        ),
    ]
    return {entry.name: entry for entry in entries}


COMMANDS = _commands()


#: Presentation-only grouping of the allowlisted commands by runbook stage.
#: Every generic-Run command appears in exactly one group (asserted by tests).
#: Controller-only commands such as run_matrix, model_acquire, and ollama_pull are intentionally
#: omitted because their validated Build workflows own launch authorization.
COMMAND_GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        _ui_text("catalog.receipts_and_conformance"),
        "receipt",
        _ui_text("catalog.runbook_sections_2_4_1_17"),
        ("project_revision", "source_conformance"),
    ),
    (
        _ui_text("catalog.prepared_attack_capture"),
        "flask",
        _ui_text("catalog.capture_first_replay_in_build"),
        ("capture_t3mp3st", "harmbench_capture"),
    ),
    (
        _ui_text("catalog.acquisition_exports"),
        "box",
        _ui_text("catalog.runbook_section_3"),
        ("export_jalmbench", "export_vlsbench", "export_aggregators"),
    ),
    (
        _ui_text("catalog.preflight_probes_and_lanes"),
        "play",
        _ui_text("catalog.runbook_sections_8_13"),
        ("rig_check", "live_attestation", "lane_canary"),
    ),
    (
        _ui_text("catalog.analysis_and_native_imports"),
        "flask",
        _ui_text("catalog.runbook_sections_14_16"),
        ("native_import", "syn_compat", "response_svm"),
    ),
    (
        _ui_text("catalog.targets_and_rosters"),
        "coins",
        _ui_text("catalog.runbook_sections_5_13"),
        ("local_targets", "local_model_readiness"),
    ),
    (
        _ui_text("catalog.analysis_and_reporting"),
        "chart",
        _ui_text("catalog.runbook_section_16"),
        (
            "level1_evidence",
            "suite_summary",
            "level2_report",
            "figures",
            "paired_compare",
            "judge_sensitivity",
            "kappa",
            "transfer_matrix",
        ),
    ),
    (
        _ui_text("catalog.hosted_budget_and_retained_judging"),
        "coins",
        _ui_text("catalog.runbook_sections_19_20"),
        (
            "retained_local_sources",
            "hosted_campaign_budget",
            "hosted_retained_inputs",
            "hosted_selected_replays",
            "hosted_campaign_prepare",
            "hosted_program_runtime",
            "hosted_campaign_execute",
            "retained_native_judge_prepare",
            "retained_native_judge_execute",
            "retained_response_judge_pair",
            "retained_judge_inventory",
            "retained_inventory_judge_items",
            "retained_hosted_judge_items",
            "retained_inventory_judging",
            "retained_response_judge_pair_execute",
        ),
    ),
    (
        _ui_text("catalog.human_audit"),
        "users",
        _ui_text("catalog.runbook_sections_15_15_1"),
        ("human_review_campaign", "human_audit"),
    ),
    (
        _ui_text("catalog.console_diagnostics"),
        "pulse",
        _ui_text("catalog.runbook_section_18"),
        ("webui_selftest",),
    ),
)


def _param_values(
    param: CommandParam,
    values: Mapping[str, str],
) -> list[str]:
    """Collect one parameter's non-empty form values, repeat rows included.

    A repeatable parameter accepts the bare ``flag`` field plus any number of
    ``flag#N`` rows (N a positive integer), returned in index order with the
    bare field first.  Non-repeatable parameters accept the bare field only;
    their ``#`` variants stay unknown parameters.
    """

    collected: list[tuple[int, str]] = []
    base = values.get(param.flag, "")
    base = base.strip() if isinstance(base, str) else ""
    if base:
        collected.append((0, base))
    if param.repeat:
        prefix = param.flag + "#"
        for key, raw in values.items():
            if not key.startswith(prefix):
                continue
            suffix = key[len(prefix) :]
            if not suffix.isdigit() or int(suffix) <= 0:
                raise ValueError((_ui_text("catalog.invalid_repeat_row") + f"{key!r}"))
            raw = raw.strip() if isinstance(raw, str) else ""
            if raw:
                collected.append((int(suffix), raw))
    collected.sort(key=lambda item: item[0])
    return [raw for _index, raw in collected]


def build_argv(
    command: str,
    values: Mapping[str, str],
    *,
    commands: Mapping[str, Command] | None = None,
) -> list[str]:
    """Build an exact argument vector from a typed allowlisted form."""

    registry = COMMANDS if commands is None else commands
    entry = registry.get(command)
    if entry is None:
        raise ValueError((_ui_text("catalog.unknown_command") + f"{command!r}"))
    known = {param.flag: param for param in entry.params}
    allowed = set(known)
    for param in entry.params:
        if param.repeat:
            allowed.update(key for key in values if key.startswith(param.flag + "#"))
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(
            (_ui_text("catalog.unknown_parameter_s_for") + f"{command!r}" + ": " + f"{unknown}")
        )
    if command == "human_audit":
        populated = {
            flag
            for flag in (
                "--prepare",
                "--prepare-source-task",
                "--labels",
                "--source-task-labels",
            )
            if isinstance(values.get(flag), str) and values[flag].strip()
        }
        if len(populated) != 1:
            raise ValueError(
                _ui_text("catalog.human_audit_requires_exactly_one_preparation_or_labels_mode")
            )
        judge_configuration = values.get("--judge-configuration-sha256", "").strip()
        historical_repository = values.get("--historical-code-repository", "").strip()
        if judge_configuration:
            if not historical_repository or populated & {
                "--prepare-source-task",
                "--source-task-labels",
            }:
                raise ValueError(
                    _ui_text(
                        "catalog.judge_configuration_selection_requires_a_historical_common_frame"
                    )
                )
            if len(judge_configuration) != 64 or any(
                c not in "0123456789abcdef" for c in judge_configuration
            ):
                raise ValueError(
                    _ui_text("catalog.judge_configuration_sha_256_must_be_64_lowercase_hex_digits")
                )
        output = values.get("--output", "")
        output = output.strip() if isinstance(output, str) else ""
        prepared_path = values.get("--prepared-rating-form", "")
        prepared_sha = values.get("--prepared-rating-form-sha256", "")
        prepared_path = prepared_path.strip() if isinstance(prepared_path, str) else ""
        prepared_sha = prepared_sha.strip() if isinstance(prepared_sha, str) else ""
        labels_mode = bool(populated & {"--labels", "--source-task-labels"})
        analysis_only = {
            flag
            for flag in (
                "--allow-single-rater",
                "--bootstrap-resamples",
                "--alpha",
                "--seed",
            )
            if isinstance(values.get(flag), str) and values[flag].strip()
        }
        if not labels_mode and analysis_only:
            raise ValueError(
                _ui_text(
                    "catalog.human_audit_preparation_is_deterministic_and_seedless_analysis_on"
                )
                + ", ".join(sorted(analysis_only))
            )
        if labels_mode and not output:
            raise ValueError(
                _ui_text("catalog.human_audit_labels_modes_require_an_explicit_external_output")
            )
        if bool(prepared_path) != bool(prepared_sha):
            raise ValueError(
                _ui_text(
                    "catalog.prepared_rating_form_and_prepared_rating_form_sha256_must_be_prov"
                )
            )
        if not labels_mode and (prepared_path or prepared_sha):
            raise ValueError(
                _ui_text(
                    "catalog.human_audit_preparation_modes_cannot_consume_a_prepared_rating_fo"
                )
            )
        if prepared_sha and (
            len(prepared_sha) != 64
            or any(character not in "0123456789abcdef" for character in prepared_sha)
        ):
            raise ValueError(
                _ui_text("catalog.prepared_rating_form_sha256_must_be_64_lowercase_hex_digits")
            )
    argv = [sys.executable, "-m", entry.module]
    for param in entry.params:
        raws = _param_values(param, values)
        if not raws:
            if param.required:
                raise ValueError((f"{command!r}" + _ui_text("catalog.requires") + f"{param.flag}"))
            continue
        if param.kind == "flag":
            if len(raws) != 1 or raws[0] not in {"on", "true", "1", "yes"}:
                raise ValueError((f"{param.flag}" + _ui_text("catalog.is_a_checkbox_flag")))
            argv.append(param.flag)
            continue
        for raw in raws:
            if param.kind == "int":
                int(raw)
            elif param.kind == "float":
                float(raw)
            elif param.kind == "path":
                if "\x00" in raw:
                    raise ValueError((_ui_text("catalog.invalid_path_for") + f"{param.flag}"))
            if param.choices and raw not in param.choices:
                raise ValueError(
                    (
                        f"{param.flag}"
                        + _ui_text("catalog.must_be_one_of")
                        + f"{', '.join(param.choices)}"
                    )
                )
            argv.extend([param.flag, raw])
    return argv


def _contained(root: Path, relative: str) -> Path:
    """Resolve a browser path strictly inside the configured root."""

    candidate = (relative or "").replace("\\", "/").strip()
    if candidate.startswith("/") or ":" in candidate.split("/", 1)[0]:
        raise ValueError(_ui_text("catalog.artifact_paths_must_be_relative_to_the_rig_root"))
    resolved = (root / candidate).resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError(_ui_text("catalog.artifact_path_escapes_the_rig_root"))
    return resolved


_BADGE_FIELDS = (
    (
        "evidence_kind",
        {
            "diagnostic_dry_run": (_ui_text("catalog.diagnostic_dry_run"), "amber"),
            "measured_run": (_ui_text("catalog.measured_run"), "blue"),
        },
    ),
    (
        "execution_purpose",
        {
            "diagnostic_canary": (_ui_text("catalog.diagnostic_canary"), "amber"),
            "attestation_probe": (_ui_text("catalog.attestation_probe"), "amber"),
            "measured_run": (_ui_text("catalog.measured_run"), "blue"),
        },
    ),
    (
        "evidence_class",
        {
            "synthetic_offline": (_ui_text("catalog.synthetic_offline"), "amber"),
            "live_diagnostic": (_ui_text("catalog.live_diagnostic"), "amber"),
        },
    ),
    (
        "status",
        {
            "complete": ("complete", "green"),
            "error": ("error", "red"),
            "running": ("running", "blue"),
        },
    ),
)


def evidence_badges(document: Any) -> list[tuple[str, str]]:
    """Derive explicit diagnostic/measured and status badges from a JSON body."""

    badges: list[tuple[str, str]] = []
    if not isinstance(document, dict):
        return badges
    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    merged: dict[str, Any] = {**scope, **document}
    for name, mapping in _BADGE_FIELDS:
        value = merged.get(name)
        if isinstance(value, str) and value in mapping:
            badges.append(mapping[value])
    if merged.get("dry_run") is True:
        badges.append(("dry-run", "amber"))
    if merged.get("campaign_authorized") is False:
        badges.append((_ui_text("catalog.campaign_not_authorized"), "gray"))
    if merged.get("empirical_validity_established") is False:
        badges.append((_ui_text("catalog.no_empirical_validity"), "gray"))
    counts = document.get("counts")
    if isinstance(counts, dict):
        strata = counts.get("planning_strata")
        if isinstance(strata, dict):
            for key, label in (
                ("structural_not_applicable", _ui_text("catalog.structural_n_a")),
                ("missing", "missing"),
                ("error", "error"),
            ):
                value = strata.get(key)
                if isinstance(value, int) and value > 0:
                    badges.append((f"{label}: {value}", "gray" if key != "error" else "red"))
    return badges


#: Inline stroke icons (24x24 viewBox); presentation only, no external assets.
_ICONS: dict[str, str] = {
    "logo": (
        "<path d='M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z'/>"
        "<path d='M8.5 12.5l2.5 2.5 4.5-5'/>"
    ),
    "grid": (
        "<rect x='3' y='3' width='7' height='7' rx='1.5'/>"
        "<rect x='14' y='3' width='7' height='7' rx='1.5'/>"
        "<rect x='3' y='14' width='7' height='7' rx='1.5'/>"
        "<rect x='14' y='14' width='7' height='7' rx='1.5'/>"
    ),
    "terminal": "<path d='M4 17l6-5-6-5'/><path d='M12 19h8'/>",
    "pulse": "<path d='M22 12h-4l-3 9L9 3l-3 9H2'/>",
    "folder": (
        "<path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'/>"
    ),
    "file": (
        "<path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 "
        "2-2V8z'/><path d='M14 2v6h6'/>"
    ),
    "receipt": (
        "<path d='M9 11l3 3L22 4'/>"
        "<path d='M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 "
        "2-2h11'/>"
    ),
    "box": (
        "<path d='M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 "
        "8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z'/>"
        "<path d='M3.3 7L12 12l8.7-5'/><path d='M12 22V12'/>"
    ),
    "play": "<path d='M6 3l14 9-14 9V3z'/>",
    "flask": (
        "<path d='M10 2v6.3L4.2 19a2 2 0 0 0 1.8 3h12a2 2 0 0 0 1.8-3L14 "
        "8.3V2'/><path d='M8 2h8'/><path d='M7.5 14h9'/>"
    ),
    "chart": "<path d='M18 20V10'/><path d='M12 20V4'/><path d='M6 20v-6'/>",
    "users": (
        "<path d='M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2'/>"
        "<circle cx='9' cy='7' r='4'/>"
        "<path d='M23 21v-2a4 4 0 0 0-3-3.87'/>"
        "<path d='M16 3.13a4 4 0 0 1 0 7.75'/>"
    ),
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "disk": ("<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='2.5'/>"),
    "sliders": (
        "<path d='M4 21v-7'/><path d='M4 10V3'/><path d='M12 21v-9'/>"
        "<path d='M12 8V3'/><path d='M20 21v-5'/><path d='M20 12V3'/>"
        "<path d='M1 14h6'/><path d='M9 8h6'/><path d='M17 16h6'/>"
    ),
    "coins": (
        "<circle cx='8' cy='8' r='6'/>"
        "<path d='M18.09 10.37A6 6 0 1 1 10.34 18'/>"
        "<path d='M7 6h1v4'/><path d='M16.71 13.88l.7.71-2.82 2.82'/>"
    ),
    "save": (
        "<path d='M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1"
        "-2 2z'/><path d='M17 21v-8H7v8'/><path d='M7 3v5h8'/>"
    ),
    "book": (
        "<path d='M4 19.5A2.5 2.5 0 0 1 6.5 17H20'/>"
        "<path d='M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 "
        "6.5 2z'/>"
    ),
    # Modality glyphs (shown instead of TEXT/IMAGE/AUDIO/VIDEO word tags).
    "mod_text": "<path d='M4 6h16'/><path d='M4 12h12'/><path d='M4 18h8'/>",
    "mod_image": (
        "<rect x='3' y='3' width='18' height='18' rx='2'/>"
        "<circle cx='8.5' cy='8.5' r='1.5'/><path d='M21 15l-5-5L5 21'/>"
    ),
    "mod_audio": ("<path d='M4 9v6h4l5 4V5L8 9H4z'/><path d='M16 8.5a4 4 0 0 1 0 7'/>"),
    "mod_video": (
        "<rect x='2' y='6' width='13' height='12' rx='2'/><path d='M15 10l7-4v12l-7-4z'/>"
    ),
}


def _icon(name: str, *, size: int = 18) -> str:
    body = _ICONS.get(name, _ICONS["file"])
    return (
        f"<svg class='ic' width='{size}' height='{size}' viewBox='0 0 24 24' "
        "fill='none' stroke='currentColor' stroke-width='1.8' "
        f"stroke-linecap='round' stroke-linejoin='round' "
        f"aria-hidden='true'>{body}</svg>"
    )


_MOD_ICON_NAME = {
    "text": "mod_text",
    "image": "mod_image",
    "audio": "mod_audio",
    "video": "mod_video",
}


def _mod_icon(modality: str) -> str:
    """A colored modality chip with an accessible label, instead of a word tag
    (keeps dense arm/target grids from being overwhelmed by TEXT/IMAGE/... text).
    """
    name = _MOD_ICON_NAME.get(modality, "file")
    return (
        f"<span class='modicon m-{html.escape(modality)}' "
        f"title='{html.escape(_ui_label(modality), quote=True)}' "
        f"aria-label='{html.escape(_ui_label(modality), quote=True)}'>{_icon(name, size=12)}</span>"
    )


def _mod_set(mods: tuple[str, ...]) -> str:
    """The right-aligned cluster of modality chips for a checkbox row header."""
    return "<span class='modset'>" + "".join(_mod_icon(m) for m in mods) + "</span>"


def _arm_head(name_html: str, mods: tuple[str, ...]) -> str:
    """One checkbox-row header line: name on the left, modality chips on the
    right - a consistent, uncluttered placement instead of icons trailing the
    name."""
    return f"<span class='armhead'><span class='armname'>{name_html}</span>{_mod_set(mods)}</span>"
