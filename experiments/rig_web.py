"""Operator-facing campaign builder and console over maintained experiment CLIs.

A single-operator application (WEB-001 basic console, promoted
to the WEB-002 campaign builder): it starts allowlisted ``python -m
experiments.*`` commands from typed forms, composes campaign lanes through a
mode-aware builder (dry run, attestation probe, diagnostic canary, measured
execution) with mode-specific validation and an exact-argv confirmation step,
monitors and stops those jobs (whole process tree), streams their logs,
edits the operator-local registries through an allowlisted JSON editor,
renders retained Level-1/Level-2 artifacts with explicit diagnostic/measured
and pending/N/A/error distinctions, and accounts observed token usage and
its calculated monetary cost from recorded artifacts and an operator-edited
effective-dated pricing table.

State is kept in a stdlib-sqlite database under the console state directory
(jobs, campaign runs, recorded usage, calculated cost, artifact index).  The
database is operational state only - the validated filesystem artifacts
remain the scientific authority, and nothing rendered here is a measurement
surface.  Every experiment the console launches runs the same maintained
``experiments.*`` module the CLI runs, through an argument vector built from a
typed allowlist (parity is tested against the real module parsers); the
console's own bookkeeping - reindexing the usage/report indexes and printing
the recorded-usage cost report - is additionally reachable headlessly via
``rig_web --reindex`` / ``--usage-report``.  No arbitrary shell input is ever
executed (``shell=False``), the server binds the operator-configured host and
port, POST bodies are size-capped, and no dependency outside the standard
library is added.
"""

from __future__ import annotations

# This module intentionally remains the stable CLI/import facade.
# ruff: noqa: F401

import argparse
import contextlib
import csv
import hashlib
import html
import io
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from .rig_web_app.app import RigWebApp
from .rig_web_app.artifacts import (
    _ANALYSIS_MARKERS,
    _BILLED_CATEGORIES,
    _MARKER_SUFFIX,
    _PIPELINE_STAGES,
    _STAGE_PATHS_SHOWN,
    _TOKEN_CATEGORIES,
    _UNBILLED_PROVIDERS,
    Job,
    StageInventory,
    _argv_out_dir,
    _judge_row_usage,
    _marker_artifact_path,
    _marker_usage_date,
    _pipeline_svg,
    _response_identity,
    _token_usage_complete,
    _tokens_by_category,
    _win_assign_job,
    _win_close_handle,
    _win_managed_job,
    _win_terminate_job,
    artifact_inventory,
    collect_usage,
    failed_cell_usage_rows,
    iter_completed_markers,
    run_kind,
    usage_rows_from_marker,
)
from .rig_web_app.catalog import (
    COMMAND_GROUPS,
    COMMANDS,
    _AGGREGATOR_ARMS,
    _ALL_MODALITIES,
    _ARM_CATALOG,
    _ARM_MODALITIES,
    _ATTACKER_NAMES,
    _BADGE_FIELDS,
    _BUILDER_OMITTED_ATTACKERS,
    _BUILD_MODES,
    _CSV_PREVIEW_ROWS,
    _EDITABLE_CONFIGS,
    _FRAMEWORK_DESCRIPTIONS,
    _FRAMEWORKS,
    _ICONS,
    _INELIGIBLE_ARMS,
    _INELIGIBLE_REASONS,
    _INVENTORY_MAX_DEPTH,
    _INVENTORY_MAX_ENTRIES,
    _LOG_TAIL_BYTES,
    _MATRIX_PARAMS,
    _MAX_RENDER_BYTES,
    _MODALITIES,
    _MOD_ICON_NAME,
    _NATIVE_ONLY_ATTACKERS,
    _PARAM_HELP,
    _REPO_ROOT,
    _SOURCE_METRIC_ARMS,
    _SUGGEST_STATIC,
    _WARNINGS_FILE,
    _WARNINGS_MAX,
    _WARNING_TONES,
    Command,
    CommandParam,
    _arm_head,
    _commands,
    _contained,
    _icon,
    _ineligible,
    _mod_icon,
    _mod_set,
    _param_values,
    build_argv,
    evidence_badges,
)
from .rig_web_app.reports import (
    _LEVEL2_ROW_FIELDS,
    _LEVEL2_STRATUM_FIELDS,
    _REPORT_SCHEMAS,
    _currency_code,
    _finite_nonneg,
    _valid_iso_date,
    _validate_content_id,
    _validate_report_document,
    collect_reports,
    compute_costs,
    load_pricing,
    rate_for,
    reconcile_pricing_ownership,
)
from .rig_web_app.server import (
    _MAX_POST_BYTES,
    _make_server,
    _serve,
    main as _server_main,
)
from .rig_web_app.storage import ConsoleDB
from .rig_web_app.ui import (
    _BUILDER_SCRIPT,
    _BUSY_OVERLAY,
    _FAVICON_SVG,
    _NAV_LINKS,
    _STYLE,
    _badges_html,
    _crumbs,
    _human_duration,
    _human_size,
    _page,
)


def main(argv: list[str] | None = None) -> int:
    """Run the modular rig-console implementation through its stable facade."""

    return _server_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
