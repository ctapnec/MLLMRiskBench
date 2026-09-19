"""Resolve saved attack material and installed capture settings, not operator paths."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import hashlib
import html
import json
from pathlib import Path
from uuid import uuid4

from .builder_replays import argument

FIELDS = {
    "t3mp3st": ("t3_artifact", "t3_artifact_sha"),
    "harmbench": ("harm_config",),
    "ideator": ("ideator_manifest", "ideator_manifest_sha"),
}


def capture_defaults(app, kind, params):
    values = dict(params)
    prefix = "t3cap_" if kind == "t3mp3st" else "hcap_"
    root = (app.results_root / "rig-web" / "prepared-attacks" / uuid4().hex).resolve()
    defaults = (
        {"out": str(root)}
        if kind == "t3mp3st"
        else {
            "artifact_out": str(root / "capture.json"),
            "config_out": str(root / "attackers.json"),
        }
    )
    from experiments.framework_runtime_installer import (
        load_lock,
        published_store,
        canonical_python_interpreter,
    )

    if all(
        values.get(prefix + k)
        for k in (("revision",) if kind == "t3mp3st" else ("revision", "repo", "source"))
    ):
        for key, value in defaults.items():
            if not values.get(prefix + key):
                values[prefix + key] = value
        return values
    service = app.framework_runtimes
    lock = load_lock(service.lock_path)
    entry = next(row for row in lock["frameworks"] if row["name"] == kind)
    layout = service._layout(lock["lock_id"])
    defaults["revision"] = entry["source"]["commit"]
    if kind == "harmbench":
        store = published_store(entry, lock, layout)
        source = (store / "source" / kind).resolve()
        defaults.update(
            repo=str(source),
            source=str(source / "data/behavior_datasets/harmbench_behaviors_text_all.csv"),
            python=str(canonical_python_interpreter(entry, lock, layout)),
        )
    for key, value in defaults.items():
        if not values.get(prefix + key):
            values[prefix + key] = value
    return values


def capture_result(app, job):
    if job.state() != "complete" or job.exit_code() != 0:
        raise ValueError(
            _ui_text("prepared_inputs.the_attack_capture_has_not_completed_successfully")
        )
    if job.command == "harmbench_capture":
        path = app._prepared_file(
            argument(job.argv, "--attacker-config-out"),
            label=_ui_text("prepared_inputs.saved_harmbench_config"),
        )
        return {"harm_config": str(path)}
    if job.command == "capture_t3mp3st":
        root = Path(argument(job.argv, "--out")).resolve()
        if not root.is_relative_to(app.results_root.resolve()):
            raise ValueError(_ui_text("prepared_inputs.capture_output_is_outside_results"))
        paths = list(root.glob("t3mp3st-plan-bundle-*.json"))
        if len(paths) != 1:
            raise ValueError(
                _ui_text(
                    "prepared_inputs.choose_an_individual_saved_capture_this_output_contains_several_b"
                )
            )
        path = app._prepared_file(
            str(paths[0]), label=_ui_text("prepared_inputs.saved_t3mp3st_bundle")
        )
        return {
            "t3_artifact": str(path),
            "t3_artifact_sha": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    raise ValueError(_ui_text("prepared_inputs.this_job_is_not_a_prepared_attack_capture"))


def choices(app, kind):
    """Read saved job metadata only; never scan the campaign payload tree."""
    command = {"t3mp3st": "capture_t3mp3st", "harmbench": "harmbench_capture"}.get(kind)
    if command is None:
        return []
    rows = (
        app.db._query(
            "SELECT job_id,argv,started_at FROM jobs WHERE command=? AND state=? ORDER BY started_at DESC",
            (command, "complete"),
        )
        or []
    )
    result = []
    for row in rows:
        argv = json.loads(row["argv"])
        corpus = argument(argv, "--corpus" if kind == "t3mp3st" else "--corpus-name") or kind
        result.append(
            (row["job_id"], corpus + " - " + str(row["started_at"]) + " - " + row["job_id"])
        )
    return result


def apply_choice(app, form):
    params = dict(form)
    for kind in FIELDS:
        key = params.pop("prepared_choice_" + kind, "")
        if not key or kind not in params.get("attackers", "").split(","):
            continue
        if key not in {item[0] for item in choices(app, kind)}:
            raise ValueError(
                _ui_text("prepared_inputs.choose_an_available_completed_attack_capture")
            )
        job = app.jobs.get(key)
        if job is None:
            raise ValueError(_ui_text("prepared_inputs.the_selected_capture_job_is_unavailable"))
        expected = {"t3mp3st": "capture_t3mp3st", "harmbench": "harmbench_capture"}[kind]
        if job.command != expected:
            raise ValueError(_ui_text("prepared_inputs.the_capture_does_not_match_this_attacker"))
        params.update(capture_result(app, job))
    # A manually imported manifest needs a location, not a copied checksum.
    for path_key, sha_key in [
        ("t3_artifact", "t3_artifact_sha"),
        ("ideator_manifest", "ideator_manifest_sha"),
    ]:
        if (
            params.get(path_key)
            and not params.get(sha_key)
            and not params[path_key].startswith("private-")
        ):
            path = app._prepared_file(
                params[path_key], label=_ui_text("prepared_inputs.imported_attack_material")
            )
            params[sha_key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return params


def picker(app, kind):
    options = choices(app, kind)
    if not options:
        return _ui_template(
            '<p class="note">[[text:prepared_inputs.no_completed_capture_is_available_yet_creating_one_will_attach_it]]</p>'
        )
    return (
        _ui_template(
            '<label class="campaign-field">[[text:prepared_inputs.saved_attack_material]]<select name="prepared_choice_'
        )
        + kind
        + _ui_template(
            '"><option value="">[[text:prepared_inputs.keep_current_selection]]</option>'
        )
        + "".join(
            '<option value="' + html.escape(key) + '">' + html.escape(label) + "</option>"
            for key, label in options
        )
        + "</select></label>"
    )
