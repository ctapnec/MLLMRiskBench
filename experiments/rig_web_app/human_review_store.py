"""Independent human ratings in SQLite, with lossless existing-audit exports.

The operator imports a prepared audit sample. Rater payloads are allowlisted:
identities needed by analysis never become rater-visible fields.
"""

from __future__ import annotations

from .i18n import text as _ui_text

from collections import Counter
from contextlib import contextmanager
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from experiments import human_audit as audit

COMMON = {"label": audit.VALID_LABELS, **audit.DIMENSION_LABELS}
VISIBLE = (
    "prompt",
    "response",
    "source_policy_instruction",
    "source_policy_intended_metric",
    "modality",
)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _csv_bytes(fields, rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8-sig")


def _allowed(row, mode):
    if mode == "common":
        labels = {k: set(v) for k, v in COMMON.items()}
        if row.get("expected_behavior") in {"safe_answer", "comply_safely"}:
            labels["label"].discard("refusal")
        else:
            labels["label"].discard("over_refusal")
        return labels
    # The native audit exporter writes pipe-separated labels, not JSON.
    vocabulary = row["task_label_vocabulary"].split("|")
    if tuple(vocabulary) not in audit.SOURCE_TASK_VOCABULARY.values():
        raise ValueError(
            _ui_text("human_review_store.source_task_needs_its_declared_label_vocabulary")
        )
    return {
        "task_label": set(vocabulary),
        "parse_status_label": set(audit._SOURCE_TASK_PARSE_LABELS),
    }


class HumanReviewStore:
    def __init__(self, database: Path, root: Path, *, allowed_roots, media_roots=()):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.allowed_roots = tuple(Path(p).resolve() for p in allowed_roots)
        self.media_roots = tuple(Path(p).resolve() for p in media_roots)
        self.lock = threading.RLock()
        self._media_indexes = {}
        self.conn = sqlite3.connect(database, check_same_thread=False, timeout=10)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS human_studies (
                    id TEXT PRIMARY KEY, campaign TEXT NOT NULL, name TEXT NOT NULL,
                    mode TEXT NOT NULL, fields TEXT NOT NULL, metadata TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS human_items (
                    study TEXT NOT NULL, id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                    content TEXT NOT NULL, media TEXT NOT NULL, PRIMARY KEY(study,id));
                CREATE TABLE IF NOT EXISTS human_reviewers (
                    study TEXT NOT NULL, id TEXT NOT NULL, role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
                    qualification TEXT NOT NULL, consent REAL, withdrawn REAL, PRIMARY KEY(study,id));
                CREATE TABLE IF NOT EXISTS human_ratings (
                    study TEXT NOT NULL, item TEXT NOT NULL, reviewer TEXT NOT NULL,
                    revision INTEGER NOT NULL, state TEXT NOT NULL, value TEXT NOT NULL, updated REAL NOT NULL,
                    PRIMARY KEY(study,item,reviewer));
                CREATE TABLE IF NOT EXISTS human_adjudications (
                    study TEXT NOT NULL, item TEXT NOT NULL, reviewer TEXT NOT NULL,
                    value TEXT NOT NULL, rationale TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(study,item));
                CREATE TABLE IF NOT EXISTS human_review_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, study TEXT NOT NULL, reviewer TEXT,
                    item TEXT, action TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS human_review_sources (
                    id TEXT PRIMARY KEY, campaign TEXT NOT NULL, name TEXT NOT NULL,
                    metadata TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS human_review_preparations (
                    id TEXT PRIMARY KEY, campaign TEXT NOT NULL, job TEXT NOT NULL,
                    value TEXT NOT NULL, study TEXT);
            """)

    def close(self):
        with self.lock:
            self.conn.close()

    @contextmanager
    def transaction(self):
        with self.lock, self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            yield

    def _event(self, study, reviewer, item, action, detail):
        self.conn.execute(
            "INSERT INTO human_review_events(study,reviewer,item,action,detail,created) VALUES(?,?,?,?,?,?)",
            (study, reviewer, item, action, _json(detail), time.time()),
        )

    def _path(self, path):
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_file() or not any(
            resolved.is_relative_to(p) for p in self.allowed_roots
        ):
            raise ValueError(
                _ui_text(
                    "human_review_store.choose_a_prepared_file_inside_the_configured_results_or_state_dir"
                )
            )
        return resolved

    def create(self, *, campaign, name, prepared, mode, metadata):
        if mode not in {"common", "source_task"} or not name.strip() or len(name) > 200:
            raise ValueError(_ui_text("human_review_store.choose_a_study_name_and_audit_frame"))
        path = self._path(prepared)
        resolved_media = path.with_suffix(".MEDIA.json")
        if resolved_media.is_file():
            metadata = dict(metadata, media_index=str(self._path(resolved_media)))
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError(_ui_text("human_review_store.prepared_sample_exceeds_64_mib"))
        reader = csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig")))
        fields = reader.fieldnames or []
        rating_fields = (
            audit._RATING_FIELDS if mode == "common" else audit._SOURCE_TASK_RATING_FIELDS
        )
        if len(fields) != len(set(fields)) or not rating_fields | set(VISIBLE) | {
            "sample_key",
            "media_references",
        } <= set(fields):
            raise ValueError(
                _ui_text(
                    "human_review_store.use_the_complete_prepared_audit_csv_for_the_selected_frame"
                )
            )
        unique, counts = {}, Counter()
        for row in reader:
            if (
                None in row
                or any(v is None for v in row.values())
                or any(row[k] for k in rating_fields)
            ):
                raise ValueError(
                    _ui_text(
                        "human_review_store.import_only_an_unchanged_blank_prepared_sample_not_existing_ratin"
                    )
                )
            key = row["sample_key"]
            if not key or (key in unique and unique[key] != row):
                raise ValueError(_ui_text("human_review_store.conflicting_prepared_sample_rows"))
            _allowed(row, mode)
            unique[key] = row
            counts[key] += 1
        if not unique or len(unique) > 10000 or set(counts.values()) not in ({1}, {2}):
            raise ValueError(
                _ui_text(
                    "human_review_store.sample_must_contain_one_or_two_identical_blank_rows_per_item"
                )
            )
        personal = metadata.get("review_kind") == "personal"
        for key in (
            ("results",)
            if personal
            else ("ethics", "consent", "compensation", "stop_contact", "results")
        ):
            if not str(metadata.get(key, "")).strip():
                raise ValueError(_ui_text("human_review_store.record_study_arrangements") + key)
        study = secrets.token_hex(12)
        directory = self.root / study
        directory.mkdir(mode=0o700)
        blank = [row for row in unique.values() for _ in range(1 if personal else 2)]
        payload = _csv_bytes(fields, blank)
        (directory / "prepared.csv").write_bytes(payload)
        metadata = dict(
            metadata,
            source=str(path),
            rows=len(unique),
            clusters=len({r.get("cluster_key", r["sample_key"]) for r in unique.values()}),
            prepared_sha256=hashlib.sha256(payload).hexdigest(),
            model_identity_hidden=True,
            qualification_policy="not_applied_to_personal_review"
            if personal
            else "independent_20_items_at_least_16_correct_per_dimension",
        )
        if personal:
            # Operator-only resume link. The blinded reviewer payload never includes metadata.
            metadata["personal_token"] = secrets.token_urlsafe(32)
        with self.transaction():
            self.conn.execute(
                "INSERT INTO human_studies VALUES(?,?,?,?,?,?,?)",
                (study, campaign, name.strip(), mode, _json(fields), _json(metadata), time.time()),
            )
            for ordinal, row in enumerate(unique.values()):
                references = json.loads(row["media_references"])
                if not isinstance(references, list):
                    raise ValueError(_ui_text("human_review_store.media_references_must_be_a_list"))
                self.conn.execute(
                    "INSERT INTO human_items VALUES(?,?,?,?,?)",
                    (study, secrets.token_hex(12), ordinal, _json(row), _json(references)),
                )
            self._event(study, None, None, "study_created", {"rows": len(unique)})
            if personal:
                self.conn.execute(
                    "INSERT INTO human_reviewers VALUES(?,?,?,?,?,?,NULL)",
                    (
                        study,
                        "personal",
                        "personal",
                        hashlib.sha256(metadata["personal_token"].encode()).hexdigest(),
                        _json({"independent": False}),
                        time.time(),
                    ),
                )
        return study

    def studies(self, campaign=""):
        with self.lock:
            return [
                dict(r)
                for r in self.conn.execute(
                    "SELECT id,campaign,name,mode,created,COALESCE(json_extract(metadata,'$.review_kind'),'independent') AS review_kind FROM human_studies WHERE (?='' OR campaign=?) ORDER BY created DESC",
                    (campaign, campaign),
                )
            ]

    def register_source(
        self,
        *,
        campaign,
        name,
        results,
        historical_code_repository="",
        judge_configuration_sha256="",
        media_index="",
    ):
        """Associate an existing analysis scope without changing its results."""
        path = Path(results).resolve(strict=True)
        if not path.is_dir() or not any(path.is_relative_to(p) for p in self.allowed_roots):
            raise ValueError(
                _ui_text(
                    "human_review_store.select_an_existing_results_directory_in_the_configured_results_st"
                )
            )
        if not name.strip() or not campaign:
            raise ValueError(
                _ui_text("human_review_store.name_the_analysis_scope_and_its_campaign")
            )
        metadata = dict(
            results=str(path),
            historical_code_repository=historical_code_repository,
            judge_configuration_sha256=judge_configuration_sha256,
            media_index=str(self._path(media_index)) if media_index else "",
        )
        with self.transaction():
            existing = self.conn.execute(
                "SELECT id FROM human_review_sources WHERE campaign=? AND name=? AND metadata=?",
                (campaign, name.strip(), _json(metadata)),
            ).fetchone()
            if existing:
                return existing["id"]
            key = secrets.token_hex(12)
            self.conn.execute(
                "INSERT INTO human_review_sources VALUES(?,?,?,?)",
                (key, campaign, name.strip(), _json(metadata)),
            )
        return key

    def sources(self, campaign):
        with self.lock:
            return [
                dict(r, metadata=json.loads(r["metadata"]))
                for r in self.conn.execute(
                    "SELECT * FROM human_review_sources WHERE campaign=? ORDER BY name,id",
                    (campaign,),
                )
            ]

    def save_preparation(self, campaign, job, value):
        key = secrets.token_hex(12)
        with self.transaction():
            self.conn.execute(
                "INSERT INTO human_review_preparations VALUES(?,?,?,?,NULL)",
                (key, campaign, job, _json(value)),
            )
        return key

    def preparations(self, campaign):
        with self.lock:
            return [
                dict(r, value=json.loads(r["value"]))
                for r in self.conn.execute(
                    "SELECT * FROM human_review_preparations WHERE campaign=? ORDER BY rowid DESC",
                    (campaign,),
                )
            ]

    def preparation(self, key):
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM human_review_preparations WHERE id=?", (key,)
            ).fetchone()
            if row is None:
                raise ValueError(_ui_text("human_review_store.unknown_sample_preparation"))
            return dict(row, value=json.loads(row["value"]))

    def create_prepared_study(self, key):
        with self.lock:
            preparation = self.preparation(key)
            if preparation["study"]:
                return preparation["study"]
            value = preparation["value"]
            study = self.create(campaign=preparation["campaign"], **value)
            with self.conn:
                self.conn.execute(
                    "UPDATE human_review_preparations SET study=? WHERE id=?", (study, key)
                )
            return study

    def study(self, study):
        row = self.conn.execute("SELECT * FROM human_studies WHERE id=?", (study,)).fetchone()
        if row is None:
            raise ValueError(_ui_text("human_review_store.unknown_human_evaluation_study"))
        return dict(row, fields=json.loads(row["fields"]), metadata=json.loads(row["metadata"]))

    def enroll(self, study, reviewer, role, qualification):
        if role not in {"rater", "adjudicator"} or not reviewer or len(reviewer) > 80:
            raise ValueError(_ui_text("human_review_store.use_a_pseudonymous_reviewer_id_and_role"))
        with self.transaction():
            info = self.study(study)
            if info["metadata"].get("review_kind") == "personal":
                raise ValueError(
                    _ui_text(
                        "human_review_store.personal_review_is_separate_from_independent_reviewer_enrollment"
                    )
                )
            dimensions = (
                list(COMMON) if info["mode"] == "common" else ["task_label", "parse_status_label"]
            )
            scores = qualification.get("correct", {})
            if (
                not qualification.get("reference")
                or qualification.get("items") != 20
                or set(scores) != set(dimensions)
                or any(type(n) is not int or not 16 <= n <= 20 for n in scores.values())
                or qualification.get("independent_reference") is not True
                or qualification.get("language_and_experience_confirmed") is not True
            ):
                raise ValueError(
                    _ui_text(
                        "human_review_store.record_the_actual_independent_20_item_qualification_with_at_least"
                    )
                )
            if self.conn.execute(
                "SELECT 1 FROM human_reviewers WHERE study=? AND id=?", (study, reviewer)
            ).fetchone():
                raise ValueError(
                    _ui_text(
                        "human_review_store.each_person_has_one_independent_role_in_this_study"
                    )
                )
            count = self.conn.execute(
                "SELECT COUNT(*) FROM human_reviewers WHERE study=? AND role=?", (study, role)
            ).fetchone()[0]
            if count >= (2 if role == "rater" else 1):
                raise ValueError(
                    _ui_text("human_review_store.study_already_has_its_two_raters_or_adjudicator")
                )
            token = secrets.token_urlsafe(32)
            self.conn.execute(
                "INSERT INTO human_reviewers VALUES(?,?,?,?,?,NULL,NULL)",
                (
                    study,
                    reviewer,
                    role,
                    hashlib.sha256(token.encode()).hexdigest(),
                    _json(qualification),
                ),
            )
            self._event(
                study,
                reviewer,
                None,
                "reviewer_enrolled",
                {"role": role, "qualification": qualification},
            )
        return token

    def _reviewer(self, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 100:
            raise ValueError(_ui_text("human_review_store.unknown_review_link"))
        row = self.conn.execute(
            "SELECT * FROM human_reviewers WHERE token_hash=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        if row is None or row["withdrawn"] is not None:
            raise ValueError(_ui_text("human_review_store.review_link_unavailable"))
        return row

    def consent(self, token):
        with self.transaction():
            r = self._reviewer(token)
            self.conn.execute(
                "UPDATE human_reviewers SET consent=COALESCE(consent,?) WHERE study=? AND id=?",
                (time.time(), r["study"], r["id"]),
            )
            self._event(r["study"], r["id"], None, "consent_recorded", {})

    def withdraw(self, token):
        with self.transaction():
            r = self._reviewer(token)
            self.conn.execute(
                "UPDATE human_reviewers SET withdrawn=? WHERE study=? AND id=?",
                (time.time(), r["study"], r["id"]),
            )
            self._event(r["study"], r["id"], None, "withdrawn", {"further_review_disabled": True})

    def _item(self, study, item):
        row = self.conn.execute(
            "SELECT * FROM human_items WHERE study=? AND id=?", (study, item)
        ).fetchone()
        if row is None:
            raise ValueError(_ui_text("human_review_store.item_is_not_assigned_to_this_study"))
        return dict(row, content=json.loads(row["content"]), media=json.loads(row["media"]))

    def _media_path(self, reference, media_index=""):
        locator = reference.get("locator", "")
        parts = locator.split("/")
        if len(parts) == 2 and parts[0] in {"@content-sha256", "@inline-sha256"}:
            digest = parts[1]
            if (
                len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or reference.get("sha256") != digest
                or not media_index
            ):
                raise ValueError(
                    _ui_text(
                        "human_review_store.required_media_has_no_matching_retained_media_index"
                    )
                )
            index = self._path(media_index)
            stat = index.stat()
            if stat.st_size > 64 * 1024 * 1024:
                raise ValueError(
                    _ui_text("human_review_store.retained_media_index_exceeds_the_reader_limit")
                )
            stamp = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino)
            cached = self._media_indexes.get(index)
            if cached is None or cached[0] != stamp:
                value = json.loads(index.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError(
                        _ui_text(
                            "human_review_store.retained_media_index_must_map_content_identities_to_local_files"
                        )
                    )
                cached = (stamp, value)
                self._media_indexes[index] = cached
            path = Path(cached[1].get(digest, ""))
            if not path.is_absolute():
                raise ValueError(
                    _ui_text("human_review_store.required_media_is_absent_from_the_retained_index")
                )
            path = path.resolve(strict=True)
        else:
            if (
                len(parts) < 3
                or parts[0] != "@media-root"
                or not parts[1].isdigit()
                or any(p in {"", ".", ".."} for p in parts[2:])
                or "\\" in locator
            ):
                raise ValueError(
                    _ui_text(
                        "human_review_store.required_media_needs_an_operator_resolved_local_locator"
                    )
                )
            number = int(parts[1])
            if number >= len(self.media_roots):
                raise ValueError(_ui_text("human_review_store.required_media_root_is_unavailable"))
            root = self.media_roots[number]
            path = root.joinpath(*parts[2:]).resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError(
                    _ui_text("human_review_store.required_media_escaped_its_configured_root")
                )
        if (
            not any(path.is_relative_to(root) for root in self.media_roots)
            or not path.is_file()
            or path.stat().st_size > 32 * 1024 * 1024
        ):
            raise ValueError(
                _ui_text(
                    "human_review_store.required_media_is_unavailable_or_exceeds_the_viewer_limit"
                )
            )
        mime = reference.get("mime")
        if mime not in {
            "image/png",
            "image/jpeg",
            "image/webp",
            "image/gif",
            "audio/wav",
            "audio/mpeg",
            "video/mp4",
            "video/webm",
        }:
            raise ValueError(
                _ui_text("human_review_store.required_media_type_is_not_supported_by_this_viewer")
            )
        return path, mime

    def _ratings(self, study, item):
        return [
            dict(r, value=json.loads(r["value"]))
            for r in self.conn.execute(
                "SELECT * FROM human_ratings WHERE study=? AND item=? AND state='submitted' ORDER BY reviewer",
                (study, item),
            )
        ]

    def view(self, token, item=None):
        with self.lock:
            r = self._reviewer(token)
            study = self.study(r["study"])
            result = {
                "role": r["role"],
                "consented": r["consent"] is not None,
                "consent": study["metadata"].get("consent", ""),
                "compensation": study["metadata"].get("compensation", ""),
                "stop_contact": study["metadata"].get("stop_contact", ""),
            }
            if r["role"] == "personal":
                result["summary_url"] = "/human-evaluation/" + r["study"]
            if r["consent"] is None:
                return result
            items = self.conn.execute(
                "SELECT id FROM human_items WHERE study=? ORDER BY ordinal", (r["study"],)
            ).fetchall()
            queue = []
            for entry in items:
                if r["role"] in {"rater", "personal"}:
                    rating = self.conn.execute(
                        "SELECT state FROM human_ratings WHERE study=? AND item=? AND reviewer=?",
                        (r["study"], entry["id"], r["id"]),
                    ).fetchone()
                    state = rating["state"] if rating else "unstarted"
                else:
                    ratings = self._ratings(r["study"], entry["id"])
                    content = self._item(r["study"], entry["id"])["content"]
                    if len(ratings) != 2 or all(
                        ratings[0]["value"][k] == ratings[1]["value"][k]
                        for k in _allowed(content, study["mode"])
                    ):
                        continue
                    state = (
                        "submitted"
                        if self.conn.execute(
                            "SELECT 1 FROM human_adjudications WHERE study=? AND item=?",
                            (r["study"], entry["id"]),
                        ).fetchone()
                        else "unstarted"
                    )
                queue.append({"id": entry["id"], "state": state})
            result["queue"] = queue
            if item is None:
                return result
            if item not in {q["id"] for q in queue}:
                raise ValueError(
                    _ui_text("human_review_store.item_is_not_available_in_this_review_queue")
                )
            selected = self._item(r["study"], item)
            content = selected["content"]
            shown = {k: content[k] for k in VISIBLE}
            shown.update(
                id=item, choices={k: sorted(v) for k, v in _allowed(content, study["mode"]).items()}
            )
            shown["media"] = []
            for index, reference in enumerate(selected["media"]):
                try:
                    self._media_path(reference, study["metadata"].get("media_index", ""))
                    available = True
                except (OSError, ValueError):
                    available = False
                shown["media"].append(
                    {"index": index, "modality": reference.get("modality"), "available": available}
                )
            if r["role"] in {"rater", "personal"}:
                rating = self.conn.execute(
                    "SELECT revision,state,value FROM human_ratings WHERE study=? AND item=? AND reviewer=?",
                    (r["study"], item, r["id"]),
                ).fetchone()
                shown["rating"] = (
                    dict(rating, value=json.loads(rating["value"]))
                    if rating
                    else {"revision": 0, "state": "unstarted", "value": {}}
                )
            else:
                shown["independent_ratings"] = [
                    {"value": row["value"]} for row in self._ratings(r["study"], item)
                ]
            result["item"] = shown
            return result

    def media(self, token, item, index):
        with self.lock:
            shown = self.view(token, item)
            if not shown["consented"]:
                raise ValueError(_ui_text("human_review_store.consent_is_required"))
            r = self._reviewer(token)
            references = self._item(r["study"], item)["media"]
            if type(index) is not int or not 0 <= index < len(references):
                raise ValueError(_ui_text("human_review_store.unknown_assigned_media"))
            path, mime = self._media_path(
                references[index], self.study(r["study"])["metadata"].get("media_index", "")
            )
            return mime, path.read_bytes()

    def save(self, token, item, *, revision, value, submit=False, defer=False):
        with self.transaction():
            r = self._reviewer(token)
            if r["role"] not in {"rater", "personal"} or r["consent"] is None:
                raise ValueError(
                    _ui_text("human_review_store.independent_rater_consent_is_required")
                )
            study = self.study(r["study"])
            selected = self._item(r["study"], item)
            choices = _allowed(selected["content"], study["mode"])
            allowed = set(choices) | {"confidence", "notes", "media_viewed", "defer_reason"}
            if (
                not isinstance(value, dict)
                or not set(value) <= allowed
                or len(_json(value)) > 16000
            ):
                raise ValueError(
                    _ui_text("human_review_store.unexpected_rating_fields_or_overlong_notes")
                )
            if any(v not in choices[k] for k, v in value.items() if k in choices and v):
                raise ValueError(_ui_text("human_review_store.invalid_rubric_choice"))
            previous = self.conn.execute(
                "SELECT * FROM human_ratings WHERE study=? AND item=? AND reviewer=?",
                (r["study"], item, r["id"]),
            ).fetchone()
            if type(revision) is not int or revision != (previous["revision"] if previous else 0):
                raise ValueError(
                    _ui_text("human_review_store.draft_changed_in_another_tab_reload_before_saving")
                )
            if previous and previous["state"] == "submitted" and r["role"] != "personal":
                raise ValueError(
                    _ui_text("human_review_store.submitted_independent_ratings_are_fixed")
                )
            if submit:
                if (
                    defer
                    or any(value.get(k) not in v for k, v in choices.items())
                    or type(value.get("confidence")) is not int
                    or value["confidence"] not in {1, 2, 3, 4, 5}
                ):
                    raise ValueError(
                        _ui_text(
                            "human_review_store.complete_every_rubric_dimension_and_confidence_before_submission"
                        )
                    )
                if selected["media"]:
                    if value.get("media_viewed") is not True:
                        raise ValueError(
                            _ui_text(
                                "human_review_store.view_every_required_asset_before_submitting"
                            )
                        )
                    for media in selected["media"]:
                        self._media_path(media, study["metadata"].get("media_index", ""))
            if defer and not str(value.get("defer_reason", "")).strip():
                raise ValueError(
                    _ui_text("human_review_store.record_why_this_item_cannot_be_assessed")
                )
            state = "submitted" if submit else "deferred" if defer else "draft"
            self.conn.execute(
                "INSERT INTO human_ratings VALUES(?,?,?,?,?,?,?) ON CONFLICT(study,item,reviewer) DO UPDATE SET revision=excluded.revision,state=excluded.state,value=excluded.value,updated=excluded.updated",
                (r["study"], item, r["id"], revision + 1, state, _json(value), time.time()),
            )
            self._event(r["study"], r["id"], item, state, {"revision": revision + 1})
            return {"revision": revision + 1, "state": state}

    def adjudicate(self, token, item, value, rationale):
        with self.transaction():
            view = self.view(token, item)
            r = self._reviewer(token)
            if r["role"] != "adjudicator" or not view["consented"]:
                raise ValueError(_ui_text("human_review_store.adjudicator_consent_is_required"))
            choices = view["item"]["choices"]
            if (
                set(value) != set(choices)
                or any(value[k] not in v for k, v in choices.items())
                or not rationale.strip()
                or len(rationale) > 8000
            ):
                raise ValueError(
                    _ui_text(
                        "human_review_store.resolve_each_dimension_and_provide_an_adjudication_rationale"
                    )
                )
            if self.conn.execute(
                "SELECT 1 FROM human_adjudications WHERE study=? AND item=?", (r["study"], item)
            ).fetchone():
                raise ValueError(_ui_text("human_review_store.adjudication_already_submitted"))
            self.conn.execute(
                "INSERT INTO human_adjudications VALUES(?,?,?,?,?,?)",
                (r["study"], item, r["id"], _json(value), rationale, time.time()),
            )
            self._event(r["study"], r["id"], item, "adjudicated", {"rationale": rationale})

    def summary(self, study):
        with self.lock:
            info = self.study(study)
            personal = info["metadata"].get("review_kind") == "personal"
            counts = Counter(
                {
                    "outputs": 0,
                    "required_ratings": 0,
                    "submitted": 0,
                    "deferred": 0,
                    "paired": 0,
                    "disagreements": 0,
                    "adjudicated": 0,
                }
            )
            for item in self.conn.execute(
                "SELECT id,content FROM human_items WHERE study=?", (study,)
            ):
                counts["outputs"] += 1
                counts["required_ratings"] += 1 if personal else 2
                rows = self._ratings(study, item["id"])
                counts["submitted"] += len(rows)
                if len(rows) == 2:
                    counts["paired"] += 1
                    if any(
                        rows[0]["value"][k] != rows[1]["value"][k]
                        for k in _allowed(json.loads(item["content"]), info["mode"])
                    ):
                        counts["disagreements"] += 1
                        counts["adjudicated"] += bool(
                            self.conn.execute(
                                "SELECT 1 FROM human_adjudications WHERE study=? AND item=?",
                                (study, item["id"]),
                            ).fetchone()
                        )
            counts["deferred"] = self.conn.execute(
                "SELECT COUNT(*) FROM human_ratings WHERE study=? AND state='deferred'", (study,)
            ).fetchone()[0]
            reviewers = [
                dict(r)
                for r in self.conn.execute(
                    "SELECT id,role,consent,withdrawn FROM human_reviewers WHERE study=? ORDER BY role,id",
                    (study,),
                )
            ]
            return {
                "study": info,
                "counts": dict(counts),
                "reviewers": reviewers,
                "ready_for_analysis": not personal
                and counts["submitted"] == counts["required_ratings"]
                and counts["disagreements"] == counts["adjudicated"]
                and not any(r["withdrawn"] for r in reviewers),
            }

    def personal_export(self, study):
        """Partial personal evaluations are never the independent two-rater CSV."""
        with self.lock:
            info = self.study(study)
            if info["metadata"].get("review_kind") != "personal":
                raise ValueError(_ui_text("human_review_store.choose_a_personal_review"))
            rows = []
            fields = [
                "review_kind",
                "item",
                "sample_key",
                "state",
                *list(
                    COMMON
                    if info["mode"] == "common"
                    else {"task_label": None, "parse_status_label": None}
                ),
                "confidence",
                "notes",
            ]
            for item in self.conn.execute(
                "SELECT id,content FROM human_items WHERE study=? ORDER BY ordinal", (study,)
            ):
                rating = self.conn.execute(
                    "SELECT state,value FROM human_ratings WHERE study=? AND item=? AND reviewer=?",
                    (study, item["id"], "personal"),
                ).fetchone()
                values = json.loads(rating["value"]) if rating else {}
                row = {key: values.get(key, "") for key in fields}
                row.update(
                    review_kind="personal_not_independent",
                    item=item["id"],
                    sample_key=json.loads(item["content"])["sample_key"],
                    state=rating["state"] if rating else "unstarted",
                )
                rows.append(
                    {
                        key: audit._csv_safe(value) if isinstance(value, str) else value
                        for key, value in row.items()
                    }
                )
            return _csv_bytes(fields, rows)

    def export(self, study):
        with self.transaction():
            summary = self.summary(study)
            if not summary["ready_for_analysis"]:
                raise ValueError(
                    _ui_text(
                        "human_review_store.complete_both_independent_ratings_and_every_disagreement_before_a"
                    )
                )
            info = summary["study"]
            rows = []
            for item in self.conn.execute(
                "SELECT * FROM human_items WHERE study=? ORDER BY ordinal", (study,)
            ):
                original = json.loads(item["content"])
                decisions = self._ratings(study, item["id"])
                adjudicated = self.conn.execute(
                    "SELECT value FROM human_adjudications WHERE study=? AND item=?",
                    (study, item["id"]),
                ).fetchone()
                final = json.loads(adjudicated["value"]) if adjudicated else {}
                for decision in decisions:
                    row = dict(original, rater_id=decision["reviewer"])
                    for key in (*_allowed(original, info["mode"]), "confidence", "notes"):
                        value = decision["value"].get(key, "")
                        row[key] = audit._csv_safe(value) if key == "notes" else value
                    for key, value in final.items():
                        row["adjudicated_" + key] = value
                    rows.append(row)
            data = _csv_bytes(info["fields"], rows)
            self._event(study, None, None, "complete_labels_exported", {"ratings": len(rows)})
            return data
