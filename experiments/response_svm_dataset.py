"""Export labelled static text responses from an explicitly selected campaign index."""
from __future__ import annotations

from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import sqlite3

from ura.response_svm import VALID_LABELS, connected_groups


def visible_turns(turns, *, assistant_only=False) -> str:
    if not isinstance(turns, list):
        raise ValueError("Retained dialog turns are unavailable")
    text = []
    for turn in turns:
        if assistant_only and turn.get("role") != "assistant":
            continue
        content = turn.get("content")
        if not isinstance(content, str):
            raise ValueError("Expected a retained text-content field")
        text.append(content if assistant_only else str(turn.get("role")) + ": " + content)
    return "\n".join(text)


def export_dataset(*, database: Path, candidates: Path, campaigns: list[str], judge: str,
                   matched_campaign: str, exclude_models=()) -> tuple[list[dict], dict]:
    opener = gzip.open if candidates.suffix == ".gz" else open
    with opener(candidates, "rt", encoding="utf-8") as stream:
        inputs = json.load(stream)
    metadata = {}
    all_text = []
    for item in inputs:
        if item["modality"] != "text" or item["framework"] != "replay":
            continue
        row = dict(item, input_id=item["input_identity_sha256"], prompt=visible_turns(item["rendered_input"]))
        if row["input_id"] in metadata:
            raise ValueError("Candidate input identity is duplicated")
        metadata[row["input_id"]] = row
        all_text.append(row)
    for row, group in zip(all_text, connected_groups(all_text)):
        row["group"] = group
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("BEGIN")
    placeholders = ",".join("?" for _ in campaigns)
    if not campaigns:
        raise ValueError("Select at least one campaign")
    query = f"""SELECT a.campaign_id,a.model,a.input_id,a.modality,a.framework,a.corpus,
        r.response_id,r.outcome,r.truncated,r.condition_id,r.details,
        h.status teacher_status,h.label teacher_label,h.source_ref teacher_source,
        n.judge_id local_condition,n.status local_status,n.label local_label,n.source_ref local_source
        FROM campaign_assignments a LEFT JOIN campaign_responses r
        ON r.campaign_id=a.campaign_id AND r.assignment_id=a.assignment_id AND r.response_id=a.response_id
        LEFT JOIN campaign_judgments h
        ON h.campaign_id=r.campaign_id AND h.response_id=r.response_id AND h.judge_id=?
        LEFT JOIN campaign_judgments n
        ON n.campaign_id=r.campaign_id AND n.response_id=r.response_id AND n.judge_id LIKE 'local-cascade-%'
        WHERE a.campaign_id IN ({placeholders}) AND a.evidence_class='measured'
        AND a.input_id IN (SELECT b.input_id FROM campaign_assignments b WHERE b.campaign_id=?
                          AND b.evidence_class='measured')
        ORDER BY a.campaign_id,a.assignment_id,n.judge_id"""
    try:
        indexed = [dict(row) for row in connection.execute(query, (judge, *campaigns, matched_campaign))]
    finally:
        connection.close()
    dispositions = Counter()
    selected = {}
    for row in indexed:
        reason = ("excluded_model" if any(row["model"].startswith(p) for p in exclude_models) else
                  "not_static_text" if row["modality"] != "text" or row["framework"] != "replay" else
                  "no_usable_output" if row["outcome"] != "usable" else
                  "no_valid_teacher" if row["teacher_status"] != "valid" or row["teacher_label"] not in VALID_LABELS else
                  "no_source_metadata" if row["input_id"] not in metadata else None)
        if reason:
            dispositions[reason] += 1
            continue
        key = row["response_id"]
        if key not in selected:
            selected[key] = dict(row, native=[])
        previous = selected[key]
        if any(previous[k] != row[k] for k in ("model", "input_id", "condition_id", "teacher_label")):
            raise ValueError("A response identity has conflicting selected metadata or teacher labels")
        if row["local_status"] == "valid" and row["local_label"] in VALID_LABELS:
            native = (row["local_condition"], row["local_label"], row["local_source"])
            if native not in previous["native"]:
                previous["native"].append(native)
    files = defaultdict(dict)
    for key, row in selected.items():
        details = json.loads(row["details"])
        path, separator, line = details["source_ref"].rpartition(":")
        if not separator or not line.isdigit() or int(line) < 1:
            raise ValueError("Invalid selected response source location")
        files[Path(path)][int(line)] = None
    for path, wanted in files.items():
        if not path.is_absolute():
            raise ValueError("Response export needs resolved absolute source locations")
        last_line = max(wanted)
        with path.open(encoding="utf-8") as stream:
            for number, text in enumerate(stream, 1):
                if number in wanted:
                    wanted[number] = json.loads(text)
                if number >= last_line:
                    break
        if any(row is None for row in wanted.values()):
            raise ValueError("A selected retained response line is missing")
    rows = []
    for key, row in selected.items():
        details = json.loads(row["details"])
        path, _, line = details["source_ref"].rpartition(":")
        raw = files[Path(path)][int(line)]
        if key != str(raw["run_id"]) + ":" + str(raw["attempt_id"]):
            raise ValueError("Selected index does not identify the retained response line")
        text = visible_turns(raw["output_turns"], assistant_only=True)
        if not text.strip():
            dispositions["indexed_usable_but_empty_visible_text"] += 1
            continue
        m = metadata[row["input_id"]]
        if any(m[k] != row[k] for k in ("modality", "framework", "corpus")):
            raise ValueError("Selected input metadata differs from the campaign assignment")
        native = row["native"][0] if len(row["native"]) == 1 else (None, None, None)
        if len(row["native"]) > 1:
            dispositions["ambiguous_local_judge_excluded_from_disagreement"] += 1
        rows.append(dict(id=key, campaign_id=row["campaign_id"], input_id=row["input_id"],
            source=m["source"], source_cluster_id=m["source_cluster_id"], source_policy=m["source_policy"],
            group=m["group"], corpus=m["corpus"], framework=m["framework"], modality=m["modality"],
            expected_behavior=m["expected_behavior"], risk=m["risk"], model=row["model"],
            generation_condition=row["condition_id"], judge_condition=judge,
            prompt=m["prompt"], response=text, label=row["teacher_label"],
            local_condition=native[0], local_label=native[1], truncated=bool(row["truncated"]),
            source_ref=details["source_ref"], teacher_source=row["teacher_source"], local_source=native[2],
            output_allowance=details.get("output_allowance"), context_tokens=details.get("context_tokens")))
    rows.sort(key=lambda row: row["id"])
    return rows, dict(status="exported_labelled_static_text", campaigns=campaigns,
        matched_campaign=matched_campaign, teacher=judge, indexed_join_rows=len(indexed),
        response_rows=len(rows), dispositions=dict(dispositions), artifact_files_read=len(files),
        target_calls=0, judge_calls=0, human_validated=False,
        exclusions_unit="indexed join rows; multiple local conditions can duplicate exclusion rows",
        grouping_scope="All static text source candidates, including candidates without valid labels")
