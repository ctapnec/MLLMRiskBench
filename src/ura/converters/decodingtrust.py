"""DecodingTrust converter: the stereotype-bias perspective only (thesis II.4).

DecodingTrust (Wang et al., NeurIPS 2023 D&B Outstanding Paper; HF
``AI-Secure/DecodingTrust``) is a trustworthiness aggregator with eight
perspectives on heterogeneous metric scales. Only its **stereotype** perspective
converts cleanly into URA's response-judgment model: each row is a stereotype
statement the model is asked to agree or disagree with, and endorsement ("I
agree") is the harmful outcome. This converter deliberately accepts *only* the
stereotype config and fails closed on every other perspective - the toxicity
perspective embeds RealToxicityPrompts and the privacy perspective ships real
Enron names/emails, neither of which URA redistributes.

Released layout (stereotype config, JSON/JSONL export): each record is
``{"prompt": {"text", "stereotype_topic_tag", "demographic_group_tag",
"sys_prompt_type_tag"}}`` (the nested fields may also appear flattened). All rows
map to ``RiskCategory.BIAS`` with ``expected_behavior="refuse"`` - a safe model
does not endorse the stereotype, so an authoritative violation is an endorsement
(URA's common judge approximates DecodingTrust's own agreement index, which is
recorded as source-native and not run here). The three system-prompt variants of
one (group, topic) share a source cluster. Point ``URA_DECODINGTRUST_STEREOTYPE_PATH``
at the stereotype export.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_json, read_jsonl


def _stereotype_fields(rec: dict) -> tuple[str, str, str, str]:
    """Extract (text, topic, group, sys_prompt) from a nested or flat record.

    Raises if the record is not a stereotype-perspective row - this is the
    fail-closed guard that rejects the toxicity/privacy/other configs.
    """
    prompt = rec.get("prompt")
    inner = prompt if isinstance(prompt, dict) else rec
    text = inner.get("text") if isinstance(inner, dict) else (prompt if isinstance(prompt, str) else None)
    if not isinstance(text, str) or not text.strip():
        raise CorpusFormatError("DecodingTrust row lacks a non-empty prompt text")
    topic = inner.get("stereotype_topic_tag") if isinstance(inner, dict) else None
    group = inner.get("demographic_group_tag") if isinstance(inner, dict) else None
    sysp = inner.get("sys_prompt_type_tag") if isinstance(inner, dict) else None
    if not (isinstance(topic, str) and topic.strip()) or not (isinstance(group, str) and group.strip()):
        raise CorpusFormatError(
            "DecodingTrust row is not a stereotype-perspective record "
            "(missing stereotype_topic_tag/demographic_group_tag); this converter "
            "accepts only the stereotype config"
        )
    return text.strip(), topic.strip(), group.strip(), (sysp or "").strip()


class DecodingTrustConverter(BaseConverter):
    name = "decodingtrust"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", records))
        if not isinstance(records, list) or not records:
            raise CorpusFormatError(
                f"DecodingTrust source is not a non-empty record list: {path}"
            )

        out: list[DataPoint] = []
        cell_counter: dict[str, int] = {}
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"DecodingTrust row {i} in {path} is not an object")
            text, topic, group, sysp = _stereotype_fields(rec)
            cluster = f"decodingtrust:stereotype:{group}:{topic}"
            cell = f"{cluster}:{sysp}"
            n = cell_counter.get(cell, 0)
            cell_counter[cell] = n + 1
            point_id = f"{cell}#{n}"

            out.append(dp(
                id=point_id,
                source="decodingtrust",
                modalities=["text"],
                risk=Rc.BIAS,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=text)],
                payload_text=text,
                risk_subtype=f"{group}:{topic}:{sysp}" if sysp else f"{group}:{topic}",
                attack_family="stereotype_endorsement",
                meta={
                    "source_cluster_id": cluster,
                    "dt_demographic_group": group,
                    "dt_stereotype_topic": topic,
                    "dt_sys_prompt_type": sysp or None,
                    "official_evaluator_executed": False,
                    "evaluator_scope": "decodingtrust_agreement_index_not_run_common_metrics_only",
                },
            ))
        return out
