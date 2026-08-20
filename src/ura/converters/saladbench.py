"""SALAD-Bench converter: a second-level safety aggregator (thesis II.4).

SALAD-Bench (Li et al., *SALAD-Bench: A Hierarchical and Comprehensive Safety
Benchmark for Large Language Models*, Findings of ACL 2024; ``saladbench-2024``)
is itself an aggregator: its ~21k harmful base questions are drawn from many
upstream sources (recorded per row in ``source``) and organised into a three-level
hierarchy of 6 domains, 16 tasks and 66 leaf categories. Converting it makes
URA-Bench a *second-level* aggregator - it ingests SALAD's normalised corpus and
its exact source taxonomy while deliberately dropping SALAD's own pooled
leaderboard number, which is the cross-source pooling URA-Bench refuses.

Every base row is a harmful probe (``expected_behavior="refuse"``); the rows are
common-metric-eligible (common ASR/refusal via URA's own judge cascade, and the
approximate common-security proxy) and are *not* bound to SALAD's native
MD-Judge, which is recorded as the source-native evaluator but not executed here.

Released layout (Hugging Face ``OpenSafetyLab/Salad-Data``, JSON or JSONL):

* ``base_set`` rows have ``qid``, ``question``, ``source`` and the taxonomy fields
  ``1-category``/``2-category``/``3-category``. Each ``qid`` is one source cluster.
* ``attack_enhanced_set`` rows have ``qid``, ``aid``, ``baseq``, ``augq``,
  ``method`` and the same taxonomy fields; every jailbreak variant of one base
  question shares that base question's ``qid`` cluster, so repeated attack
  variants stay dependent under the whole-cluster bootstrap.

The unified ``RiskCategory`` is assigned from the exact ``3-category`` leaf label
(the only faithful granularity, because SALAD tasks mix constructs - e.g. its
``Security Threats`` task spans both weapon generation and malware). The full
SALAD path is preserved verbatim in ``risk_subtype``/``meta``. Unknown or blank
leaf labels fail closed rather than entering a fallback stratum. Point
``URA_SALADBENCH_PATH`` at the selected release file.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_json, read_jsonl

# Exact SALAD-Bench third-level (leaf) taxonomy -> unified RiskCategory. Keyed on
# the verbatim ``3-category`` string of the released data (66 leaves, O1..O67 with
# O61 absent). The mapping follows the project's fixed conventions: violence and
# hateful/harassing/sexual content targeting persons -> TOXICITY; CBRN, weapons,
# critical infrastructure, terrorism, self-harm and CSEM -> CATASTROPHIC; stereotyping
# -> BIAS; misinformation/disinformation -> HALLUCINATION; private data/secrets/
# surveillance -> PRIVACY; malware/network intrusion -> INFORMATION_SECURITY; non-violent crime, fraud,
# advice, IP/identity and financial/trade -> LEGALITY.
LEAF_CATEGORY_MAP: dict[str, Rc] = {
    # O1: Toxic Content
    "O1: Hate Speech": Rc.TOXICITY,
    "O2: Harass, Threaten, or Bully An Individual": Rc.TOXICITY,
    "O3: Enjoying someone else's Pain": Rc.TOXICITY,
    "O4: Terrorism": Rc.CATASTROPHIC,
    "O5: Violent Content": Rc.TOXICITY,
    "O6: Child Abuse": Rc.CATASTROPHIC,
    "O7: Insult": Rc.TOXICITY,
    # O2: Unfair Representation
    "O8: Racial and Ethnic Stereotyping": Rc.BIAS,
    "O9: Age Stereotyping": Rc.BIAS,
    "O10: Disability Stereotyping": Rc.BIAS,
    "O11: Gender Stereotyping": Rc.BIAS,
    "O12: Religious Stereotyping": Rc.BIAS,
    "O13: Location Stereotyping": Rc.BIAS,
    # O3: Adult Content
    "O14: Erotic Chat": Rc.TOXICITY,
    "O15: Sexual Activity": Rc.TOXICITY,
    "O16: Pornography": Rc.TOXICITY,
    # O4: Erosion of Trust in Public Information
    "O17: Law Advice": Rc.LEGALITY,
    "O18: Common Sense": Rc.HALLUCINATION,
    "O19: Illegal Drugs and Regulated/Controlled Substances": Rc.LEGALITY,
    "O20: Medical Advice": Rc.LEGALITY,
    # O5: Propagating Misconceptions/False Beliefs
    "O21: Historical Revisionism": Rc.HALLUCINATION,
    "O22: Science Denialism": Rc.HALLUCINATION,
    "O23: Radicalization": Rc.CATASTROPHIC,
    # O6: Risky Financial Practices
    "O24: Multi-level Marketing": Rc.LEGALITY,
    "O25: Paypal Lending": Rc.LEGALITY,
    "O26: Gambling": Rc.LEGALITY,
    # O7: Trade and Compliance
    "O27: Labor Issues": Rc.LEGALITY,
    "O28: Trade Affairs": Rc.LEGALITY,
    # O8: Dissemination of Dangerous Information
    "O29: Fake News": Rc.HALLUCINATION,
    "O30: Social Media Rumors": Rc.HALLUCINATION,
    "O31: Government Secrets": Rc.PRIVACY,
    "O32: Financial Data Leaks": Rc.PRIVACY,
    # O9: Privacy Infringement
    "O33: Inferring Personal Information": Rc.PRIVACY,
    "O34: Leaking Private Information": Rc.PRIVACY,
    # O10: Security Threats
    "O35: Weapon Generation and Transportation": Rc.CATASTROPHIC,
    "O36: Management or Operation of Critical Infrastructure": Rc.CATASTROPHIC,
    "O37: Malware Generation": Rc.INFORMATION_SECURITY,
    "O38: Cyber Attack": Rc.INFORMATION_SECURITY,
    "O39: Biological and Chemical Harms": Rc.CATASTROPHIC,
    # O11: Defamation
    "O40: Group Defamation": Rc.TOXICITY,
    "O41: Defamation Someone": Rc.TOXICITY,
    # O12: Fraud or Deceptive Action
    "O42: Scams": Rc.LEGALITY,
    "O43: Financial Fraud": Rc.LEGALITY,
    "O44: Academic Dishonesty": Rc.LEGALITY,
    "O45: Fake Review Generation": Rc.LEGALITY,
    "O46: Fake Online Content": Rc.LEGALITY,
    "O47: Disinformation": Rc.HALLUCINATION,
    "O48: Spam": Rc.LEGALITY,
    "O49: Pseudo-pharmaceuticals": Rc.LEGALITY,
    # O13: Influence Operations
    "O50: Manipulation of Public Opinion": Rc.HALLUCINATION,
    "O51: Campaign Materials": Rc.HALLUCINATION,
    "O52: Illegitimate Surveillance": Rc.PRIVACY,
    # O14: Illegal Activities
    "O53: Financial Crimes": Rc.LEGALITY,
    "O54: Drug-related Crimes": Rc.LEGALITY,
    "O55: Sexual Offenses": Rc.TOXICITY,
    "O56: Violent Crimes": Rc.TOXICITY,
    "O57: Theft": Rc.LEGALITY,
    "O58: Illegal Law Advice": Rc.LEGALITY,
    "O59: Environmental Crimes": Rc.LEGALITY,
    "O60: Traffic and Driving Offenses": Rc.LEGALITY,
    # O15: Persuasion and Manipulation
    "O62: Self-Harm": Rc.CATASTROPHIC,
    "O63: Psychological Manipulation": Rc.TOXICITY,
    # O16: Violation of Personal Property
    "O64: Mimicking Writing Style": Rc.LEGALITY,
    "O65: Plagiarism": Rc.LEGALITY,
    "O66: Copyright Infringement": Rc.LEGALITY,
    "O67: Forge Identity": Rc.LEGALITY,
}


class SaladBenchConverter(BaseConverter):
    name = "saladbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("questions", records))
        if not isinstance(records, list):
            raise CorpusFormatError(f"SALAD-Bench source is not a record list: {path}")
        if not records:
            raise CorpusFormatError(
                f"SALAD-Bench conversion produced no rows from {path}"
            )

        out: list[DataPoint] = []
        seen_ids: set[str] = set()
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"SALAD-Bench row {i} in {path} is not an object"
                )
            # attack-enhanced rows carry augq+baseq; base rows carry question.
            augmented = rec.get("augq")
            prompt = augmented if augmented is not None else rec.get("question")
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"SALAD-Bench row {i} in {path} lacks a non-empty question/augq"
                )
            leaf = rec.get("3-category")
            if not isinstance(leaf, str) or not leaf.strip():
                raise CorpusFormatError(
                    f"SALAD-Bench row {i} in {path} lacks a non-empty 3-category"
                )
            leaf = leaf.strip()
            if leaf not in LEAF_CATEGORY_MAP:
                raise CorpusFormatError(
                    f"SALAD-Bench row {i} in {path} has unknown leaf category "
                    f"{leaf!r}; extend LEAF_CATEGORY_MAP to admit it"
                )
            risk = LEAF_CATEGORY_MAP[leaf]

            qid = rec.get("qid")
            if qid is None or not str(qid).strip():
                raise CorpusFormatError(
                    f"SALAD-Bench row {i} in {path} lacks a qid"
                )
            qid = str(qid).strip()
            # Every attack variant of one base question shares that question's
            # qid cluster so repeated variants stay dependent in the bootstrap.
            cluster_id = f"saladbench:{qid}"
            aid = rec.get("aid")
            point_id = (
                f"saladbench:{qid}:{str(aid).strip()}"
                if augmented is not None and aid is not None
                else f"saladbench:{qid}"
            )
            if point_id in seen_ids:
                raise CorpusFormatError(
                    f"SALAD-Bench release contains duplicate id {point_id!r} at row {i}"
                )
            seen_ids.add(point_id)

            method = rec.get("method")
            out.append(dp(
                id=point_id,
                source="saladbench",
                modalities=["text"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=leaf,
                attack_family=(
                    str(method).strip() if isinstance(method, str) and method.strip()
                    else ("salad_attack_enhanced" if augmented is not None else None)
                ),
                meta={
                    "source_cluster_id": cluster_id,
                    "salad_qid": qid,
                    "salad_upstream_source": rec.get("source"),
                    "salad_domain": rec.get("1-category"),
                    "salad_task": rec.get("2-category"),
                    "salad_category": leaf,
                    "salad_layout": (
                        "attack_enhanced" if augmented is not None else "base"
                    ),
                    "official_evaluator_executed": False,
                    "evaluator_scope": "salad_md_judge_not_run_common_metrics_only",
                },
            ))
        return out
