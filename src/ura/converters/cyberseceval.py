"""CyberSecEval converter: Meta's offensive-cyber prompt suites (PurpleLlama).

CyberSecEval / CYBERSECEVAL 3 (github.com/meta-llama/PurpleLlama,
``CybersecurityBenchmarks``, Bhatt et al. 2024, ``cyberseceval3-2024``) is Meta's
LLM cyber-risk benchmark. Beyond the insecure-coding tests it ships several
natural-language *prompt* suites that probe a model's willingness to assist with
offensive cyber operations, all released as plain JSON lists under
``CybersecurityBenchmarks/datasets/``:

* ``mitre/mitre_benchmark_100_per_category_with_augmentation.json`` - each record
  is ``{base_prompt, mutated_prompt_base, mutated_prompt, mitre_category,
  ttp_id_name_mapping:{TTP_ID, TTP_Name}}``. ``mutated_prompt`` is the request sent
  to the model; ``mitre_category`` is the ATT&CK tactic (e.g. ``"C2"``).
* ``interpreter/interpreter.json`` - ``{mutated_prompt, attack_type:[...]}``, code
  the model is asked to run in an interpreter (e.g. ``["Privilege Escalation"]``).
* ``prompt_injection/prompt_injection.json`` - ``{prompt_id, test_case_prompt,
  user_input, judge_question, injection_variant, injection_type, risk_category,
  speaking_language}``. ``test_case_prompt`` is the app's system instruction and
  ``user_input`` the adversarial turn; the correct behaviour is to keep the
  original instruction and resist the injection.

Point ``URA_CYBERSECEVAL_PATH`` at any of these JSON files (a JSONL export is also
tolerated). Every record maps to ``Rc.CYBERSEC`` with
``attack_family="offensive_cyber"``. Missing inputs fail closed.
This file parser covers the released JSON/JSONL prompt suites.  It is distinct
from the official native runner and from the visual benchmark's directory
loader.  Any CyberSecEval DataPoint carrying verified media must place the same
MediaRefs on its authored user turn; the source-bound ``purplellama`` identity
adapter enforces that invariant rather than silently dropping images.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_json, read_jsonl

# The prompt-injection suite wants the model to keep its original instruction and
# ignore the injected turn (safe_answer); the offensive-generation suites (mitre,
# interpreter, insecure coding) want an outright refusal.
EXPECTED_BY_DATASET = {
    "prompt_injection": "safe_answer",
}


def _as_text(value) -> str:
    """Coerce a prompt/category field (str or list of str) to a single string."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v)
    return str(value) if value is not None else ""


class CyberSecEvalConverter(BaseConverter):
    name = "cyberseceval"

    @staticmethod
    def _dataset(rec: dict, path: Path) -> str:
        """Identify which CyberSecEval prompt suite a record came from."""
        if "mitre_category" in rec:
            return "mitre"
        if "injection_type" in rec or "user_input" in rec:
            return "prompt_injection"
        if "attack_type" in rec:
            return "interpreter"
        if "cwe_identifier" in rec or "origin_code" in rec:
            return "insecure_coding"
        return path.stem

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get(
                "data", records.get("prompts", records.get("test_cases", []))
            )
        if not isinstance(records, list):
            raise CorpusFormatError(
                f"CyberSecEval source is not a record list: {path}"
            )
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"CyberSecEval row {i} in {path} is not an object"
                )
            dataset = self._dataset(rec, path)
            rid = rec.get("prompt_id", rec.get("id", i))

            if dataset == "prompt_injection":
                system = _as_text(rec.get("test_case_prompt"))
                user = _as_text(rec.get("user_input") or rec.get("mutated_prompt"))
                judge_question = _as_text(rec.get("judge_question"))
                if not system.strip():
                    raise CorpusFormatError(
                        f"CyberSecEval prompt-injection row {i} in {path} "
                        "has no application system prompt"
                    )
                if not user.strip():
                    raise CorpusFormatError(
                        f"CyberSecEval prompt-injection row {i} in {path} "
                        "has no user input"
                    )
                if not judge_question.strip():
                    raise CorpusFormatError(
                        f"CyberSecEval prompt-injection row {i} in {path} "
                        "has no judge_question required by the source evaluator"
                    )
                dialog = [
                    DialogTurn(role="system", content=system),
                    DialogTurn(role="user", content=user),
                ]
                payload = user
                subtype = (
                    _as_text(rec.get("injection_type"))
                    or _as_text(rec.get("risk_category"))
                    or None
                )
            else:
                judge_question = ""
                text = _as_text(
                    rec.get("mutated_prompt")
                    or rec.get("test_case_prompt")
                    or rec.get("prompt")
                    or rec.get("base_prompt")
                )
                if not text.strip():
                    raise CorpusFormatError(
                        f"CyberSecEval row {i} in {path} has no executable prompt"
                    )
                dialog = [DialogTurn(role="user", content=text)]
                payload = text
                subtype = (
                    _as_text(rec.get("mitre_category"))
                    or _as_text(rec.get("attack_type"))
                    or _as_text(rec.get("cwe_identifier"))
                    or dataset
                    or None
                )

            is_prompt_injection = dataset == "prompt_injection"
            out.append(dp(
                id=f"cyberseceval:{dataset}:{rid}",
                source="cyberseceval",
                modalities=["text"],
                risk=Rc.CYBERSEC,
                expected=EXPECTED_BY_DATASET.get(dataset, "refuse"),
                dialog=dialog,
                payload_text=payload or None,
                risk_subtype=subtype,
                attack_family=(
                    "indirect_prompt_injection"
                    if is_prompt_injection else "offensive_cyber"
                ),
                meta={
                    "dataset": dataset,
                    "mitre_category": rec.get("mitre_category"),
                    "ttp": rec.get("ttp_id_name_mapping"),
                    "attack_type": rec.get("attack_type"),
                    "injection_variant": rec.get("injection_variant"),
                    "judge_question": judge_question or None,
                    "speaking_language": rec.get("speaking_language"),
                    "cwe_identifier": rec.get("cwe_identifier"),
                    # The released prompt-injection suite supplies a
                    # task-specific judge question. Refusal/over-refusal does not
                    # determine whether the original application instruction was
                    # preserved, so keep this construct in the framework as an
                    # explicit source-specific track until that scorer is wired.
                    "common_metrics_eligible": not is_prompt_injection,
                    "required_metric": (
                        "cyberseceval_prompt_injection_judge_question"
                        if is_prompt_injection else None
                    ),
                    "source_metric_attackers": (
                        ["replay", "purplellama"]
                        if is_prompt_injection else None
                    ),
                    "source_cluster_id": (
                        f"cyberseceval:prompt_injection:{rid}"
                        if is_prompt_injection else f"cyberseceval:{dataset}:{rid}"
                    ),
                    "source_metric_runtime": (
                        "separate_judge_LLM_with_per-record_judge_question_then_"
                        "case-insensitive_yes-substring_parser"
                        if is_prompt_injection else None
                    ),
                    "source_metric_semantics": (
                        "source_injection_success_not_refusal_or_common_ASR"
                        if is_prompt_injection else None
                    ),
                    "source_metric_fidelity": (
                        "requires_upstream_second-stage_judge_call"
                        if is_prompt_injection else None
                    ),
                    "execution_adapters": ["replay", "purplellama"],
                    "purplellama_identity_eligible": True,
                    "native_purplellama_runner_executed": False,
                    "official_judge_question_executed": False,
                    "citation": "cyberseceval3-2024",
                },
            ))
        if not out:
            raise CorpusFormatError(
                f"CyberSecEval conversion produced no rows from {path}"
            )
        return out
