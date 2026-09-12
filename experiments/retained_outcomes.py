"""Interpret explicit provider evidence without rewriting retained responses."""
from __future__ import annotations

LEGACY_POLICY_BASES = frozenset({"openai_http400_cyber_policy", "openai_http400_bio_policy"})


def legacy_provider_policy_basis(response: dict) -> str | None:
    """Recognize old transport wrappers carrying an explicit native policy code.

    A generic HTTP 400, an empty answer or a filter that discarded partial text
    is not sufficient evidence of refusal. This is outcome accounting, not a
    new security judgment, a billing adjustment or authorization for another call.
    """
    raw = response.get("raw") or {}
    audit = raw.get("call_audit") or {}
    code = audit.get("provider_error_code")
    visible = any(isinstance(t.get("content"), str) and t["content"].strip()
                  for t in response.get("output_turns", []))
    if (not response.get("target", "").startswith("openai:") or visible
            or raw.get("model_stability_status") != "failed_output"
            or raw.get("model_stability_category") != "transport_failure"
            or audit.get("provider") != "openai" or audit.get("operation") != "generate"
            or audit.get("status_code") != 400 or code not in {"cyber_policy", "bio_policy"}):
        return None
    return "openai_http400_" + code
