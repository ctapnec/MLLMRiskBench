"""Composite aggregate bucket-label codec shared by the Runner and consumers.

The Runner keys its metric buckets by a human-readable label that joins
``key=value`` pairs with ``|``.  The same label is persisted as
``provenance.bucket`` on every EvalResult and is inverted back into the
``group_by`` mapping those results carry, so a group value that itself contains
a separator (AIR-Bench ``risk_subtype`` is ``"<cate-idx> | <l4-name>"``) must
survive the round trip.  This module is the single encoder/decoder for that
label: a backslash, ``|`` and ``=`` inside a key or value are escaped with
a backslash and the decoder honours the escapes.

Backward compatibility: a key or value that contains none of the three special
characters encodes byte-for-byte as the historical unescaped form, so existing
labels, persisted buckets and the result identities derived from them are
unchanged.  Legacy labels that were produced before escaping existed decode
exactly as the old ``split('|')`` / ``partition('=')`` logic decoded them.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

GROUP_LABEL_ALL = "all"

_PAIR_SEPARATOR = "|"
_KEY_VALUE_SEPARATOR = "="
_ESCAPE = "\\"
_SPECIAL = (_ESCAPE, _PAIR_SEPARATOR, _KEY_VALUE_SEPARATOR)


def encode_group_component(text: str) -> str:
    """Escape one key or value so separators inside it survive the label."""
    text = str(text)
    if not any(ch in text for ch in _SPECIAL):
        return text
    return (
        text.replace(_ESCAPE, _ESCAPE + _ESCAPE)
        .replace(_PAIR_SEPARATOR, _ESCAPE + _PAIR_SEPARATOR)
        .replace(_KEY_VALUE_SEPARATOR, _ESCAPE + _KEY_VALUE_SEPARATOR)
    )


def encode_group_label(pairs: Iterable[tuple[str, str]] | Mapping[str, str]) -> str:
    """Join ordered ``(key, value)`` pairs into the composite bucket label.

    An empty grouping encodes as :data:`GROUP_LABEL_ALL`.
    """
    items = pairs.items() if isinstance(pairs, Mapping) else pairs
    return _PAIR_SEPARATOR.join(
        encode_group_component(key)
        + _KEY_VALUE_SEPARATOR
        + encode_group_component(value)
        for key, value in items
    ) or GROUP_LABEL_ALL


def decode_group_label(label: str) -> dict[str, str]:
    """Invert :func:`encode_group_label` (escape-aware).

    Only an unescaped ``|`` separates pairs and only the first unescaped ``=``
    inside a pair separates key from value; escaped characters are restored.
    A label ending in a dangling escape is malformed and raises ``ValueError``.
    """
    if label == GROUP_LABEL_ALL:
        return {}
    out: dict[str, str] = {}
    key_chars: list[str] = []
    value_chars: list[str] | None = None
    escaped = False
    for ch in label:
        target = key_chars if value_chars is None else value_chars
        if escaped:
            target.append(ch)
            escaped = False
        elif ch == _ESCAPE:
            escaped = True
        elif ch == _PAIR_SEPARATOR:
            out["".join(key_chars)] = "".join(value_chars or [])
            key_chars, value_chars = [], None
        elif ch == _KEY_VALUE_SEPARATOR and value_chars is None:
            value_chars = []
        else:
            target.append(ch)
    if escaped:
        raise ValueError(f"group label ends with a dangling escape: {label!r}")
    out["".join(key_chars)] = "".join(value_chars or [])
    return out


__all__ = [
    "GROUP_LABEL_ALL",
    "decode_group_label",
    "encode_group_component",
    "encode_group_label",
]
