"""English UI catalog, shared by HTML renderers and embedded client scripts.

Only application-authored copy belongs here. Research text, command identifiers,
stored enum values and provider errors are not translated. Catalogs are loaded
once, not fetched or reparsed on each navigation.
"""

from __future__ import annotations

import html
import json
import re
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType

_MARKER = re.compile(r"\[\[(text|attr|js|jshtml):([a-z0-9_.-]+)\]\]")


@lru_cache(maxsize=1)
def catalog():
    path = Path(__file__).with_name("locales") / "en.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data.items()
    ):
        raise ValueError("The English UI catalog must map message IDs to strings")
    return MappingProxyType(data)


def text(key: str, **values) -> str:
    """Get authored copy; the caller retains control of HTML escaping."""
    message = catalog()[key]
    return message.format_map(values) if values else message


@lru_cache(maxsize=2048)
def template(source: str) -> str:
    """Expand text slots in a *static* HTML/JS template, before adding user data.

    HTML and JavaScript remain in source, not in the language catalog. A JS slot
    includes its string quotes. Escaping '<' prevents script-tag termination.
    Never pass interpolated model answers or other user content to this helper.
    """

    def replace(match):
        kind, key = match.groups()
        value = text(key)
        if kind in {"js", "jshtml"}:
            if kind == "jshtml":
                value = html.escape(value, quote=True)
            return (
                json.dumps(value, ensure_ascii=False)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029")
            )
        return html.escape(value, quote=kind == "attr")

    return _MARKER.sub(replace, source)
