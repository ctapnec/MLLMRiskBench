"""Budgets, pricing, secrets, and allowlisted configuration editing."""

from __future__ import annotations

import contextlib
import html
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .catalog import _PROVIDER_BUDGETS, _EDITABLE_CONFIGS, _icon

from .ui import _page


from .reports import reconcile_pricing_ownership


class SettingsMixin:
    def _budgets(self) -> list[tuple[str, str, str, str]]:
        """(name, prepaid, match-prefix, funds) rows from the editable
        budgets config, falling back to the recorded ledger defaults."""

        document = self._load_registry("budgets.json", "rig/budgets.example.json")
        providers = document.get("providers")
        rows: list[tuple[str, str, str, str]] = []
        if isinstance(providers, list):
            for entry in providers:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip()
                if not name:
                    continue
                rows.append(
                    (
                        name,
                        str(entry.get("prepaid", "")).strip() or "-",
                        str(entry.get("match", name.split()[0].lower())).lower(),
                        str(entry.get("funds", "")).strip(),
                    )
                )
        if rows:
            return rows
        return [
            (name, amount, name.split()[0].lower(), role)
            for name, amount, role in _PROVIDER_BUDGETS
        ]

    def _budget_card(self) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td><strong>{html.escape(amount)}</strong></td>"
            f"<td>{html.escape(role)}</td></tr>"
            for name, amount, _match, role in self._budgets()
        )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Provider budgets</h2>"
            "<div class='scroll'><table><tr><th>Provider</th><th>Prepaid</th>"
            "<th>Funds</th></tr>" + rows + "</table></div>"
            "<p class='note'>Prepaid budgets from the editable "
            "<a href='/config?file=budgets'>budgets</a> config (defaults "
            "recorded in ledger 11.22). The Anthropic balance is the "
            "constraint because the Haiku judge is metered on every judged "
            "response, local lanes included. Canaries report only exact "
            "observed tokens and spend; campaign <code>--limit</code> and call "
            "caps come from prepaid funds plus the prospective call upper "
            "bound. This card spends nothing.</p></div>"
        )

    @staticmethod
    def _pricing_fetch_banner(fetched: str) -> str:
        """Render the outcome of a provider-pricing fetch (escaped)."""

        try:
            summary = json.loads(fetched)
        except ValueError:
            return ""
        if not isinstance(summary, dict) or not summary:
            return ""
        if summary.get("error"):
            return (
                "<div class='notice red'><strong>Pricing fetch failed."
                "</strong><p class='note'>" + html.escape(str(summary["error"])) + "</p></div>"
            )
        lines = []
        for provider, report in sorted((summary.get("providers") or {}).items()):
            report = report if isinstance(report, dict) else {}
            matched = report.get("matched") or []
            unmatched = report.get("unmatched") or []
            note = report.get("note") or ""
            if matched:
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: "
                    f"{len(matched)} rate(s) read from "
                    f"<code>{html.escape(str(report.get('url', '')))}</code></li>"
                )
            elif note:
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: {html.escape(str(note))}</li>"
                )
            elif unmatched:
                # Attempted (has url + extractor + models) but the page matched
                # no model rows: say so, so the operator is not left assuming the
                # provider's prices are current when they stay N/A.
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: fetched "
                    f"but matched 0 of {len(unmatched)} model(s) - the page "
                    "layout may have changed; enter these rates by hand</li>"
                )
        return (
            "<div class='notice blue'><strong>Fetched provider pricing ("
            + html.escape(str(summary.get("rates_written", 0)))
            + " rate(s) written).</strong><p class='note'>Auto-fetched rates "
            "are stamped with their source and date; verify each against the "
            "provider's page before relying on the calculated cost. A model you "
            "have priced by hand is left untouched, and editing a fetched rate "
            "in the config editor makes it yours too - once you change its "
            "value the fetcher stops overwriting it.</p>"
            "<ul>" + "".join(lines) + "</ul></div>"
        )

    def fetch_pricing(self) -> dict[str, Any]:
        """Fetch published provider prices into the pricing table.

        Delegates to the same experiments.pricing_fetch module the CLI uses;
        never fabricates a rate (unreadable ones stay manual), stamps each
        fetched rate with its source and date, and never supersedes a rate the
        operator has priced by hand (on any date - the operator's figure is
        billed until they edit it directly).
        """

        from experiments import pricing_fetch  # noqa: PLC0415 - optional, on demand

        today = time.strftime("%Y-%m-%d", time.gmtime())
        try:
            # Hold the pricing lock across the whole read-network-write span so a
            # concurrent pricing edit cannot be lost, and two fetches cannot
            # collide on the temp file.
            with self._pricing_lock:
                return pricing_fetch.fetch_pricing(self.repo_root, today=today)
        except Exception as exc:  # noqa: BLE001 - a fetch fault must not 500
            return {"error": str(exc)}

    # -- provider secrets (presence + write-only; values never rendered) ---

    #: The provider API-key environment variables the console may manage.
    #: (env var, provider label, funded).  Values are never displayed; only
    #: presence and a masked last-4 hint are ever surfaced.
    _SECRET_ENV_VARS: tuple[tuple[str, str, bool], ...] = (
        ("ANTHROPIC_API_KEY", "Anthropic (focal Fable + Haiku judge)", True),
        ("OPENAI_API_KEY", "OpenAI (focal Sol)", True),
        ("GEMINI_API_KEY", "Google Gemini", True),
        ("DEEPSEEK_API_KEY", "DeepSeek", True),
        ("MOONSHOT_API_KEY", "Moonshot (Kimi)", True),
        ("DASHSCOPE_API_KEY", "Alibaba DashScope (Qwen) - unfunded", False),
        ("ZHIPU_API_KEY", "Zhipu (GLM) - unfunded/unpayable", False),
    )
    _SECRET_NAMES = frozenset(name for name, _label, _funded in _SECRET_ENV_VARS)

    @staticmethod
    def _mask(value: str) -> str:
        """A last-4 hint for a present secret; never the value itself."""

        value = value.strip()
        if len(value) <= 4:
            return "set"
        return "set - ...." + value[-4:]

    def secret_status(self) -> list[dict[str, Any]]:
        """Presence (and a masked hint) for each managed provider key.

        Reads only os.environ presence; never the file, never the full value.
        """

        rows = []
        for name, label, funded in self._SECRET_ENV_VARS:
            value = os.environ.get(name, "")
            rows.append(
                {
                    "name": name,
                    "label": label,
                    "funded": funded,
                    "present": bool(value.strip()),
                    "hint": self._mask(value) if value.strip() else "not set",
                }
            )
        return rows

    def set_secret(self, name: str, value: str) -> None:
        """Write/replace an allowlisted provider key in the 600-mode env file.

        Fail-closed: only allowlisted names, only a non-empty single-line
        token.  The value is written to the operator secrets file (created
        0600) and mirrored into os.environ so newly launched jobs pick it up;
        it is never echoed to a page, written to the database, backed up to a
        browsable directory, or logged.
        """

        if name not in self._SECRET_NAMES:
            raise ValueError(f"unknown secret {name!r}")
        value = value.strip()
        if not value:
            raise ValueError("secret value must not be empty")
        # Must be a single line by str.splitlines()'s definition, which is what
        # the env file is later read back with.  That set is broader than just
        # \n/\r: it also includes the Unicode line/paragraph separators
        # (U+0085, U+2028, U+2029) a paste from a PDF or rich-text field can
        # carry.  Reject them here so a stored key can never be split apart on
        # the next read-modify-write and corrupt the sourced file.
        if value.splitlines() != [value]:
            raise ValueError("secret value must be a single line")
        if len(value) > 4096:
            raise ValueError("secret value is implausibly long")
        # The value is written inside single quotes into a file that is sourced
        # by the campaign shell.  A single quote would close the quoting and let
        # the remainder run as shell; control characters would corrupt the line.
        # Real provider keys never contain either, so reject them fail-closed
        # rather than attempting to escape them.
        if "'" in value:
            raise ValueError("secret value must not contain a single quote")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("secret value must not contain control characters")
        line = f"export {name}='{value}'"
        pattern = re.compile(rf"^\s*export\s+{re.escape(name)}=")
        # Serialize the read-modify-write so a concurrent set/clear cannot drop
        # a key, and surface any filesystem fault as a ValueError the secrets
        # page renders as "Not saved" (never an unhandled 500; the value never
        # appears in the message).
        with self._secret_lock:
            existing = self._read_env_lines()
            replaced = False
            out_lines = []
            for entry in existing:
                if pattern.match(entry):
                    if not replaced:
                        out_lines.append(line)
                        replaced = True
                    # drop any further duplicate definitions
                else:
                    out_lines.append(entry)
            if not replaced:
                out_lines.append(line)
            text = "\n".join(out_lines) + "\n"
            try:
                self._write_env_file(text)
            except OSError as exc:
                raise ValueError(f"could not write the secrets file: {exc}") from exc
            os.environ[name] = value  # live: new jobs inherit it immediately

    def _read_env_lines(self) -> list[str]:
        """Current lines of the secrets file, fail-closed on a non-absent fault.

        An absent file is empty (nothing stored yet).  A present-but-unreadable
        file (permission denial, transient lock) raises rather than silently
        returning [], because rewriting from [] would drop every other stored
        key.
        """

        try:
            return self.env_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ValueError(f"could not read the secrets file: {exc}") from exc

    def _write_env_file(self, text: str) -> None:
        """Write the operator secrets file atomically at mode 0600.

        A 0600 temp file (so the key never briefly lands world-readable) is
        written and os.replace()d into place, so a mid-write fault leaves the
        prior file intact rather than a truncated/empty one - the same
        atomic-write discipline the pricing table uses, but with NO backup copy
        (a browsable .bak of a secret would defeat the point).
        """

        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.env_file.with_name(self.env_file.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            # newline="\n": the file is sourced by a POSIX shell, so it must use
            # LF endings on every platform.  Without this, a text-mode write on
            # Windows would emit CRLF and the trailing \r would become part of
            # each key value when the campaign shell sources it (a silent 401).
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            os.replace(tmp, self.env_file)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(self.env_file, 0o600)
        except OSError:
            pass

    def clear_secret(self, name: str) -> None:
        """Remove an allowlisted provider key from the env file and process."""

        if name not in self._SECRET_NAMES:
            raise ValueError(f"unknown secret {name!r}")
        pattern = re.compile(rf"^\s*export\s+{re.escape(name)}=")
        with self._secret_lock:
            # Fail-closed: if the file is present but unreadable, _read_env_lines
            # raises rather than reporting a false success while the key survives
            # on disk (it would return to life on the next source of the file).
            existing = self._read_env_lines()
            out_lines = [entry for entry in existing if not pattern.match(entry)]
            if existing:
                try:
                    self._write_env_file("\n".join(out_lines) + "\n")
                except OSError as exc:
                    raise ValueError(f"could not write the secrets file: {exc}") from exc
            os.environ.pop(name, None)

    def _secrets_page(self, *, error: str = "", saved: str = "") -> bytes:
        rows = []
        for row in self.secret_status():
            tone = "green" if row["present"] else ("gray" if not row["funded"] else "amber")
            state = html.escape(row["hint"])
            clear = (
                "<form class='inline' method='post' action='/config/secrets'>"
                f"<input type='hidden' name='name' value='{html.escape(row['name'])}'>"
                "<input type='hidden' name='action' value='clear'>"
                "<button type='submit' class='danger small'>Clear</button></form>"
                if row["present"]
                else ""
            )
            rows.append(
                "<tr><td><code>" + html.escape(row["name"]) + "</code></td>"
                f"<td>{html.escape(row['label'])}</td>"
                f"<td><span class='badge {tone}'>{state}</span></td>"
                "<td><input class='wide' type='password' autocomplete='off' "
                f"form='setkey-{html.escape(row['name'])}' name='value' "
                "placeholder='paste key to set/rotate'></td>"
                "<td>"
                f"<form id='setkey-{html.escape(row['name'])}' method='post' "
                "action='/config/secrets'>"
                f"<input type='hidden' name='name' value='{html.escape(row['name'])}'>"
                "<input type='hidden' name='action' value='set'>"
                "<button type='submit' class='small'>Save</button></form> " + clear + "</td></tr>"
            )
        banner = ""
        if saved:
            banner = (
                "<div class='notice blue'><strong>Key "
                + html.escape(saved)
                + " updated.</strong><p class='note'>Written to the "
                "operator secrets file and applied to this console's "
                "environment; new jobs use it immediately. The value is "
                "never displayed.</p></div>"
            )
        if error:
            banner = (
                "<div class='notice red'><strong>Not saved: "
                + html.escape(error)
                + "</strong></div>"
            )
        body = (
            "<h1>" + _icon("sliders", size=22) + "Provider API keys</h1>"
            "<p class='crumbs'><a href='/config'>Configuration</a>"
            "<span class='sep'>/</span>secrets</p>"
            + banner
            + "<p class='note'>Set or rotate the hosted-provider API keys the "
            "campaign uses. Keys are written to the operator secrets file "
            "(<code>~/.ura_env</code>, mode 600) and applied to this console's "
            "environment. For your safety the console <strong>never displays a "
            "stored key</strong> - only whether it is set and its last four "
            "characters - and never writes a key to the database, a backup, or "
            "a log. Secrets are still yours to manage; nothing here is shared "
            "off this host.</p>"
            "<div class='card scroll'><table><tr><th>Env var</th>"
            "<th>Provider</th><th>Status</th><th>Set / rotate</th><th></th></tr>"
            + "".join(rows)
            + "</table></div>"
            "<p class='note'>Unfunded providers (DashScope/Qwen, Zhipu/GLM) are "
            "listed for completeness; their lanes record as structural N/A "
            "unless a key is provided. A key set here takes effect for jobs "
            "launched afterwards.</p>"
        )
        return _page("Provider API keys", body, active="Config")

    # -- config editor -----------------------------------------------------

    def _config_target(self, key: str) -> tuple[Path, str]:
        """Resolve an allowlisted config key to its file path and description.

        Only keys in ``_EDITABLE_CONFIGS`` resolve; anything else is rejected,
        so no path outside the allowlist is ever readable or writable here.
        """

        entry = _EDITABLE_CONFIGS.get(key)
        if entry is None:
            raise ValueError(f"unknown config {key!r}")
        relative, _example, description = entry
        return (self.repo_root / relative), description

    def _config_example_text(self, key: str) -> str:
        """The checked-in example content for an allowlisted config, if any."""

        entry = _EDITABLE_CONFIGS.get(key)
        if entry is None:
            return ""
        example = self.repo_root / entry[1]
        try:
            return example.read_text(encoding="utf-8")
        except OSError:
            return ""

    def save_config(self, key: str, content: str) -> Path:
        """Validate JSON and write an allowlisted config, backing up first.

        Fail-closed: rejects unknown keys and any content that is not a JSON
        object, and preserves the prior bytes under the state dir before
        overwriting so a bad edit is always recoverable.
        """

        path, _description = self._config_target(key)
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise ValueError(f"content is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("config must be a JSON object")
        # The pricing table has a second writer (the fetcher); serialize this
        # write with it so an overlapping fetch cannot lose the operator's edit.
        lock = self._pricing_lock if key == "pricing" else contextlib.nullcontext()
        with lock:
            if key == "pricing":
                # If the operator corrected a fetched rate in place, drop its
                # auto-fetch provenance so the fetcher treats it as operator-
                # owned and never reverts it.  Compare under the lock against the
                # current on-disk table.
                try:
                    on_disk = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    on_disk = {}
                if isinstance(on_disk, dict):
                    reconcile_pricing_ownership(parsed, on_disk)
            normalized = (
                json.dumps(
                    parsed,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise ValueError("config target is not a regular file")
                backups = self.state_dir / "config-backups"
                backups.mkdir(parents=True, exist_ok=True)
                stamp = time.strftime("%Y%m%d-%H%M%S")
                (backups / f"{path.name}.{stamp}.bak").write_bytes(path.read_bytes())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(normalized, encoding="utf-8")
        return path

    def _config_page(
        self,
        key: str,
        saved: str,
        *,
        error: str = "",
        draft: str = "",
        fetched: str = "",
    ) -> bytes:
        # Index of editable files.
        if key not in _EDITABLE_CONFIGS:
            cards = []
            for token, (relative, _example, description) in _EDITABLE_CONFIGS.items():
                path = self.repo_root / relative
                state = "exists" if path.is_file() else "not created yet"
                cards.append(
                    "<div class='card'><h2>" + _icon("sliders") + f"{html.escape(token)}</h2>"
                    f"<p class='note'><code>{html.escape(relative)}</code> - "
                    f"{html.escape(state)}</p>"
                    f"<p>{html.escape(description)}</p>"
                    f"<p><a href='/config?file={quote(token)}'>"
                    "<button type='button'>Open editor</button></a></p></div>"
                )
            # Provider API keys: presence + set/rotate, values never shown.
            statuses = self.secret_status()
            set_count = sum(1 for s in statuses if s["present"])
            cards.append(
                "<div class='card'><h2>" + _icon("logo") + "Provider API keys"
                "</h2><p class='note'>Set or rotate the hosted-provider keys "
                f"(<code>~/.ura_env</code>, mode 600). {set_count} of "
                f"{len(statuses)} set. The console never displays a stored "
                "key.</p><p><a href='/config/secrets'>"
                "<button type='button'>Manage keys</button></a></p></div>"
            )
            body = (
                "<h1>" + _icon("sliders", size=22) + "Configuration</h1>"
                "<p class='note'>Edit the operator-local registries in place. "
                "Saves are JSON-validated and the prior version is backed up "
                "under the console state directory. These files are read fresh "
                "by each run, so an edit takes effect on the next job. Secret "
                "API keys are managed separately (presence only, never "
                "displayed); nothing here shows a stored key.</p>" + "".join(cards)
            )
            return _page("Configuration", body, active="Config")
        # Single-file editor.
        path, description = self._config_target(key)
        relative = _EDITABLE_CONFIGS[key][0]
        example_text = self._config_example_text(key)
        seeded = ""
        if draft:
            content = draft
        else:
            try:
                content = path.read_text(encoding="utf-8")
                if not content.strip():
                    raise OSError  # treat an empty file as unseeded
            except OSError:
                # Seed a fresh editor from the checked-in example so the roster
                # is never a blank page.
                content = example_text
                if example_text:
                    seeded = (
                        "<div class='notice blue'><strong>Prefilled from "
                        "the checked-in example.</strong><p class='note'>"
                        "Review and edit, then save to write the local "
                        "registry.</p></div>"
                    )
        banner = seeded
        if saved:
            banner = (
                "<div class='notice blue'><strong>Saved.</strong>"
                "<p class='note'>Prior version backed up under the "
                "console state directory.</p></div>"
            )
        if error:
            banner = (
                f"<div class='notice red'><strong>Not saved: {html.escape(error)}</strong></div>"
            )
        if fetched:
            banner = self._pricing_fetch_banner(fetched) + banner
        # The pricing editor gets a fetch-from-provider-pages action.
        fetch_action = ""
        if key == "pricing":
            fetch_action = (
                "<form class='inline' method='post' action='/pricing/fetch' "
                "data-busy='Fetching provider pricing pages...'>"
                "<button type='submit' class='ghost'>"
                + _icon("coins", size=15)
                + "Fetch from provider pricing pages</button></form> "
            )
        body = (
            "<h1>" + _icon("sliders", size=22) + f"Edit {html.escape(key)}</h1>"
            f"<p class='crumbs'><a href='/config'>Configuration</a>"
            f"<span class='sep'>/</span>{html.escape(relative)}</p>"
            + banner
            + f"<p class='note'>{html.escape(description)}</p>"
            + fetch_action
            + "<form method='post' action='/config'>"
            f"<input type='hidden' name='file' value='{html.escape(key)}'>"
            f"<textarea class='editor' id='cfg-editor' name='content' "
            f"spellcheck='false'>{html.escape(content)}</textarea>"
            + (
                "<textarea id='cfg-example' style='display:none'>"
                f"{html.escape(example_text)}</textarea>"
                if example_text
                else ""
            )
            + "<div class='editor-actions'>"
            "<button type='submit'>"
            + _icon("save", size=15)
            + "Validate &amp; save</button>"
            + (
                "<button type='button' class='ghost' id='cfg-prefill'>"
                + _icon("box", size=15)
                + "Prefill from example</button>"
                if example_text
                else ""
            )
            + f"<a href='/config?file={quote(key)}'>"
            "<button type='button' class='ghost'>Reload</button></a>"
            "</div></form>"
            "<p class='note'>Save is rejected unless the content parses as a "
            "JSON object; on success it is normalized (sorted keys, 2-space "
            "indent) and the prior bytes are backed up. 'Prefill from example' "
            "loads the checked-in roster into the editor without saving.</p>"
            "<script>(function(){"
            "var btn=document.getElementById('cfg-prefill');"
            "var ex=document.getElementById('cfg-example');"
            "var ed=document.getElementById('cfg-editor');"
            "if(btn&&ex&&ed){btn.addEventListener('click',function(){"
            "if(!ed.value.trim()||confirm('Replace the editor contents with "
            "the example roster?')){ed.value=ex.value;ed.focus();}});}"
            "})();</script>"
        )
        return _page(f"Edit {key}", body, active="Config")
