"""Budgets, pricing, secrets, and allowlisted configuration editing."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import contextlib
import html
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ura.strict_json import strict_json_loads

from .catalog import _EDITABLE_CONFIGS, _icon

from .ui import _page


from .reports import reconcile_pricing_ownership


class SettingsMixin:
    def _budgets(self) -> list[tuple[str, str, str, str]]:
        """Return configured (name, prepaid, match-prefix, funds) rows."""

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
        return rows

    def _budget_card(self) -> str:
        configured = self._budgets()
        rows = "".join(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td><strong>{html.escape(amount)}</strong></td>"
            f"<td>{html.escape(role)}</td></tr>"
            for name, amount, _match, role in configured
        )
        table = (
            _ui_template(
                "<div class='scroll'><table><tr><th>[[text:settings.provider]]</th><th>[[text:settings.prepaid]]</th><th>[[text:settings.funds]]</th></tr>"
            )
            + rows
            + "</table></div>"
            if configured
            else _ui_template("<p class='note'>[[text:settings.budgets_not_configured]]</p>")
        )
        return (
            "<div class='card'><h2>"
            + _icon("coins")
            + _ui_template("[[text:settings.provider_budgets]]</h2>")
            + table
            + _ui_template(
                "<p class='note'>[[text:settings.optional_operator_values_come_from_the_editable]] <a href='/config?file=budgets'>[[text:settings.budgets]]</a> [[text:settings.config_they_support_usage_reporting_only_execution_limits_remain]]</p></div>"
            )
        )

    @staticmethod
    def _pricing_fetch_banner(fetched: str) -> str:
        """Render the outcome of a provider-pricing fetch (escaped)."""

        try:
            summary = strict_json_loads(fetched)
        except ValueError:
            return ""
        if not isinstance(summary, dict) or not summary:
            return ""
        if summary.get("error"):
            return (
                _ui_template(
                    "<div class='notice red'><strong>[[text:settings.pricing_fetch_failed]]</strong><p class='note'>"
                )
                + html.escape(str(summary["error"]))
                + "</p></div>"
            )
        lines = []
        for provider, report in sorted((summary.get("providers") or {}).items()):
            report = report if isinstance(report, dict) else {}
            matched = report.get("matched") or []
            unmatched = report.get("unmatched") or []
            note = report.get("note") or ""
            if matched:
                lines.append(
                    (
                        "<li><strong>"
                        + f"{html.escape(provider)}"
                        + "</strong>: "
                        + f"{len(matched)}"
                        + _ui_template(" [[text:settings.rate_s_read_from]] <code>")
                        + f"{html.escape(str(report.get('url', '')))}"
                        + "</code></li>"
                    )
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
                    (
                        "<li><strong>"
                        + f"{html.escape(provider)}"
                        + _ui_template("</strong>[[text:settings.fetched_but_matched_0_of]] ")
                        + f"{len(unmatched)}"
                        + _ui_template(
                            " [[text:settings.model_s_the_page_layout_may_have_changed_enter_these_rates_by_han]]</li>"
                        )
                    )
                )
        added = summary.get("models_added", [])
        added_note = ""
        if isinstance(added, list) and added:
            added_note = (
                _ui_template(" <strong>[[text:settings.added]] ")
                + html.escape(str(len(added)))
                + _ui_template(" [[text:settings.missing_current_roster_model_s]]</strong>")
            )
        return (
            _ui_template(
                "<div class='notice blue'><strong>[[text:settings.fetched_provider_pricing]]"
            )
            + html.escape(str(summary.get("rates_written", 0)))
            + _ui_template(" [[text:settings.rate_s_written]]</strong>")
            + added_note
            + _ui_template(
                "<p class='note'>[[text:settings.auto_fetched_rates_are_stamped_with_their_source_and_date_verify]]</p><ul>"
            )
            + "".join(lines)
            + "</ul></div>"
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
        ("ANTHROPIC_API_KEY", _ui_text("settings.anthropic"), True),
        ("OPENAI_API_KEY", _ui_text("settings.openai"), True),
        ("GEMINI_API_KEY", _ui_text("settings.google_gemini"), True),
        ("DEEPSEEK_API_KEY", _ui_text("settings.deepseek"), True),
        ("MOONSHOT_API_KEY", _ui_text("settings.moonshot_kimi"), True),
        (
            "HF_TOKEN",
            _ui_text("settings.hugging_face"),
            False,
        ),
        ("DASHSCOPE_API_KEY", _ui_text("settings.alibaba_dashscope_qwen"), False),
        ("ZHIPU_API_KEY", _ui_text("settings.zhipu_glm"), False),
    )
    _SECRET_NAMES = frozenset(name for name, _label, _funded in _SECRET_ENV_VARS)
    # Acquisition credentials are deliberately process-scoped.  Unlike hosted
    # provider keys they must never be written to the operator env file: only
    # the acquisition children (the sealed model_acquire controller and the
    # export_aggregators corpus export) may inherit one, and measured/preflight
    # workers are credential-free and offline.
    _EPHEMERAL_SECRET_NAMES = frozenset({"HF_TOKEN"})

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
                    "hint": (
                        _ui_text("settings.set")
                        if name == "HF_TOKEN" and value.strip()
                        else self._mask(value)
                        if value.strip()
                        else _ui_text("settings.not_set")
                    ),
                }
            )
        return rows

    def set_secret(self, name: str, value: str) -> None:
        """Set an allowlisted secret without ever rendering its value.

        Fail-closed: only allowlisted names, only a non-empty single-line
        token.  Hosted-provider keys are written to the operator secrets file
        (created 0600) and mirrored into ``os.environ``.  Acquisition-only
        credentials are held in this console process and scrubbed from any
        legacy env-file entry, so only the acquisition children (model_acquire
        and export_aggregators) can receive them.  No value is echoed, logged,
        backed up, or stored in the database.
        """

        if name not in self._SECRET_NAMES:
            raise ValueError((_ui_text("settings.unknown_secret") + f"{name!r}"))
        value = value.strip()
        if not value:
            raise ValueError(_ui_text("settings.secret_value_must_not_be_empty"))
        # Must be a single line by str.splitlines()'s definition, which is what
        # the env file is later read back with.  That set is broader than just
        # \n/\r: it also includes the Unicode line/paragraph separators
        # (U+0085, U+2028, U+2029) a paste from a PDF or rich-text field can
        # carry.  Reject them here so a stored key can never be split apart on
        # the next read-modify-write and corrupt the sourced file.
        if value.splitlines() != [value]:
            raise ValueError(_ui_text("settings.secret_value_must_be_a_single_line"))
        if len(value) > 4096:
            raise ValueError(_ui_text("settings.secret_value_is_implausibly_long"))
        # The value is written inside single quotes into a file that is sourced
        # by the campaign shell.  A single quote would close the quoting and let
        # the remainder run as shell; control characters would corrupt the line.
        # Real provider keys never contain either, so reject them fail-closed
        # rather than attempting to escape them.
        if "'" in value:
            raise ValueError(_ui_text("settings.secret_value_must_not_contain_a_single_quote"))
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError(_ui_text("settings.secret_value_must_not_contain_control_characters"))
        line = f"export {name}='{value}'"
        pattern = re.compile(rf"^\s*export\s+{re.escape(name)}=")
        # Serialize the read-modify-write so a concurrent set/clear cannot drop
        # a key, and surface any filesystem fault as a ValueError the secrets
        # page renders as "Not saved" (never an unhandled 500; the value never
        # appears in the message).
        with self._secret_lock:
            existing = self._read_env_lines()
            if name in self._EPHEMERAL_SECRET_NAMES:
                # Older releases treated every allowlisted secret uniformly.
                # Remove any legacy durable acquisition credential before
                # making the newly supplied token visible to this process.
                # If the scrub cannot be committed, fail without setting it.
                out_lines = [entry for entry in existing if not pattern.match(entry)]
                if out_lines != existing:
                    try:
                        self._write_env_file("\n".join(out_lines) + "\n")
                    except OSError as exc:
                        raise ValueError(
                            (_ui_text("settings.could_not_write_the_secrets_file") + f"{exc}")
                        ) from exc
                os.environ[name] = value
                return
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
                raise ValueError(
                    (_ui_text("settings.could_not_write_the_secrets_file") + f"{exc}")
                ) from exc
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
            raise ValueError(
                (_ui_text("settings.could_not_read_the_secrets_file") + f"{exc}")
            ) from exc

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
        """Remove an allowlisted secret from durable storage and the process."""

        if name not in self._SECRET_NAMES:
            raise ValueError((_ui_text("settings.unknown_secret") + f"{name!r}"))
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
                    raise ValueError(
                        (_ui_text("settings.could_not_write_the_secrets_file") + f"{exc}")
                    ) from exc
            os.environ.pop(name, None)

    def _secrets_page(self, *, error: str = "", saved: str = "") -> bytes:
        groups = {
            "Campaign providers": [],
            "Additional providers": [],
            "Model and corpus downloads": [],
        }
        statuses = self.secret_status()
        for row in statuses:
            tone = "green" if row["present"] else ("gray" if not row["funded"] else "amber")
            state = html.escape(row["hint"])
            clear = (
                (
                    "<form class='action-row provider-key-clear' method='post' action='/config/secrets'><input type='hidden' name='name' value='"
                    + f"{html.escape(row['name'])}"
                    + _ui_template(
                        "'><input type='hidden' name='action' value='clear'><button type='submit' class='danger small'>[[text:settings.clear]]</button></form>"
                    )
                )
                if row["present"]
                else ""
            )
            group = (
                _ui_text("settings.model_and_corpus_downloads")
                if row["name"] == "HF_TOKEN"
                else _ui_text("settings.campaign_providers")
                if row["funded"]
                else _ui_text("settings.additional_providers")
            )
            groups[group].append(
                "<article class='card provider-key-card'>"
                "<div class='provider-key-heading'>"
                f"<h3>{html.escape(row['label'])}</h3>"
                f"<span class='badge {tone}'>{state}</span></div>"
                "<code class='provider-key-variable'>" + html.escape(row["name"]) + "</code>"
                "<details class='provider-key-editor'><summary>"
                + (
                    _ui_text("settings.update_key")
                    if row["present"]
                    else _ui_text("settings.add_key")
                )
                + (
                    "</summary><form id='setkey-"
                    + f"{html.escape(row['name'])}"
                    + "' method='post' action='/config/secrets'><input type='hidden' name='name' value='"
                    + f"{html.escape(row['name'])}"
                    + "'><input type='hidden' name='action' value='set'><label for='key-"
                    + f"{html.escape(row['name'])}"
                    + _ui_template(
                        "'>[[text:settings.new_key]]</label><div class='provider-key-input-row'><input id='key-"
                    )
                    + f"{html.escape(row['name'])}"
                    + _ui_template(
                        "' type='password' autocomplete='new-password' name='value' placeholder='[[attr:settings.paste_new_key]]' required spellcheck='false'><button type='submit'>[[text:settings.save_key]]</button></div></form>"
                    )
                )
                + clear
                + "</details></article>"
            )
        banner = ""
        if saved:
            storage_note = (
                _ui_text(
                    "settings.held_only_in_this_console_process_and_supplied_only_to_the_dedica"
                )
                if saved in self._EPHEMERAL_SECRET_NAMES
                else _ui_text(
                    "settings.written_to_the_operator_secrets_file_and_applied_to_this_console"
                )
            )
            banner = (
                _ui_template("<div class='notice blue'><strong>[[text:settings.key]] ")
                + html.escape(_ui_text("settings.updated_provider", provider=saved))
                + "</strong><p class='note'>"
                + storage_note
                + _ui_template(" [[text:settings.the_value_is_never_displayed]]</p></div>")
            )
        if error:
            banner = (
                _ui_template("<div class='notice red'><strong>[[text:settings.not_saved]] ")
                + html.escape(error)
                + "</strong></div>"
            )
        body = (
            "<h1>"
            + _icon("sliders", size=22)
            + _ui_template(
                "[[text:settings.provider_api_keys]]</h1><p class='crumbs'><a href='/config'>[[text:settings.configuration]]</a><span class='sep'>/</span>[[text:settings.secrets]]</p>"
            )
            + banner
            + (
                _ui_template(
                    "<p class='note'>[[text:settings.manage_access_for_new_jobs_stored_keys_stay_hidden_a_saved_key_do]]</p><p>"
                )
                + html.escape(
                    _ui_text(
                        "settings.credentials_configured",
                        configured=sum(row["present"] for row in statuses),
                        total=len(statuses),
                    )
                )
                + "</p><style>.provider-key-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:16px}.provider-key-card{min-width:0;margin:0}.provider-key-heading{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}.provider-key-heading h3{margin:0}.provider-key-variable{display:block;overflow-wrap:anywhere;margin:12px 0}.provider-key-editor summary{cursor:pointer}.provider-key-editor form{margin-top:12px}.provider-key-editor label{display:block;margin-bottom:6px}.provider-key-input-row{display:flex;flex-wrap:wrap;gap:12px;align-items:center}.provider-key-input-row input{min-width:0;flex:1 1 180px;width:auto;font:inherit;min-height:2.65rem;padding:.65rem .8rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}.provider-key-input-row input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.provider-key-editor form.provider-key-clear{margin-top:16px}.provider-key-input-row button{flex:0 0 auto}.provider-key-section{margin:24px 0}</style>"
            )
            + "".join(
                "<section class='provider-key-section'><h2>"
                + heading
                + "</h2><div class='provider-key-grid'>"
                + "".join(cards)
                + "</div></section>"
                for heading, cards in groups.items()
            )
            + _ui_template(
                "<details><summary>[[text:settings.storage_and_job_access]]</summary><p class='note'>[[text:settings.hosted_keys_are_stored_in]] <code>~/.ura_env</code> [[text:settings.mode_600_and_used_by_new_jobs_only_their_last_four_characters_are]]</p></details>"
            )
        )
        return _page(
            _ui_text("settings.provider_api_keys"), body, active=_ui_text("settings.config")
        )

    # -- config editor -----------------------------------------------------

    def _config_target(self, key: str) -> tuple[Path, str]:
        """Resolve an allowlisted config key to its file path and description.

        Only keys in ``_EDITABLE_CONFIGS`` resolve; anything else is rejected,
        so no path outside the allowlist is ever readable or writable here.
        """

        entry = _EDITABLE_CONFIGS.get(key)
        if entry is None:
            raise ValueError((_ui_text("settings.unknown_config") + f"{key!r}"))
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
            parsed = strict_json_loads(content)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise ValueError((_ui_text("settings.content_is_not_valid_json") + f"{exc}")) from exc
        if not isinstance(parsed, dict):
            raise ValueError(_ui_text("settings.config_must_be_a_json_object"))
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
                    on_disk_raw = path.read_text(encoding="utf-8")
                except FileNotFoundError:
                    on_disk = {}
                except OSError as exc:
                    raise ValueError(
                        _ui_text(
                            "settings.existing_pricing_config_is_unreadable_refusing_to_overwrite_opera"
                        )
                    ) from exc
                else:
                    try:
                        on_disk = strict_json_loads(on_disk_raw)
                    except (UnicodeError, ValueError, RecursionError) as exc:
                        raise ValueError(
                            _ui_text(
                                "settings.existing_pricing_config_is_not_strict_json_refusing_to_overwrite"
                            )
                        ) from exc
                    if not isinstance(on_disk, dict):
                        raise ValueError(
                            _ui_text(
                                "settings.existing_pricing_config_is_not_a_json_object_refusing_to_overwrit"
                            )
                        )
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
                    raise ValueError(_ui_text("settings.config_target_is_not_a_regular_file"))
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
                state = (
                    _ui_text("settings.exists")
                    if path.is_file()
                    else _ui_text("settings.not_created_yet")
                )
                cards.append(
                    "<div class='card'><h2>"
                    + _icon("sliders")
                    + (
                        f"{html.escape(token)}"
                        + "</h2><p class='note'><code>"
                        + f"{html.escape(relative)}"
                        + "</code> - "
                        + f"{html.escape(state)}"
                        + "</p><p>"
                        + f"{html.escape(description)}"
                        + "</p><p><a href='/config?file="
                        + f"{quote(token)}"
                        + _ui_template(
                            "'><button type='button'>[[text:settings.open_editor]]</button></a></p></div>"
                        )
                    )
                )
            # Provider API keys: presence + set/rotate, values never shown.
            statuses = self.secret_status()
            set_count = sum(1 for s in statuses if s["present"])
            cards.append(
                "<div class='card'><h2>"
                + _icon("logo")
                + (
                    _ui_template(
                        "[[text:settings.provider_api_keys]]</h2><p class='note'>[[text:settings.set_or_rotate_the_hosted_provider_keys]]<code>~/.ura_env</code>[[text:settings.mode_600]] "
                    )
                    + f"{set_count}"
                    + _ui_text("settings.of")
                    + f"{len(statuses)}"
                    + _ui_template(
                        " [[text:settings.set_the_console_never_displays_a_stored_key]]</p><p><a href='/config/secrets'><button type='button'>[[text:settings.manage_keys]]</button></a></p></div>"
                    )
                )
            )
            body = (
                "<h1>"
                + _icon("sliders", size=22)
                + _ui_template(
                    "[[text:settings.configuration]]</h1><p class='note'>[[text:settings.edit_the_operator_local_registries_in_place_saves_are_json_valida]]</p>"
                )
                + "".join(cards)
            )
            return _page(
                _ui_text("settings.configuration"), body, active=_ui_text("settings.config")
            )
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
                    seeded = _ui_template(
                        "<div class='notice blue'><strong>[[text:settings.prefilled_from_the_checked_in_example]]</strong><p class='note'>[[text:settings.review_and_edit_then_save_to_write_the_local_registry]]</p></div>"
                    )
        banner = seeded
        if saved:
            banner = _ui_template(
                "<div class='notice blue'><strong>[[text:settings.saved]]</strong><p class='note'>[[text:settings.prior_version_backed_up_under_the_console_state_directory]]</p></div>"
            )
        if error:
            banner = (
                _ui_template("<div class='notice red'><strong>[[text:settings.not_saved]] ")
                + f"{html.escape(error)}"
                + "</strong></div>"
            )
        if fetched:
            banner = self._pricing_fetch_banner(fetched) + banner
        # The pricing editor gets a fetch-from-provider-pages action.
        fetch_action = ""
        if key == "pricing":
            fetch_action = (
                _ui_template(
                    "<form class='inline' method='post' action='/pricing/fetch' data-busy='[[attr:settings.fetching_provider_pricing_pages]]'><button type='submit' class='ghost'>"
                )
                + _icon("coins", size=15)
                + _ui_template(
                    "[[text:settings.fetch_from_provider_pricing_pages]]</button></form> "
                )
            )
        body = (
            "<h1>"
            + _icon("sliders", size=22)
            + (
                _ui_text("settings.edit")
                + f"{html.escape(key)}"
                + _ui_template(
                    "</h1><p class='crumbs'><a href='/config'>[[text:settings.configuration]]</a><span class='sep'>/</span>"
                )
                + f"{html.escape(relative)}"
                + "</p>"
            )
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
            + _ui_template("[[text:settings.validate_save]]</button>")
            + (
                "<button type='button' class='ghost' id='cfg-prefill'>"
                + _icon("box", size=15)
                + _ui_template("[[text:settings.prefill_from_example]]</button>")
                if example_text
                else ""
            )
            + (
                "<a href='/config?file="
                + f"{quote(key)}"
                + _ui_template(
                    "'><button type='button' class='ghost'>[[text:settings.reload]]</button></a></div></form><p class='note'>[[text:settings.save_is_rejected_unless_the_content_parses_as_a_json_object_on_su]]</p><script>(function(){var btn=document.getElementById('cfg-prefill');var ex=document.getElementById('cfg-example');var ed=document.getElementById('cfg-editor');if(btn&&ex&&ed){btn.addEventListener('click',function(){if(!ed.value.trim()||confirm([[js:settings.replace_the_editor_contents_with_the_example_roster]])){ed.value=ex.value;ed.focus();}});}})();</script>"
                )
            )
        )
        return _page(
            (_ui_text("settings.edit") + f"{key}"), body, active=_ui_text("settings.config")
        )
