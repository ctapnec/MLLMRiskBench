"""HTTP adapter and headless rig-console entry point."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

from .app import RigWebApp
from .reports import compute_costs, load_pricing

_MAX_POST_BYTES = 2 * 1024 * 1024
_MAX_FORM_FIELDS = 2048
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _parse_form_payload(payload: bytes) -> dict[str, str]:
    """Decode one strict, unambiguous URL-encoded form body.

    Repeatable application inputs use distinct indexed names. Duplicate HTTP
    keys therefore have no legitimate meaning and are rejected instead of
    silently choosing the first value.
    """

    try:
        text = payload.decode("utf-8")
        if _INVALID_PERCENT_ESCAPE.search(text):
            raise ValueError("malformed percent escape")
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_FORM_FIELDS,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid URL-encoded form body") from exc
    form: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in pairs:
        if (
            not key
            or len(key) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in key)
        ):
            raise ValueError("invalid URL-encoded form field name")
        if key in seen:
            raise ValueError("duplicate URL-encoded form field name")
        seen.add(key)
        # Preserve the prior request-core contract: empty controls are absent.
        if value:
            form[key] = value
    return form


def _make_server(app: RigWebApp, host: str, port: int):
    """Construct (without serving) the configured HTTP server for ``app``."""

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _send(
            self,
            status: int,
            content_type: str | None,
            body: bytes,
            *,
            location: str | None = None,
        ) -> None:
            self.send_response(status)
            if location is not None:
                self.send_header("Location", location)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            # The console is a control surface. These headers apply even to
            # errors and redirects so an attacker cannot frame a valid form or
            # reinterpret a response while probing the boundary.
            self.send_header(
                "Content-Security-Policy",
                "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
            )
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if content_type is None or content_type.startswith("text/html") or self.path.startswith('/review/'):
                self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _dispatch(self, method: str) -> None:
            form: dict[str, str] = {}
            if method == "POST":
                raw_lengths = self.headers.get_all("Content-Length", [])
                transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
                raw_length = raw_lengths[0] if len(raw_lengths) == 1 else None
                try:
                    length = (
                        int(raw_length)
                        if raw_length is not None and not transfer_encodings
                        else -1
                    )
                except ValueError:
                    length = -1
                # A missing/malformed/negative length, or one over the cap, is
                # rejected outright: never fall through to an unbounded
                # rfile.read(-1).  For an over-cap body the client is still
                # streaming, so drain a bounded amount first (so it can read
                # the 413) then close; a negative/invalid length carries no
                # trustworthy body, so reject immediately.
                if length < 0 or length > _MAX_POST_BYTES:
                    self.close_connection = True
                    if length > _MAX_POST_BYTES:
                        status_code = 413
                        body = b"request body exceeds the console limit"
                        remaining = min(length, 64 * 1024 * 1024)
                        while remaining > 0:
                            chunk = self.rfile.read(min(remaining, 65536))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                    else:
                        status_code = 400
                        body = b"invalid Content-Length"
                    self._send(status_code, "text/plain; charset=utf-8", body)
                    return
                payload = self.rfile.read(length)
                try:
                    form = _parse_form_payload(payload)
                except ValueError:
                    body = b"invalid or duplicate URL-encoded form fields"
                    self._send(400, "text/plain; charset=utf-8", body)
                    return
            status, content_type, body = app.handle(method, self.path, form)
            if status == 303:
                self._send(303, None, b"", location=content_type)
                return
            self._send(status, content_type, body)

        def do_GET(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            message = format % args
            message = re.sub(r"/review/[A-Za-z0-9_-]+", "/review/[private]", message)
            sys.stderr.write("rig-web: " + message + "\n")

    return ThreadingHTTPServer((host, port), Handler)


def _serve(app: RigWebApp, host: str, port: int) -> None:
    server = _make_server(app, host, port)
    print(
        json.dumps(
            {
                "status": "serving",
                "url": f"http://{host}:{server.server_address[1]}/",
                "results_root": str(app.results_root),
                "state_dir": str(app.state_dir),
            },
            sort_keys=True,
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()  # reconcile terminal jobs and release the database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rig-local web console over the maintained experiment CLIs "
            "(single operator; artifacts stay authoritative)"
        )
    )
    parser.add_argument("--results-root", type=Path, default=Path("runs"))
    parser.add_argument("--state-dir", type=Path, default=Path("runs") / "rig-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8642)
    parser.add_argument("--check-database", action="store_true",
                        help="headless: explicitly scan the existing SQLite database and exit (default: off)")
    parser.add_argument("--verify-artifact-sha256", action="store_true",
                        help="with --reindex: additionally hash retained files (default: off)")
    parser.add_argument(
        "--reindex",
        action="store_true",
        help="headless: rebuild the usage/report indexes from retained "
        "artifacts, print the JSON summary, and exit (same operation as "
        "the dashboard Reindex button)",
    )
    parser.add_argument(
        "--usage-report",
        action="store_true",
        help="headless: print the recorded token usage and calculated cost "
        "(the Stats spend table) as JSON and exit",
    )
    parser.add_argument(
        "--selftest-sleep",
        type=float,
        default=None,
        help="UI diagnostic only: sleep this many seconds and exit",
    )
    args = parser.parse_args(argv)
    if args.verify_artifact_sha256 and not args.reindex:
        parser.error("--verify-artifact-sha256 requires --reindex")
    if args.check_database:
        import sqlite3
        if args.reindex or args.usage_report or args.selftest_sleep is not None:
            parser.error("--check-database cannot be combined with another headless action")
        try:
            database = (args.state_dir / "console.db").resolve(strict=True)
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                findings = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            healthy = findings == ["ok"]
            print(json.dumps({"status": "ok" if healthy else "failed", "findings": findings}))
            return 0 if healthy else 1
        except (OSError, sqlite3.Error) as exc:
            print(json.dumps({"status": "failed", "error": str(exc)}))
            return 1
    if args.selftest_sleep is not None:
        time.sleep(args.selftest_sleep)
        print("rig-web selftest complete")
        return 0
    # Headless operations make the console's usage/cost/reindex functions
    # available through the CLI too, without serving the interface.
    if args.reindex or args.usage_report:
        app = RigWebApp(
            results_root=args.results_root.resolve(),
            state_dir=args.state_dir.resolve(),
        )
        app.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            if args.reindex:
                print(json.dumps(app.reindex_all(verify_sha=args.verify_artifact_sha256), sort_keys=True))
            if args.usage_report:
                totals = app.db.usage_totals() or {}
                pricing = load_pricing(app.repo_root)
                rows = compute_costs(totals, pricing)
                print(
                    json.dumps(
                        {
                            "schema": "ura-console-usage-report/1",
                            "rows": [{**row, "tokens": dict(row["tokens"])} for row in rows],
                        },
                        sort_keys=True,
                    )
                )
        finally:
            app.close()
        return 0
    app = RigWebApp(
        results_root=args.results_root.resolve(),
        state_dir=args.state_dir.resolve(),
    )
    app.state_dir.mkdir(parents=True, exist_ok=True)
    _serve(app, args.host, args.port)
    return 0
