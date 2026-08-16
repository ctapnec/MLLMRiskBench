"""Localhost HTTP adapter and headless rig-console entry point."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from .app import RigWebApp
from .reports import compute_costs, load_pricing

_MAX_POST_BYTES = 2 * 1024 * 1024


def _make_server(app: RigWebApp, host: str, port: int):
    """Construct (without serving) the localhost HTTP server for ``app``."""

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            form: dict[str, str] = {}
            if method == "POST":
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length) if raw_length is not None else 0
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
                    self.send_response(status_code)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                payload = self.rfile.read(length).decode("utf-8")
                form = {key: values[0] for key, values in parse_qs(payload).items() if values}
            status, content_type, body = app.handle(method, self.path, form)
            if status == 303:
                self.send_response(303)
                self.send_header("Location", content_type)
                self.end_headers()
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            sys.stderr.write("rig-web: " + format % args + "\n")

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
            "(single operator, localhost only; artifacts stay authoritative)"
        )
    )
    parser.add_argument("--results-root", type=Path, default=Path("runs"))
    parser.add_argument("--state-dir", type=Path, default=Path("runs") / "rig-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8642)
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
                print(json.dumps(app.reindex_all(), sort_keys=True))
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
    if args.host != "127.0.0.1":
        print(
            f"rig-web is a single-operator localhost console; refusing to bind {args.host!r}",
            file=sys.stderr,
        )
        return 1
    app = RigWebApp(
        results_root=args.results_root.resolve(),
        state_dir=args.state_dir.resolve(),
    )
    app.state_dir.mkdir(parents=True, exist_ok=True)
    _serve(app, args.host, args.port)
    return 0
