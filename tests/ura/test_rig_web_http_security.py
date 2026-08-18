"""HTTP control-plane security regressions for the rig-local web console."""

from __future__ import annotations

import http.client
import threading
from dataclasses import dataclass, field
from typing import Iterable

import pytest

from experiments.rig_web_app.server import _make_server


_MUTATING_ROUTES = (
    "/config",
    "/config/secrets",
    "/pricing/fetch",
    "/db/reindex",
    "/build",
    "/build/framework-runtimes",
    "/build/t3mp3st/capture",
    "/build/harmbench/prepare",
    "/jobs",
    "/jobs/job-fixture/stop",
    "/ollama/start",
    "/ollama/stop",
    "/ollama/pull",
)


@dataclass
class _RecordingApp:
    calls: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)

    def handle(
        self, method: str, path: str, form: dict[str, str] | None = None,
    ) -> tuple[int, str, bytes]:
        self.calls.append((method, path, dict(form or {})))
        if method == "GET":
            forms = "".join(
                (
                    f"<form method='post' action='{route}'>"
                    "<button type='submit'>go</button></form>"
                )
                for route in _MUTATING_ROUTES
            )
            # Exercise both quote styles and case-insensitive method matching.
            forms += '<form class="extra" method="POST" action="/build"></form>'
            forms += "<form method=post action='/jobs'></form>"
            # A similarly named data attribute must remain untouched.
            forms += (
                "<form data-method='post' method='get' "
                "action='/search'></form>"
            )
            return 200, "text/html; charset=utf-8", forms.encode("utf-8")
        return 303, "/done", b""


def _request(
    port: int,
    method: str,
    path: str,
    *,
    headers: Iterable[tuple[str, str]] = (),
    body: bytes = b"",
    auto_content_length: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    """Send one request while retaining duplicate/missing-header control."""

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    items = list(headers)
    connection.putrequest(
        method,
        path,
        skip_host=True,
        skip_accept_encoding=True,
    )
    for name, value in items:
        connection.putheader(name, value)
    if method == "POST" and auto_content_length and not any(
        name.lower() == "content-length" for name, _value in items
    ):
        connection.putheader("Content-Length", str(len(body)))
    if method == "POST" and not any(
        name.lower() == "content-type" for name, _value in items
    ):
        connection.putheader(
            "Content-Type", "application/x-www-form-urlencoded"
        )
    connection.endheaders(body)
    response = connection.getresponse()
    response_body = response.read()
    response_headers = {
        name.lower(): value for name, value in response.getheaders()
    }
    status = response.status
    connection.close()
    return status, response_headers, response_body


@pytest.fixture
def running_server():
    app = _RecordingApp()
    server = _make_server(app, "127.0.0.1", 0)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield app, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def test_server_honors_configured_non_loopback_socket_bind() -> None:
    app = _RecordingApp()
    server = _make_server(app, "0.0.0.0", 0)
    try:
        assert server.server_address[0] == "0.0.0.0"
        assert int(server.server_address[1]) > 0
    finally:
        server.server_close()


def test_html_forms_are_unchanged_and_keep_clickjacking_headers(
    running_server,
) -> None:
    app, port = running_server
    status, headers, body = _request(
        port,
        "GET",
        "/",
        headers=(("Host", f"console.example:{port}"),),
    )

    assert status == 200
    assert b"name='_csrf'" not in body
    assert body.lower().count(b"<form ") == len(_MUTATING_ROUTES) + 3
    assert b"data-method='post' method='get'" in body
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "form-action 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert app.calls == [("GET", "/", {})]


def test_host_origin_and_fetch_site_headers_do_not_gate_dispatch(
    running_server,
) -> None:
    app, port = running_server
    probes: tuple[tuple[tuple[str, str], ...], ...] = (
        (),
        (("Host", "localhost:8642"),),
        (("Host", "attacker.example:8642"),),
        (("Host", "127.0.0.1.attacker.example:8642"),),
        (("Host", "2130706433:8642"),),
        (("Host", "127.0.0.1:080"),),
        (("Host", "first.example"), ("Host", "second.example")),
        (("Origin", "null"),),
        (("Origin", "https://127.0.0.1:%d" % port),),
        (("Origin", "https://attacker.example"),),
        (("Origin", "http://127.0.0.1:1"),),
        (
            ("Origin", "https://first.example"),
            ("Origin", "https://second.example"),
        ),
        (("Sec-Fetch-Site", "cross-site"),),
        (("Sec-Fetch-Site", "same-site"),),
    )
    for request_headers in probes:
        app.calls.clear()
        status, headers, body = _request(
            port,
            "GET",
            "/config/secrets",
            headers=request_headers,
        )
        assert status == 200
        assert b"_csrf" not in body
        assert app.calls == [("GET", "/config/secrets", {})]
        assert headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]

    app.calls.clear()
    status, headers, _body = _request(
        port,
        "POST",
        "/config",
        headers=(
            ("Host", "attacker.example:8642"),
            ("Origin", "https://attacker.example"),
            ("Sec-Fetch-Site", "cross-site"),
        ),
        body=b"marker=x",
    )
    assert status == 303 and headers["location"] == "/done"
    assert app.calls == [("POST", "/config", {"marker": "x"})]


def test_mutating_routes_dispatch_without_csrf_or_origin_admission(
    running_server,
) -> None:
    app, port = running_server

    for route in _MUTATING_ROUTES:
        status, headers, _response_body = _request(
            port,
            "POST",
            route,
            headers=(
                ("Host", "attacker.example"),
                ("Origin", "https://attacker.example"),
                ("Sec-Fetch-Site", "cross-site"),
            ),
            body=b"marker=x",
        )
        assert status == 303
        assert headers["location"] == "/done"
        assert headers["x-frame-options"] == "DENY"
        assert app.calls == [("POST", route, {"marker": "x"})]
        app.calls.clear()

    # Removing CSRF special handling does not weaken strict duplicate-key parsing.
    status, _headers, body = _request(
        port,
        "POST",
        "/db/reindex",
        body=b"marker=x&marker=y",
    )
    assert status == 400
    assert b"duplicate URL-encoded" in body
    assert app.calls == []


@pytest.mark.parametrize(
    "framing_headers",
    (
        (),
        (("Content-Length", "0"), ("Content-Length", "0")),
        (("Content-Length", "0"), ("Transfer-Encoding", "chunked")),
        (("Transfer-Encoding", "chunked"),),
    ),
)
def test_ambiguous_or_missing_post_framing_is_rejected_before_dispatch(
    running_server,
    framing_headers: tuple[tuple[str, str], ...],
) -> None:
    app, port = running_server
    status, _headers, body = _request(
        port,
        "POST",
        "/config",
        headers=(("Host", f"127.0.0.1:{port}"), *framing_headers),
        auto_content_length=False,
    )
    assert status == 400
    assert b"Content-Length" in body
    assert app.calls == []
