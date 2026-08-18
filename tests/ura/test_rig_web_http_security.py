"""HTTP control-plane security regressions for the rig-local web console."""

from __future__ import annotations

import http.client
import re
import threading
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlencode

import pytest

from experiments.rig_web_app.server import _make_server


_MUTATING_ROUTES = (
    "/config",
    "/config/secrets",
    "/pricing/fetch",
    "/db/reindex",
    "/build",
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
            # A similarly named data attribute must not put a token in a GET form.
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


def _get_token(port: int, authority: str) -> tuple[str, dict[str, str], bytes]:
    status, headers, body = _request(
        port,
        "GET",
        "/",
        headers=(("Host", authority),),
    )
    assert status == 200
    tokens = re.findall(rb"name='_csrf' value='([^']+)'", body)
    assert len(tokens) == len(_MUTATING_ROUTES) + 2
    assert len(set(tokens)) == 1
    token = tokens[0].decode("ascii")
    assert len(token) >= 40
    return token, headers, body


def test_html_forms_get_one_process_token_and_clickjacking_headers(
    running_server,
) -> None:
    app, port = running_server
    token, headers, body = _get_token(port, f"127.0.0.1:{port}")

    assert token.encode("ascii") in body
    assert body.lower().count(b"<form ") == len(_MUTATING_ROUTES) + 3
    assert b"data-method='post' method='get'><input" not in body
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "form-action 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert app.calls == [("GET", "/", {})]


@pytest.mark.parametrize(
    ("authority", "origin"),
    (
        ("127.0.0.1:43123", "http://127.0.0.1:43123"),
        ("[::1]:43124", "http://[::1]:43124"),
        ("127.0.0.1", "http://127.0.0.1"),
        ("[::1]", "http://[::1]"),
    ),
)
def test_literal_loopback_forwarded_authorities_are_supported(
    running_server,
    authority: str,
    origin: str,
) -> None:
    app, port = running_server
    status, _headers, body = _request(
        port,
        "GET",
        "/build",
        headers=(("Host", authority), ("Origin", origin)),
    )
    assert status == 200 and b"name='_csrf'" in body
    assert app.calls == [("GET", "/build", {})]


def test_host_origin_and_fetch_site_fail_before_dispatch_or_token_disclosure(
    running_server,
) -> None:
    app, port = running_server
    good_host = f"127.0.0.1:{port}"
    probes: tuple[tuple[tuple[str, str], ...], ...] = (
        (),
        (("Host", "localhost:8642"),),
        (("Host", "attacker.example:8642"),),
        (("Host", "127.0.0.1.attacker.example:8642"),),
        (("Host", "2130706433:8642"),),
        (("Host", "127.0.0.1:080"),),
        (("Host", good_host), ("Host", good_host)),
        (("Host", good_host), ("Origin", "null")),
        (("Host", good_host), ("Origin", "https://127.0.0.1:%d" % port)),
        (("Host", good_host), ("Origin", "https://attacker.example")),
        (("Host", good_host), ("Origin", "http://127.0.0.1:1")),
        (
            ("Host", good_host),
            ("Origin", f"http://{good_host}"),
            ("Origin", f"http://{good_host}"),
        ),
        (("Host", good_host), ("Sec-Fetch-Site", "cross-site")),
        (("Host", good_host), ("Sec-Fetch-Site", "same-site")),
    )
    for request_headers in probes:
        app.calls.clear()
        status, headers, body = _request(
            port,
            "GET",
            "/config/secrets",
            headers=request_headers,
        )
        assert status in {400, 403}
        assert b"_csrf" not in body
        assert app.calls == []
        assert headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]

    # Host admission happens before a declared request body is read or drained.
    status, _headers, body = _request(
        port,
        "POST",
        "/config",
        headers=(
            ("Host", "attacker.example:8642"),
            ("Content-Length", str(1024 * 1024)),
        ),
    )
    assert status == 403 and b"literal loopback" in body
    assert app.calls == []


def test_every_mutating_route_requires_one_valid_csrf_before_dispatch(
    running_server,
) -> None:
    app, port = running_server
    authority = f"127.0.0.1:{port}"
    origin = f"http://{authority}"
    token, _headers, _body = _get_token(port, authority)
    app.calls.clear()

    for route in _MUTATING_ROUTES:
        for payload, expected_status in (
            (b"marker=x", 403),
            (urlencode({"_csrf": "wrong", "marker": "x"}).encode(), 403),
            (
                (
                    f"_csrf={token}&_csrf={token}&marker=x"
                ).encode("ascii"),
                400,
            ),
        ):
            status, _response_headers, _response_body = _request(
                port,
                "POST",
                route,
                headers=(("Host", authority), ("Origin", origin)),
                body=payload,
            )
            assert status == expected_status
            assert app.calls == []

        valid = urlencode({"_csrf": token, "marker": "x"}).encode("ascii")
        status, headers, _response_body = _request(
            port,
            "POST",
            route,
            headers=(
                ("Host", authority),
                ("Origin", origin),
                ("Sec-Fetch-Site", "same-origin"),
            ),
            body=valid,
        )
        assert status == 303
        assert headers["location"] == "/done"
        assert headers["x-frame-options"] == "DENY"
        assert app.calls == [("POST", route, {"marker": "x"})]
        app.calls.clear()

        # Browser-origin admission happens before the body or its token is read.
        for hostile_header in (
            ("Origin", "null"),
            ("Origin", "https://attacker.example"),
            ("Sec-Fetch-Site", "cross-site"),
        ):
            status, _headers, _body = _request(
                port,
                "POST",
                route,
                headers=(("Host", authority), hostile_header),
                body=b"",
            )
            assert status == 403
            assert app.calls == []

    # A non-browser client may omit Origin only when it possesses the token.
    status, _headers, _body = _request(
        port,
        "POST",
        "/db/reindex",
        headers=(("Host", authority),),
        body=urlencode({"_csrf": token}).encode("ascii"),
    )
    assert status == 303
    assert app.calls == [("POST", "/db/reindex", {})]


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
