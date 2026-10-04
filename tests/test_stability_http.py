"""Stability and hostility tests for the web stage's HTTP client and concurrency.

The hosts this stage talks to are, by definition, not trustworthy. Everything
here exists to catch one of five classes of bug:

1. **An exception type the stage does not expect.** ``GetOnlyClient.get`` is
   contracted to raise only :class:`~netrecon.stages.webrecon.WebReconError`.
   A malformed status line, a header with no colon or two hundred response
   headers raise :class:`http.client.HTTPException`, which is *not* an
   ``OSError`` and which urllib does not wrap - so it used to escape.
2. **Unbounded work.** An endless body, a body far over the byte cap, a server
   that sends headers and then stops, a page linking five hundred scripts, a
   script that references itself, a robots.txt with ten thousand rules.
3. **Walking off the authorised endpoint.** A redirect, a sitemap entry or a
   ``<script src>`` pointing at another host (or another port on the same IP)
   must be recorded and never requested. Every scenario asserts over the full
   recorded request list, not just the happy path.
4. **Concurrency.** The shared rate limiter must hold the aggregate rate
   without deadlocking or serialising, and one worker's failure must not
   discard the other workers' results.
5. **Leaking a scanned host's content.** A response body must not reach the
   log, at any level.

Tests that need a real socket bind to 127.0.0.1 on an ephemeral port, are
marked ``e2e``, and are torn down by a fixture. Nothing here reaches the
network. No test is allowed to take more than about two seconds, so the client
is configured with short timeouts rather than the tests using long sleeps.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import re
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from netrecon.core.jsonio import write_json
from netrecon.core.runner import run_parallel
from netrecon.report import build as report_build
from netrecon.stages import webrecon
from netrecon.stages.webrecon import (
    Endpoint,
    GetOnlyClient,
    HttpResponse,
    RateLimiter,
    WebReconError,
)

IN_SCOPE = "10.10.10.5"
SECOND_IN_SCOPE = "10.10.10.6"
OUT_OF_SCOPE = "192.168.99.99"

#: Smallest body cap the config layer accepts; keeps the "5x the cap" case tiny.
CAP = 1024
#: Short enough that the slowest test still finishes well inside two seconds.
TIMEOUT = 1

#: An HTTP method token, used to tell a request apart from a TLS ClientHello.
_METHOD_TOKEN = re.compile(r"[A-Z]{3,12}")


# ===================================================================
# the hostile server
# ===================================================================


def _canned(status_line: str, headers: str, body: bytes) -> bytes:
    return f"{status_line}\r\n{headers}\r\n".encode("latin-1") + body


def _with_length(status_line: str, body: bytes, extra: str = "") -> bytes:
    return _canned(status_line, f"Content-Length: {len(body)}\r\n{extra}", body)


def _hang(sock: socket.socket) -> None:
    """Headers, then silence. The client must time out instead of blocking."""
    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
    time.sleep(TIMEOUT * 3)


def _endless(sock: socket.socket) -> None:
    """A body with no end. Stops only when the client gives up on us."""
    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
    try:
        while True:
            sock.sendall(b"A" * 4096)
    except OSError:
        return


def _accept_then_close(sock: socket.socket) -> None:
    sock.shutdown(socket.SHUT_RDWR)


def _routes(port_holder: list[int]) -> dict[str, bytes | Callable[[socket.socket], None]]:
    """Every hostile response this module can serve, keyed by request path."""
    huge_header = "X-Huge: " + "h" * 10_240 + "\r\n"
    gzipped = gzip.compress(b"<html><title>gzipped</title></html>")
    return {
        "/": _with_length("HTTP/1.1 200 OK", b"<html><title>ok</title></html>"),
        # --- transport-level hostility ---
        "/close": _accept_then_close,
        "/hang": _hang,
        "/endless": _endless,
        "/big": _with_length("HTTP/1.1 200 OK", b"B" * (CAP * 5)),
        "/lying-length": _canned("HTTP/1.1 200 OK", "Content-Length: 100000\r\n", b"short"),
        # --- redirects: recorded, never followed ---
        "/r301": _canned(
            "HTTP/1.1 301 Moved Permanently",
            "Location: http://evil.example.com/landing\r\nContent-Length: 0\r\n",
            b"",
        ),
        "/r302": _canned(
            "HTTP/1.1 302 Found",
            "Location: http://evil.example.com/landing\r\nContent-Length: 0\r\n",
            b"",
        ),
        "/r307": _canned(
            "HTTP/1.1 307 Temporary Redirect",
            "Location: http://evil.example.com/landing\r\nContent-Length: 0\r\n",
            b"",
        ),
        "/r308": _canned(
            "HTTP/1.1 308 Permanent Redirect",
            "Location: http://evil.example.com/landing\r\nContent-Length: 0\r\n",
            b"",
        ),
        "/loop": lambda sock: sock.sendall(
            _canned(
                "HTTP/1.1 302 Found",
                f"Location: http://127.0.0.1:{port_holder[0]}/loop\r\nContent-Length: 0\r\n",
                b"",
            )
        ),
        # --- error statuses are results, not failures ---
        "/401": _with_length("HTTP/1.1 401 Unauthorized", b"nope", "WWW-Authenticate: Basic\r\n"),
        "/403": _with_length("HTTP/1.1 403 Forbidden", b"nope"),
        "/500": _with_length("HTTP/1.1 500 Internal Server Error", b"boom"),
        "/503": _with_length("HTTP/1.1 503 Service Unavailable", b"later"),
        # --- malformed framing and headers ---
        "/bad-status": _with_length("HTTP/1.1 OK", b"hi"),
        "/not-http": b"this is not an HTTP response at all\r\n\r\n",
        "/no-colon": _canned("HTTP/1.1 200 OK", "ThisHeaderHasNoColon\r\n", b"hi"),
        "/dup-headers": _with_length(
            "HTTP/1.1 200 OK", b"hi", "X-Dup: first\r\nX-Dup: second\r\n"
        ),
        "/huge-header": _with_length("HTTP/1.1 200 OK", b"hi", huge_header),
        "/ctl-header-name": _with_length("HTTP/1.1 200 OK", b"hi", "X-\x01\x02Bad: v\r\n"),
        "/too-many-headers": _with_length(
            "HTTP/1.1 200 OK", b"hi", "".join(f"X-N{i}: v\r\n" for i in range(250))
        ),
        # --- content types that lie or are missing ---
        "/no-ct": _canned("HTTP/1.1 200 OK", "Content-Length: 2\r\n", b"hi"),
        "/nonsense-ct": _with_length("HTTP/1.1 200 OK", b"hi", "Content-Type: ?!?/\x7f;;\r\n"),
        "/lying-ct": _with_length(
            "HTTP/1.1 200 OK", b"<html><body>not json</body></html>",
            "Content-Type: application/json\r\n",
        ),
        # --- bodies that are not valid UTF-8 ---
        "/latin1": _with_length(
            "HTTP/1.1 200 OK", "caf\xe9 r\xe9sum\xe9".encode("latin-1")
        ),
        "/utf16": _with_length("HTTP/1.1 200 OK", "hello é".encode("utf-16")),
        "/bom": _with_length("HTTP/1.1 200 OK", b"\xef\xbb\xbf<html>bom</html>"),
        "/invalid-utf8": _with_length("HTTP/1.1 200 OK", b"ok \xc3\x28\xff\xfe bad"),
        "/nulls": _with_length("HTTP/1.1 200 OK", b"a\x00b\x00\x00c"),
        # --- encoding we never asked for ---
        "/gzip": _with_length("HTTP/1.1 200 OK", gzipped, "Content-Encoding: gzip\r\n"),
    }


class _HostileServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tls_context: ssl.SSLContext | None = None) -> None:
        self.port_holder: list[int] = [0]
        self.routes = _routes(self.port_holder)
        self.seen: list[tuple[str, str]] = []
        self._seen_lock = threading.Lock()
        self._tls_context = tls_context
        super().__init__(("127.0.0.1", 0), _HostileHandler)
        self.port_holder[0] = self.server_address[1]

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def url(self, path: str, scheme: str = "http") -> str:
        return f"{scheme}://127.0.0.1:{self.port}{path}"

    def record(self, method: str, path: str) -> None:
        with self._seen_lock:
            self.seen.append((method, path))

    def get_request(self):  # noqa: ANN201 - socketserver's own signature
        sock, addr = super().get_request()
        if self._tls_context is not None:
            sock = self._tls_context.wrap_socket(sock, server_side=True)
        return sock, addr

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        # Being hung up on mid-response, or handed a cleartext request on a TLS
        # port, is exactly what this fixture is for. Not an error here.
        return


class _HostileHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        raw = self._read_request_head()
        if raw is None:
            return
        parts = raw.split(b"\r\n", 1)[0].split(b" ")
        method = parts[0].decode("latin-1") if parts else ""
        path = parts[1].decode("latin-1").split("?")[0] if len(parts) > 1 else "/"
        if not _METHOD_TOKEN.fullmatch(method):
            return  # a TLS ClientHello, not a request; nothing to answer
        self.server.record(method, path)
        route = self.server.routes.get(path)
        if route is None:
            self.request.sendall(_with_length("HTTP/1.1 404 Not Found", b"missing"))
        elif callable(route):
            route(self.request)
        else:
            self.request.sendall(route)

    def _read_request_head(self) -> bytes | None:
        self.request.settimeout(TIMEOUT * 2)
        buffer = b""
        try:
            while b"\r\n\r\n" not in buffer and len(buffer) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if not buffer[:1].isalpha():
                    break  # not an HTTP request line; do not wait for a CRLF pair
        except OSError:
            return None
        return buffer or None


def _serve(server: socketserver.TCPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


@pytest.fixture(scope="module")
def hostile() -> Iterator[_HostileServer]:
    server = _HostileServer()
    _serve(server)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def tls_cert(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A throwaway self-signed certificate for the TLS-port fixture."""
    directory = tmp_path_factory.mktemp("tls")
    pem = directory / "server.pem"
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            "openssl", "req", "-x509", "-nodes", "-days", "1",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-subj", "/CN=127.0.0.1", "-keyout", str(pem), "-out", str(pem),
        ],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0 or not pem.is_file():
        pytest.skip("openssl could not produce a test certificate")
    return pem


@pytest.fixture(scope="module")
def tls_hostile(tls_cert: Path) -> Iterator[_HostileServer]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tls_cert))
    server = _HostileServer(tls_context=context)
    _serve(server)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _client(*, max_bytes: int = CAP, timeout: int = TIMEOUT) -> GetOnlyClient:
    return GetOnlyClient(
        limiter=RateLimiter(0),  # the limiter has its own tests; keep these fast
        timeout=timeout,
        max_bytes=max_bytes,
        user_agent="netrecon/test",
        verify_tls=False,
    )


def _get_or_error(client: GetOnlyClient, url: str) -> HttpResponse | WebReconError:
    """Call ``get`` and assert the documented exception contract.

    ``WebReconError`` is the only type allowed to escape. Anything else is the
    bug this helper exists to surface, with the offending type named.
    """
    try:
        return client.get(url)
    except WebReconError as exc:
        return exc
    except BaseException as exc:  # noqa: BLE001 - the assertion is the point
        raise AssertionError(
            f"get({url!r}) raised {type(exc).__module__}.{type(exc).__name__}: {exc}; "
            "only WebReconError may escape GetOnlyClient.get"
        ) from exc


# ===================================================================
# 1. GetOnlyClient against a hostile server
# ===================================================================


@pytest.mark.e2e
def test_connection_refused_is_a_webrecon_error() -> None:
    # Bind and immediately close to get a port nothing is listening on.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    outcome = _get_or_error(_client(), f"http://127.0.0.1:{dead_port}/")
    assert isinstance(outcome, WebReconError)
    assert "Refused" in str(outcome) or "refused" in str(outcome)


@pytest.mark.e2e
def test_accept_then_close_without_response(hostile: _HostileServer) -> None:
    outcome = _get_or_error(_client(), hostile.url("/close"))
    assert isinstance(outcome, WebReconError)


@pytest.mark.e2e
def test_headers_then_hang_hits_the_timeout(hostile: _HostileServer) -> None:
    client = _client()
    started = time.monotonic()
    outcome = _get_or_error(client, hostile.url("/hang"))
    elapsed = time.monotonic() - started
    # The server sleeps 3x the timeout; finishing near the timeout proves the
    # read deadline is enforced rather than the socket blocking indefinitely.
    assert elapsed < TIMEOUT + 0.6, f"blocked for {elapsed:.2f}s with a {TIMEOUT}s timeout"
    # Either a timeout error or a short/empty body is acceptable; a hang is not.
    assert isinstance(outcome, WebReconError) or len(outcome.body) < 4096


@pytest.mark.e2e
def test_body_over_the_cap_is_truncated(hostile: _HostileServer) -> None:
    response = _get_or_error(_client(), hostile.url("/big"))
    assert isinstance(response, HttpResponse)
    assert len(response.body) == CAP, "the byte cap must bound what is held in memory"
    assert response.truncated is True


@pytest.mark.e2e
def test_content_length_larger_than_the_body(hostile: _HostileServer) -> None:
    response = _get_or_error(_client(), hostile.url("/lying-length"))
    assert isinstance(response, HttpResponse)
    assert response.body == b"short"
    assert response.truncated is False


@pytest.mark.e2e
def test_endless_body_is_capped(hostile: _HostileServer) -> None:
    response = _get_or_error(_client(), hostile.url("/endless"))
    assert isinstance(response, HttpResponse)
    assert len(response.body) == CAP
    assert response.truncated is True


@pytest.mark.e2e
@pytest.mark.parametrize("path", ["/r301", "/r302", "/r307", "/r308"])
def test_cross_host_redirects_are_recorded_not_followed(
    hostile: _HostileServer, path: str
) -> None:
    before = len(hostile.seen)
    response = _get_or_error(_client(), hostile.url(path))
    assert isinstance(response, HttpResponse)
    assert response.status in (301, 302, 307, 308)
    assert response.headers["location"] == "http://evil.example.com/landing"
    assert len(hostile.seen) - before == 1, "a redirect must not produce a second request"


@pytest.mark.e2e
def test_self_referential_redirect_loop_returns_once(hostile: _HostileServer) -> None:
    before = len(hostile.seen)
    response = _get_or_error(_client(), hostile.url("/loop"))
    assert isinstance(response, HttpResponse)
    assert response.status == 302
    assert len(hostile.seen) - before == 1


@pytest.mark.e2e
@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_error_statuses_come_back_as_results(hostile: _HostileServer, status: int) -> None:
    response = _get_or_error(_client(), hostile.url(f"/{status}"))
    assert isinstance(response, HttpResponse), "a 4xx/5xx is a result, not a failure"
    assert response.status == status
    assert response.body


@pytest.mark.e2e
@pytest.mark.parametrize(
    "path",
    [
        "/bad-status",
        "/not-http",
        "/no-colon",
        "/dup-headers",
        "/huge-header",
        "/ctl-header-name",
        "/too-many-headers",
    ],
)
def test_malformed_responses_only_raise_webrecon_error(
    hostile: _HostileServer, path: str
) -> None:
    outcome = _get_or_error(_client(), hostile.url(path))
    if isinstance(outcome, HttpResponse):
        assert outcome.text is not None
        assert isinstance(outcome.headers, dict)


@pytest.mark.e2e
def test_duplicate_header_keeps_one_value(hostile: _HostileServer) -> None:
    response = _get_or_error(_client(), hostile.url("/dup-headers"))
    assert isinstance(response, HttpResponse)
    assert response.headers["x-dup"] in ("first", "second")


@pytest.mark.e2e
def test_ten_kilobyte_header_value_is_accepted(hostile: _HostileServer) -> None:
    response = _get_or_error(_client(), hostile.url("/huge-header"))
    assert isinstance(response, HttpResponse)
    assert len(response.headers["x-huge"]) >= 10_240


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("path", "expected_type"),
    [("/no-ct", ""), ("/nonsense-ct", "?!?/\x7f"), ("/lying-ct", "application/json")],
)
def test_content_type_absent_nonsense_or_lying(
    hostile: _HostileServer, path: str, expected_type: str
) -> None:
    response = _get_or_error(_client(), hostile.url(path))
    assert isinstance(response, HttpResponse)
    # content_type is a plain string either way; nothing downstream may assume
    # it is a real media type or that it matches the body.
    assert response.content_type == expected_type.lower()


@pytest.mark.e2e
@pytest.mark.parametrize("path", ["/latin1", "/utf16", "/bom", "/invalid-utf8", "/nulls"])
def test_undecodable_bodies_never_raise_on_text(hostile: _HostileServer, path: str) -> None:
    response = _get_or_error(_client(), hostile.url(path))
    assert isinstance(response, HttpResponse)
    assert isinstance(response.text, str)


@pytest.mark.e2e
def test_unrequested_gzip_encoding_does_not_raise(hostile: _HostileServer) -> None:
    """The client asks for ``identity``; a server may ignore that anyway.

    The body is then compressed bytes. That is allowed to produce nonsense
    text, but it must not raise and must not be mistaken for a decode failure.
    """
    response = _get_or_error(_client(), hostile.url("/gzip"))
    assert isinstance(response, HttpResponse)
    assert response.headers["content-encoding"] == "gzip"
    assert isinstance(response.text, str)
    assert gzip.decompress(response.body).startswith(b"<html>")


@pytest.mark.e2e
def test_tls_request_against_a_cleartext_port(hostile: _HostileServer) -> None:
    outcome = _get_or_error(_client(), hostile.url("/", scheme="https"))
    assert isinstance(outcome, WebReconError)
    assert "SSL" in str(outcome) or "ssl" in str(outcome)


@pytest.mark.e2e
def test_cleartext_request_against_a_tls_port(tls_hostile: _HostileServer) -> None:
    outcome = _get_or_error(_client(), tls_hostile.url("/", scheme="http"))
    assert isinstance(outcome, WebReconError)


@pytest.mark.e2e
def test_the_tls_port_does_answer_over_https(tls_hostile: _HostileServer) -> None:
    """Guards the test above: the failure must be the scheme, not a dead port."""
    response = _get_or_error(_client(), tls_hostile.url("/", scheme="https"))
    assert isinstance(response, HttpResponse)
    assert response.status == 200


@pytest.mark.e2e
def test_the_client_only_ever_sent_get(hostile: _HostileServer) -> None:
    """Audits the verb on every request this module's server has ever seen."""
    client = _client()
    for path in ("/", "/401", "/r302"):
        _get_or_error(client, hostile.url(path))
    assert hostile.seen
    assert {method for method, _ in hostile.seen} == {"GET"}


# ===================================================================
# 2. the rate limiter under concurrency
# ===================================================================


def _hammer(limiter: RateLimiter, calls: int, threads: int) -> tuple[float, set[str]]:
    seen_threads: set[str] = set()
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(calls):
            limiter.wait()
            with lock:
                seen_threads.add(threading.current_thread().name)

    pool = [threading.Thread(target=worker, name=f"hammer-{i}") for i in range(threads)]
    started = time.monotonic()
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join(timeout=5.0)
    elapsed = time.monotonic() - started
    assert not any(t.is_alive() for t in pool), "the rate limiter deadlocked"
    return elapsed, seen_threads


def test_aggregate_rate_is_not_exceeded_across_threads() -> None:
    rate, threads, calls = 100.0, 8, 5
    elapsed, _ = _hammer(RateLimiter(rate), calls, threads)
    total = threads * calls
    observed = total / elapsed
    # One slot is free at t=0, so the floor is (total - 1) intervals.
    assert elapsed >= (total - 1) / rate * 0.95, f"{total} calls in only {elapsed:.3f}s"
    assert observed <= rate * 1.3, f"observed {observed:.1f} rps against a {rate} rps cap"


def test_limiter_does_not_serialise_work_onto_one_thread() -> None:
    _, seen_threads = _hammer(RateLimiter(200.0), calls=4, threads=6)
    assert len(seen_threads) == 6, f"only {sorted(seen_threads)} made progress"


def test_rate_limiter_zero_never_blocks() -> None:
    limiter = RateLimiter(0)
    started = time.monotonic()
    for _ in range(2000):
        limiter.wait()
    assert time.monotonic() - started < 0.25


def test_very_high_rate_does_not_busy_spin() -> None:
    """A tiny interval must still be a sleep, not a spin on the clock."""
    limiter = RateLimiter(20_000.0)  # 50 us apart
    wall_start, cpu_start = time.monotonic(), time.process_time()
    for _ in range(400):
        limiter.wait()
    wall = time.monotonic() - wall_start
    cpu = time.process_time() - cpu_start
    assert wall < 0.6
    assert cpu < max(wall * 0.6, 0.05), f"burned {cpu:.3f}s CPU over {wall:.3f}s wall"


# ===================================================================
# 3. run_parallel
# ===================================================================


def test_run_parallel_preserves_input_order() -> None:
    items = list(range(20))
    assert run_parallel(items, lambda n: n * 2, concurrency=8) == [n * 2 for n in items]


@pytest.mark.parametrize(("count", "concurrency"), [(0, 4), (1, 4), (12, 3), (2, 16)])
def test_run_parallel_handles_every_size_combination(count: int, concurrency: int) -> None:
    items = list(range(count))
    assert run_parallel(items, lambda n: n, concurrency=concurrency) == items


def test_run_parallel_is_fail_fast_and_discards_finished_results() -> None:
    """Documents the real contract: one raising worker loses everything.

    ``run_parallel`` is ``Executor.map`` wrapped in ``list()``, so the first
    exception propagates and every already-computed result is thrown away.
    That is why :func:`netrecon.stages.webrecon.run` wraps its own worker - see
    ``test_one_endpoint_crashing_does_not_erase_the_others``. ``run_parallel``
    lives in ``netrecon/core/``, which this suite does not own, so the
    behaviour is pinned here rather than changed.
    """
    done: list[int] = []
    lock = threading.Lock()

    def worker(n: int) -> int:
        if n == 3:
            raise RuntimeError("worker 3 exploded")
        with lock:
            done.append(n)
        return n

    with pytest.raises(RuntimeError, match="worker 3 exploded"):
        run_parallel(range(8), worker, concurrency=2)
    assert done, "the surviving workers did run"  # their results are still lost


def test_a_slow_worker_does_not_block_the_others_from_starting() -> None:
    # Two parties: the two fast workers must meet while worker 0 is still asleep.
    barrier = threading.Barrier(2)

    def worker(n: int) -> int:
        if n == 0:
            time.sleep(0.3)
        else:
            # Times out and raises BrokenBarrierError if worker 0 holds the pool.
            barrier.wait(timeout=1.0)
        return n

    assert run_parallel(range(3), worker, concurrency=3) == [0, 1, 2]
    barrier.abort()


# ===================================================================
# 4. stage-level scenarios with a fake client
# ===================================================================

Page = tuple[int, str, dict[str, str]]


class TracingClient:
    """A ``GetOnlyClient`` stand-in that records every request it is asked for.

    Only ``get`` exists. Any other method name is an assertion failure, which
    is how "the stage never issues a method other than GET" is enforced at the
    stage level.
    """

    def __init__(self, pages: dict[str, Page], *, default_status: int = 404) -> None:
        self.pages = pages
        self.default_status = default_status
        self.requested: list[str] = []
        self._lock = threading.Lock()

    def get(self, url: str) -> HttpResponse:
        with self._lock:
            self.requested.append(url)
        if url not in self.pages:
            return HttpResponse(url, self.default_status, "Not Found", {}, b"", False, 0.0)
        status, body, headers = self.pages[url]
        return HttpResponse(url, status, "OK", headers, body.encode(), False, 0.001)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the stage must not call client.{name}(); GET only")


class DeadClient:
    def __init__(self) -> None:
        self.requested: list[str] = []

    def get(self, url: str) -> HttpResponse:
        self.requested.append(url)
        raise WebReconError("ConnectionRefusedError: [Errno 111] Connection refused")


def _seed(ctx: Any, ips: dict[str, list[int]]) -> None:
    write_json(
        ctx.paths.open_ports,
        {"hosts": {ip: [{"port": p, "protocol": "tcp"} for p in ports]
                   for ip, ports in ips.items()}},
    )


def _stage_context(make_context: Any, **cfg: Any) -> Any:
    ctx = make_context(web=True)
    ctx.config.webrecon.probe_both_schemes = False
    for key, value in cfg.items():
        setattr(ctx.config.webrecon, key, value)
    return ctx


def _install(monkeypatch: pytest.MonkeyPatch, client: Any) -> Any:
    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: client)
    return client


def assert_requests_stayed_in_scope(requested: list[str], *, allowed: set[str]) -> None:
    """Every URL requested must name an in-scope IP literal and nothing else.

    A hostname would be a finding in itself: the stage is contracted to address
    in-scope hosts by IP literal only, because a name can resolve anywhere.
    """
    for url in requested:
        parts = urlsplit(url)
        assert parts.scheme in {"http", "https"}, url
        host = (parts.hostname or "").strip("[]")
        assert host in allowed, f"requested out-of-scope host {host!r} via {url}"
        ipaddress.ip_address(host)  # raises if the stage used a name instead of a literal


def test_every_endpoint_unreachable_still_produces_a_report(make_context: Any, monkeypatch) -> None:
    ctx = _stage_context(make_context)
    _seed(ctx, {IN_SCOPE: [80, 8080], SECOND_IN_SCOPE: [80]})
    client = _install(monkeypatch, DeadClient())

    result = webrecon.run(ctx)

    assert result.counts["endpoints_probed"] == 3
    assert result.counts["endpoints_reachable"] == 0
    assert result.counts["failures"] == 3
    payload = json.loads(ctx.paths.webrecon.read_text())
    assert len(payload["failures"]) == 3
    # The report must render over a run where nothing answered.
    report_build.build(ctx)
    assert ctx.paths.report.is_file()
    assert ctx.paths.report_html.is_file()
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE, SECOND_IN_SCOPE})


def test_one_good_one_broken_endpoint_do_not_contaminate_each_other(
    make_context: Any, monkeypatch
) -> None:
    ctx = _stage_context(make_context)
    _seed(ctx, {IN_SCOPE: [80], SECOND_IN_SCOPE: [80]})
    good = f"http://{IN_SCOPE}:80"
    broken = f"http://{SECOND_IN_SCOPE}:80"

    class Mixed(TracingClient):
        def get(self, url: str) -> HttpResponse:
            if url.startswith(broken):
                with self._lock:
                    self.requested.append(url)
                raise WebReconError("TimeoutError: timed out")
            return super().get(url)

    client = _install(
        monkeypatch,
        Mixed(
            {
                f"{good}/": (
                    200,
                    '<html><title>Good</title><script src="/app.js"></script></html>',
                    {"server": "nginx/1.18.0"},
                ),
                f"{good}/app.js": (200, 'fetch("/api/good");', {}),
            }
        ),
    )

    webrecon.run(ctx)
    payload = json.loads(ctx.paths.webrecon.read_text())
    by_ip = {entry["ip"]: entry for entry in payload["results"]}

    assert by_ip[IN_SCOPE]["error"] is None
    assert by_ip[IN_SCOPE]["root"]["title"] == "Good"
    assert by_ip[SECOND_IN_SCOPE]["error"] is not None
    assert by_ip[SECOND_IN_SCOPE]["root"] is None
    assert by_ip[SECOND_IN_SCOPE]["scripts"] == []
    assert by_ip[SECOND_IN_SCOPE]["technologies"] == []
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE, SECOND_IN_SCOPE})


def test_the_script_budget_binds_against_a_page_linking_five_hundred_scripts(
    make_context: Any, monkeypatch
) -> None:
    ctx = _stage_context(make_context, max_scripts_per_endpoint=10)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    links = "".join(f'<script src="/s{i}.js"></script>' for i in range(500))
    pages: dict[str, Page] = {f"{base}/": (200, f"<html>{links}</html>", {})}
    for i in range(500):
        pages[f"{base}/s{i}.js"] = (200, f"var x{i} = 1;", {})
    client = _install(monkeypatch, TracingClient(pages))

    webrecon.run(ctx)

    js_requests = [u for u in client.requested if u.endswith(".js")]
    assert len(js_requests) <= 10, f"{len(js_requests)} script fetches against a budget of 10"
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE})


def test_mutually_referencing_scripts_terminate(make_context: Any, monkeypatch) -> None:
    """A self-reference and a two-script cycle are both real infinite-loop risks.

    ``a.js`` points at ``b.js``, ``b.js`` points back at ``a.js``, and ``c.js``
    points at itself. The crawl must visit each exactly once and stop.
    """
    ctx = _stage_context(make_context, max_scripts_per_endpoint=25, crawl_scripts=True)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (
                    200,
                    '<html><script src="/a.js"></script>'
                    '<script src="/c.js"></script></html>',
                    {},
                ),
                f"{base}/a.js": (200, 'require("/b.js"); require("/a.js");', {}),
                f"{base}/b.js": (200, 'require("/a.js"); require("/b.js");', {}),
                f"{base}/c.js": (200, 'require("/c.js");', {}),
            }
        ),
    )

    webrecon.run(ctx)

    js_requests = [u for u in client.requested if u.endswith(".js")]
    assert sorted(js_requests) == [f"{base}/a.js", f"{base}/b.js", f"{base}/c.js"]
    assert len(js_requests) == len(set(js_requests)), "a script was fetched twice"


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("enormous", json.dumps({"sources": ["big.js"], "sourcesContent": ["x = 1;" * 40_000]})),
        ("not-a-list", json.dumps({"sources": ["a.js"], "sourcesContent": "not a list"})),
        ("nulls", json.dumps({"sources": ["a.js", "b.js"], "sourcesContent": [None, "y = 2;"]})),
        ("sources-missing", json.dumps({"sources": ["a.js", "b.js"]})),
        ("sources-is-a-dict", json.dumps({"sources": {"0": "a.js"}, "sourcesContent": ["z = 3;"]})),
        ("sources-shorter", json.dumps({"sources": [], "sourcesContent": ["q = 4;", "r = 5;"]})),
        ("not-json", "<html>this is not a source map</html>"),
    ],
    ids=lambda value: value if isinstance(value, str) and len(value) < 24 else "",
)
def test_hostile_source_maps_do_not_crash_the_stage(
    make_context: Any, monkeypatch, name: str, payload: str
) -> None:
    ctx = _stage_context(make_context, fetch_source_maps=True)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (200, '<html><script src="/app.js"></script></html>', {}),
                f"{base}/app.js": (200, "var a=1;\n//# sourceMappingURL=app.js.map", {}),
                f"{base}/app.js.map": (200, payload, {"content-type": "application/json"}),
            }
        ),
    )

    result = webrecon.run(ctx)

    assert f"{base}/app.js.map" in client.requested, f"{name}: the map was never fetched"
    assert result.counts["endpoints_reachable"] == 1
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE})


def test_ten_thousand_robots_rules_hit_the_published_path_cap(
    make_context: Any, monkeypatch
) -> None:
    ctx = _stage_context(make_context, follow_published_paths=True, hidden_paths=False)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    robots = "User-agent: *\n" + "".join(f"Disallow: /secret{i}\n" for i in range(10_000))
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (200, "<html></html>", {}),
                f"{base}/robots.txt": (200, robots, {}),
            }
        ),
    )

    webrecon.run(ctx)

    probed = [u for u in client.requested if "/secret" in u]
    assert 0 < len(probed) <= 60, f"{len(probed)} published paths requested; the cap is 60"


def test_a_sitemap_listing_another_host_is_not_requested(make_context: Any, monkeypatch) -> None:
    ctx = _stage_context(make_context, follow_published_paths=True)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    sitemap = (
        "<urlset>"
        f"<url><loc>http://{IN_SCOPE}:80/mine</loc></url>"
        f"<url><loc>http://{OUT_OF_SCOPE}/theirs</loc></url>"
        "<url><loc>https://evil.example.com/theirs-too</loc></url>"
        "<url><loc>//evil.example.com/scheme-relative</loc></url>"
        f"<url><loc>http://{IN_SCOPE}:9999/other-port</loc></url>"
        "</urlset>"
    )
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (200, "<html></html>", {}),
                f"{base}/sitemap.xml": (200, sitemap, {}),
            }
        ),
    )

    webrecon.run(ctx)

    assert f"{base}/mine" in client.requested
    for marker in ("theirs", "theirs-too", "scheme-relative", "other-port"):
        assert not any(marker in url for url in client.requested), marker
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE})
    assert all(":80/" in url or url.endswith(":80") for url in client.requested)


def test_a_script_on_another_port_of_the_same_ip_is_not_fetched(
    make_context: Any, monkeypatch
) -> None:
    ctx = _stage_context(make_context)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (
                    200,
                    "<html>"
                    f'<script src="http://{IN_SCOPE}:9999/other.js"></script>'
                    f'<script src="https://{IN_SCOPE}:80/tls.js"></script>'
                    '<script src="https://cdn.example.com/x.js"></script>'
                    '<script src="/same.js"></script>'
                    "</html>",
                    {},
                ),
                f"{base}/same.js": (200, "var ok = 1;", {}),
            }
        ),
    )

    webrecon.run(ctx)

    assert f"{base}/same.js" in client.requested
    assert not any(":9999" in url for url in client.requested)
    # Same IP and port, different scheme: still a different endpoint.
    assert not any(url.startswith("https://") for url in client.requested)
    assert not any("cdn.example.com" in url for url in client.requested)


def test_hidden_path_probing_when_everything_404s(make_context: Any, monkeypatch) -> None:
    ctx = _stage_context(make_context, hidden_paths=True, max_hidden_paths=40)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    client = _install(monkeypatch, TracingClient({f"{base}/": (200, "<html></html>", {})}))

    result = webrecon.run(ctx)

    assert result.counts["paths_accessible"] == 0
    payload = json.loads(ctx.paths.webrecon.read_text())
    assert payload["results"][0]["hidden_paths"] == []
    assert payload["high_value_paths"] == []
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE})


def test_a_target_chosen_path_cannot_name_a_directory(make_context: Any, monkeypatch) -> None:
    """``Disallow: /..`` used to crash the whole stage.

    The saved-body filename is derived from a path the *target* published.
    ``..`` and ``.`` survive the character substitution unchanged, so
    ``write_bytes`` hit the parent directory and raised IsADirectoryError.
    """
    ctx = _stage_context(make_context, follow_published_paths=True)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    robots = "User-agent: *\nDisallow: /..\nDisallow: /.\nDisallow: /../\nDisallow: /ok\n"
    pages: dict[str, Page] = {
        f"{base}/": (200, "<html></html>", {}),
        f"{base}/robots.txt": (200, robots, {}),
    }
    for path in ("/..", "/.", "/../", "/ok"):
        pages[f"{base}{path}"] = (200, "body", {"content-type": "text/html"})
    client = _install(monkeypatch, TracingClient(pages))

    result = webrecon.run(ctx)

    assert result.counts["endpoints_reachable"] == 1
    assert result.counts["failures"] == 0
    accessible = json.loads(ctx.paths.webrecon.read_text())["results"][0]["hidden_paths"]
    assert {entry["path"] for entry in accessible} >= {"/..", "/ok"}
    assert_requests_stayed_in_scope(client.requested, allowed={IN_SCOPE})


def test_one_endpoint_crashing_does_not_erase_the_others(make_context: Any, monkeypatch) -> None:
    """``run_parallel`` is fail-fast, so the stage must contain its own failures.

    Without the per-endpoint guard in ``webrecon.run``, an unexpected exception
    from one hostile endpoint propagates out of ``Executor.map`` and discards
    every other endpoint's finished results - and the stage writes nothing.
    """
    ctx = _stage_context(make_context)
    _seed(ctx, {IN_SCOPE: [80], SECOND_IN_SCOPE: [80]})
    good = f"http://{IN_SCOPE}:80"

    class Exploding(TracingClient):
        def get(self, url: str) -> HttpResponse:
            if url.startswith(f"http://{SECOND_IN_SCOPE}:"):
                raise MemoryError("something unforeseen")
            return super().get(url)

    _install(monkeypatch, Exploding({f"{good}/": (200, "<html><title>Fine</title></html>", {})}))

    result = webrecon.run(ctx)

    assert result.counts["endpoints_reachable"] == 1
    assert result.counts["failures"] == 1
    payload = json.loads(ctx.paths.webrecon.read_text())
    by_ip = {entry["ip"]: entry for entry in payload["results"]}
    assert by_ip[IN_SCOPE]["root"]["title"] == "Fine"
    assert "MemoryError" in by_ip[SECOND_IN_SCOPE]["error"]


# ===================================================================
# 5. invariants that hold whatever the server does
# ===================================================================


def test_get_only_client_exposes_no_other_verb() -> None:
    for verb in ("post", "put", "delete", "head", "patch", "options", "request", "open"):
        assert not hasattr(GetOnlyClient, verb), f"GetOnlyClient.{verb} must not exist"


def test_out_of_scope_endpoint_is_refused_before_the_socket(
    make_context: Any, monkeypatch
) -> None:
    ctx = _stage_context(make_context)
    _seed(ctx, {IN_SCOPE: [80]})
    client = _install(monkeypatch, TracingClient({}))
    # An endpoint smuggled past discovery still has to clear enforce_strict.
    monkeypatch.setattr(
        webrecon,
        "load_endpoints",
        lambda _ctx: [Endpoint(ip=OUT_OF_SCOPE, port=80, scheme="http")],
    )

    result = webrecon.run(ctx)

    assert client.requested == [], "a scope violation must happen before any request"
    assert result.counts["failures"] == 1


def test_a_scanned_hosts_response_body_never_reaches_the_log(
    make_context: Any, monkeypatch, caplog: pytest.LogCaptureFixture
) -> None:
    marker = "CANARY_7f3a9b_SHOULD_NOT_BE_LOGGED"
    ctx = _stage_context(make_context, hidden_paths=True, max_hidden_paths=5)
    _seed(ctx, {IN_SCOPE: [80]})
    base = f"http://{IN_SCOPE}:80"
    client = _install(
        monkeypatch,
        TracingClient(
            {
                f"{base}/": (
                    200,
                    f"<html><title>{marker}</title><!-- {marker} -->"
                    f'<script>var k = "{marker}";</script>'
                    '<script src="/app.js"></script></html>',
                    {"server": f"nginx {marker}"},
                ),
                f"{base}/app.js": (200, f'fetch("/api/{marker}");', {}),
                f"{base}/robots.txt": (200, f"Disallow: /{marker}\n", {}),
                f"{base}/.git/HEAD": (200, f"ref: {marker}\n", {}),
            }
        ),
    )

    with caplog.at_level(logging.DEBUG):
        webrecon.run(ctx)

    offenders = [r.getMessage() for r in caplog.records if marker in r.getMessage()]
    assert offenders == [], f"response content reached the log: {offenders}"
    # Sanity: the body really was fetched and analysed, so the check had teeth.
    assert f"{base}/app.js" in client.requested
    assert marker in (ctx.paths.webrecon.read_text())


def test_every_fake_client_scenario_only_used_in_scope_hosts() -> None:
    """A guard on the guard: the shared assertion must actually reject a miss."""
    with pytest.raises(AssertionError, match="out-of-scope"):
        assert_requests_stayed_in_scope(
            [f"http://{OUT_OF_SCOPE}:80/"], allowed={IN_SCOPE}
        )
