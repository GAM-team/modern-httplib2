"""Tests for modern httpx/httpcore features in httplib2:
- httpx/httpcore connection & pool backend verification
- Connection keep-alive reuse
- Thread-safe concurrent requests on a single shared Http() instance
- Native HTTP/2 negotiation and stream multiplexing over TLS (ALPN 'h2')
- google-auth-httplib2 AuthorizedHttp drop-in compatibility
"""

from concurrent.futures import ThreadPoolExecutor
import contextlib
import socket
import threading

import h2.config
import h2.connection
import h2.events
import httpcore
import httpx

import httplib2
import tests


def test_httpx_httpcore_backend_inspection():
    http = httplib2.Http(timeout=5)
    with tests.server_const_http(body=b"modern-transport") as uri:
        resp, content = http.request(uri)
        assert resp.status == 200
        assert content == b"modern-transport"

        assert len(http.connections) == 1
        conn_wrapper = next(iter(http.connections.values()))
        assert isinstance(conn_wrapper, httplib2.HTTPConnectionWithTimeout)
        assert isinstance(conn_wrapper.httpcore_pool, httpcore.ConnectionPool)
        assert len(conn_wrapper.httpcore_pool.connections) == 1
        assert httpx.__version__
    http.close()


def test_keep_alive_connection_reuse():
    http = httplib2.Http(timeout=5)
    request_numbers = []

    def handler(request):
        request_numbers.append(request.number)
        return tests.http_response_bytes(body=f"req-{request.number}".encode("ascii"))

    with tests.server_request(handler, request_count=3) as uri:
        for expected in (1, 2, 3):
            resp, content = http.request(uri)
            assert resp.status == 200
            assert content == f"req-{expected}".encode("ascii")

    # All 3 requests should have been served on the exact same TCP connection
    assert request_numbers == [1, 2, 3]
    http.close()


@contextlib.contextmanager
def _threaded_keepalive_server(request_handler, total_requests, timeout=5):
    """Multi-threaded socket server that handles concurrent keep-alive connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("localhost", 0))
    srv.listen(32)
    srv.settimeout(timeout)
    port = srv.getsockname()[1]

    counter_lock = threading.Lock()
    handled = [0]
    done_event = threading.Event()
    client_threads = []

    def handle_client(client_sock):
        client_sock.settimeout(timeout)
        buf = tests.BufferedReader(client_sock)
        i = 0
        try:
            while not done_event.is_set():
                req = tests.HttpRequest.from_buffered(buf)
                if req is None:
                    break
                i += 1
                req.number = i
                resp_bytes = request_handler(req)
                client_sock.sendall(resp_bytes)
                with counter_lock:
                    handled[0] += 1
                    if handled[0] >= total_requests:
                        done_event.set()
                        break
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    def accept_loop():
        while not done_event.is_set():
            try:
                client_sock, _ = srv.accept()
            except OSError:
                break
            ct = threading.Thread(target=handle_client, args=(client_sock,), daemon=True)
            ct.start()
            client_threads.append(ct)

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()
    try:
        yield f"http://localhost:{port}/"
        done_event.wait(timeout=timeout)
    finally:
        done_event.set()
        try:
            srv.close()
        except OSError:
            pass
        accept_thread.join(timeout=2)
        for ct in client_threads:
            ct.join(timeout=1)


def test_thread_safe_concurrent_requests_shared_http():
    num_threads = 8
    requests_per_thread = 4
    total_requests = num_threads * requests_per_thread
    http = httplib2.Http(timeout=5, pool_maxsize=num_threads)
    barrier = threading.Barrier(num_threads)

    def handler(request):
        return tests.http_response_bytes(
            headers={"x-echo-uri": request.uri},
            body=f"body:{request.uri}".encode("utf-8"),
        )

    with _threaded_keepalive_server(handler, total_requests=total_requests, timeout=5) as base_uri:
        def worker(tid):
            barrier.wait(timeout=5)
            results = []
            for seq in range(requests_per_thread):
                path = f"/thread-{tid}/req-{seq}"
                target = base_uri.rstrip("/") + path
                resp, content = http.request(target)
                results.append((path, resp.status, resp.get("x-echo-uri"), content))
            return results

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, tid) for tid in range(num_threads)]
            for fut in futures:
                for path, status, echo_uri, content in fut.result(timeout=5):
                    assert status == 200
                    assert echo_uri == path
                    assert content == f"body:{path}".encode("utf-8")
        http.close()


def _make_h2_tls_wrapper(ssl_context, server_sock, tls_skip_errors):
    ssl_context.set_alpn_protocols(["h2", "http/1.1"])
    return ssl_context.wrap_socket(server_sock, server_side=True)


def test_http2_negotiation_over_tls():
    received_headers = {}
    received_body = bytearray()

    def h2_server_handler(client_sock, tick):
        assert client_sock.selected_alpn_protocol() == "h2"
        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2_conn = h2.connection.H2Connection(config=config)
        h2_conn.initiate_connection()
        client_sock.sendall(h2_conn.data_to_send())

        stream_ended = False
        while not stream_ended:
            data = client_sock.recv(65535)
            if not data:
                break
            events = h2_conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    for k, v in event.headers:
                        received_headers[k] = v
                elif isinstance(event, h2.events.DataReceived):
                    received_body.extend(event.data)
                    h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    response_body = b"hello-over-http2"
                    h2_conn.send_headers(
                        stream_id=event.stream_id,
                        headers=[
                            (":status", "200"),
                            ("content-type", "text/plain"),
                            ("content-length", str(len(response_body))),
                            ("x-protocol", "h2"),
                        ],
                    )
                    h2_conn.send_data(
                        stream_id=event.stream_id,
                        data=response_body,
                        end_stream=True,
                    )
                    stream_ended = True
            out = h2_conn.data_to_send()
            if out:
                client_sock.sendall(out)
        tick(None)

    with tests.server_socket(h2_server_handler, request_count=1, tls=_make_h2_tls_wrapper) as uri:
        http = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS, enable_http2=True)
        resp, content = http.request(
            uri + "h2-endpoint",
            method="POST",
            body=b"ping-h2",
            headers={"X-Custom-Header": "modern"},
        )
        assert resp.status == 200
        assert resp.version == 20
        assert resp["x-protocol"] == "h2"
        assert content == b"hello-over-http2"
        assert received_headers.get(":path") == "/h2-endpoint"
        assert received_headers.get(":method") == "POST"
        assert received_headers.get("x-custom-header") == "modern"
        assert bytes(received_body) == b"ping-h2"
        http.close()


def test_http2_can_be_disabled():
    alpn_selected = []

    def h1_fallback_handler(client_sock, tick):
        alpn_selected.append(client_sock.selected_alpn_protocol())
        buf = tests.BufferedReader(client_sock)
        req = tests.HttpRequest.from_buffered(buf)
        client_sock.sendall(tests.http_response_bytes(body=b"http11-fallback"))
        tick(req)

    with tests.server_socket(h1_fallback_handler, request_count=1, tls=_make_h2_tls_wrapper) as uri:
        http = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS, enable_http2=False)
        resp, content = http.request(uri)
        assert resp.status == 200
        assert resp.version == 11
        assert content == b"http11-fallback"
        assert alpn_selected in ([None], ["http/1.1"])
        http.close()


def test_google_auth_httplib2_authorized_http_integration():
    import google.auth.credentials
    import google_auth_httplib2

    class MockGoogleCredentials(google.auth.credentials.Credentials):
        def __init__(self):
            super().__init__()
            self.token = "initial-access-token"
            self.refresh_count = 0

        def refresh(self, request):
            self.refresh_count += 1
            self.token = f"refreshed-access-token-{self.refresh_count}"

    creds = MockGoogleCredentials()
    seen_auth_headers = []

    def auth_server(request):
        auth_hdr = request.headers.get("authorization")
        seen_auth_headers.append(auth_hdr)
        if len(seen_auth_headers) == 1:
            # Trigger token refresh on first request with 401 Unauthorized
            return tests.http_response_bytes(status="401 Unauthorized", body=b"expired")
        return tests.http_response_bytes(status="200 OK", body=b"authenticated-payload")

    with tests.server_request(auth_server, request_count=2) as uri:
        authed_http = google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http(timeout=5))
        resp, content = authed_http.request(uri)
        assert resp.status == 200
        assert content == b"authenticated-payload"
        assert creds.refresh_count == 1
        assert seen_auth_headers == [
            "Bearer initial-access-token",
            "Bearer refreshed-access-token-1",
        ]


def test_attribution_and_python_version_metadata():
    import importlib
    import sys

    iri2uri_mod = importlib.import_module("httplib2.iri2uri")
    assert sys.version_info >= (3, 11)
    assert httplib2.__author__ == "Jay Lee"
    assert httplib2.__contributors__ == ["Jay Lee"]
    assert "Jay Lee" in httplib2.__copyright__
    assert httplib2.__version__.startswith("1.32.")
    assert iri2uri_mod.__author__ == "Jay Lee"
    assert iri2uri_mod.__contributors__ == ["Jay Lee"]



def test_alt_svc_header_preserves_keepalive_connection():
    """Verify that `Alt-Svc: h3=":443"` headers (sent by Google APIs & Cloudflare)
    preserve the pooled TCP/TLS connection across sequential requests.
    """
    http = httplib2.Http(timeout=5)
    request_numbers = []

    def handler(request):
        request_numbers.append(request.number)
        return tests.http_response_bytes(
            headers={"Alt-Svc": 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000'},
            body=f"alt-svc-req-{request.number}".encode("ascii"),
        )

    with tests.server_request(handler, request_count=3) as uri:
        for expected in (1, 2, 3):
            resp, content = http.request(uri)
            assert resp.status == 200
            assert content == f"alt-svc-req-{expected}".encode("ascii")

        conn_wrapper = next(iter(http.connections.values()))
        assert len(conn_wrapper.httpcore_pool.connections) == 1
        http.close()

    assert request_numbers == [1, 2, 3]


def test_http2_concurrent_multiplexing_single_connection():
    """Verify that concurrent threads on a fresh Http() instance multiplex over a
    SINGLE HTTP/2 TCP+TLS connection (GAM multi-threaded fan-out pattern).
    """
    num_streams = 8
    seen_stream_ids = set()
    req_paths = {}

    def h2_multiplex_server(client_sock, tick):
        assert client_sock.selected_alpn_protocol() == "h2"
        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2_conn = h2.connection.H2Connection(config=config)
        h2_conn.initiate_connection()
        client_sock.sendall(h2_conn.data_to_send())

        completed = 0
        while completed < num_streams:
            data = client_sock.recv(65535)
            if not data:
                break
            events = h2_conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    hdrs = dict(event.headers)
                    req_paths[event.stream_id] = hdrs.get(":path", "")
                    seen_stream_ids.add(event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    body = f"stream:{event.stream_id}:{req_paths.get(event.stream_id, '')}".encode("utf-8")
                    h2_conn.send_headers(
                        stream_id=event.stream_id,
                        headers=[
                            (":status", "200"),
                            ("content-length", str(len(body))),
                            ("x-stream-id", str(event.stream_id)),
                        ],
                    )
                    h2_conn.send_data(
                        stream_id=event.stream_id,
                        data=body,
                        end_stream=True,
                    )
                    completed += 1
            out = h2_conn.data_to_send()
            if out:
                client_sock.sendall(out)
        tick(None)

    with tests.server_socket(h2_multiplex_server, request_count=1, tls=_make_h2_tls_wrapper) as uri:
        http = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS, enable_http2=True)
        barrier = threading.Barrier(num_streams)

        def worker(idx):
            barrier.wait(timeout=5)
            path = f"/gam-item-{idx}"
            resp, content = http.request(uri.rstrip("/") + path)
            return path, resp.status, resp.version, resp.get("x-stream-id"), content

        with ThreadPoolExecutor(max_workers=num_streams) as pool:
            futures = [pool.submit(worker, i) for i in range(num_streams)]
            for fut in futures:
                path, status, version, stream_id, content = fut.result(timeout=5)
                assert status == 200
                assert version == 20
                assert content == f"stream:{stream_id}:{path}".encode("utf-8")

        conn_wrapper = next(iter(http.connections.values()))
        # All 8 concurrent threads shared a SINGLE HTTP/2 connection!
        assert len(conn_wrapper.httpcore_pool.connections) == 1
        assert len(seen_stream_ids) == num_streams
        http.close()


def test_debuglevel_logging(capsys):
    def server_handler(client_sock, tick):
        buf = tests.BufferedReader(client_sock)
        req = tests.HttpRequest.from_buffered(buf)
        client_sock.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n\r\n"
            b"hello"
        )
        tick(req)

    old_debuglevel = httplib2.debuglevel
    try:
        httplib2.debuglevel = 1
        with tests.server_socket(server_handler, request_count=1) as uri:
            http = httplib2.Http(timeout=5)
            resp, content = http.request(uri + "debug-test", method="GET", headers={"X-Test": "1"})
            assert resp.status == 200
            assert content == b"hello"
            http.close()

        captured = capsys.readouterr().out
        assert "connect: (" in captured
        assert "send: b'GET /debug-test HTTP/1.1" in captured
        assert "reply: 'HTTP/1.1 200 OK" in captured
        assert "header: Content-Type: text/plain" in captured
    finally:
        httplib2.debuglevel = old_debuglevel


def test_debug_redaction_custom_printer(capsys):
    import http.client
    import re

    def server_handler(client_sock, tick):
        buf = tests.BufferedReader(client_sock)
        req = tests.HttpRequest.from_buffered(buf)
        client_sock.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Set-Cookie: session=ya29.TOPSECRET\r\n"
            b"Content-Length: 2\r\n\r\n"
            b"ok"
        )
        tick(req)

    patterns = [
        (r"(Bearer\s+)\S+", r"\1*****"),
        (r"ya29\.[0-9A-Za-z-_]+", "*****"),
    ]

    def mock_gam_redact_print(*args):
        processed = []
        for arg in args:
            if arg.startswith("b'"):
                sbytes = arg[2:-1].encode("utf-8")
                arg = sbytes.decode().replace(r"\r\n", "\n          ")
            for pat, repl in patterns:
                arg = re.sub(pat, repl, arg)
            processed.append(arg)
        print(*processed)

    old_print = getattr(http.client, "print", None)
    old_debuglevel = httplib2.debuglevel
    try:
        http.client.print = mock_gam_redact_print
        httplib2.debuglevel = 1
        with tests.server_socket(server_handler, request_count=1) as uri:
            http_obj = httplib2.Http(timeout=5)
            resp, content = http_obj.request(
                uri + "users?key=ya29.QUERYSECRET",
                method="POST",
                headers={"Authorization": "Bearer ya29.HEADERSECRET"},
                body=b"{\"token\": \"ya29.BODYSECRET\"}",
            )
            assert resp.status == 200
            http_obj.close()

            # Verify non-string args (like integer stream IDs) are safely converted and do not crash .startswith()
            httplib2.debug_print("stream:", 1)
            httplib2.debug_print("status_code:", 200, True)

        captured = capsys.readouterr().out
        assert "stream: 1" in captured
        assert "status_code: 200 True" in captured
        assert "Bearer *****" in captured
        assert "ya29." not in captured
        assert "*****" in captured
    finally:
        httplib2.debuglevel = old_debuglevel
        if old_print is None:
            if hasattr(http.client, "print"):
                del http.client.print
        else:
            http.client.print = old_print


def test_force_http11_global_toggle():
    """Verify global force_http11() and enable_http2() toggles affect subsequent connections."""
    try:
        httplib2.force_http11()
        assert httplib2.ENABLE_HTTP2 is False
        assert httplib2.Http.enable_http2 is False

        http_obj = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS)
        assert http_obj.enable_http2 is False

        alpn_selected = []

        def h1_server_handler(client_sock, tick):
            alpn_selected.append(client_sock.selected_alpn_protocol())
            buf = tests.BufferedReader(client_sock)
            req = tests.HttpRequest.from_buffered(buf)
            client_sock.sendall(tests.http_response_bytes(body=b"global-h1-only"))
            tick(req)

        with tests.server_socket(h1_server_handler, request_count=1, tls=_make_h2_tls_wrapper) as uri:
            resp, content = http_obj.request(uri)
            assert resp.status == 200
            assert resp.version == 11
            assert content == b"global-h1-only"
            assert alpn_selected == ["http/1.1"]
            http_obj.close()
    finally:
        httplib2.enable_http2()
        assert httplib2.ENABLE_HTTP2 is True


def test_http_instance_force_http11():
    """Verify http_obj.force_http11() downgrades active and future connections on that instance."""
    alpn_selected = []

    def h1_server_handler(client_sock, tick):
        alpn_selected.append(client_sock.selected_alpn_protocol())
        buf = tests.BufferedReader(client_sock)
        req = tests.HttpRequest.from_buffered(buf)
        client_sock.sendall(tests.http_response_bytes(body=b"instance-forced-h1"))
        tick(req)

    with tests.server_socket(h1_server_handler, request_count=1, tls=_make_h2_tls_wrapper) as uri:
        http_obj = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS)
        assert http_obj.enable_http2 is True

        http_obj.force_http11()
        assert http_obj.enable_http2 is False

        resp, content = http_obj.request(uri)
        assert resp.status == 200
        assert resp.version == 11
        assert content == b"instance-forced-h1"
        assert alpn_selected == ["http/1.1"]
        http_obj.close()


def test_conn_downgrade_to_http1_method():
    """Verify HTTPSConnectionWithTimeout.downgrade_to_http1() reconfigures pool to HTTP/1.1."""
    conn = httplib2.HTTPSConnectionWithTimeout("127.0.0.1", port=443, ca_certs=tests.CA_CERTS)
    assert conn.enable_http2 is True
    assert conn.httpcore_pool._http2 is True

    conn.downgrade_to_http1()
    assert conn.enable_http2 is False
    assert conn.httpcore_pool._http2 is False
    conn.close()


def test_auto_downgrade_on_http2_failure(capsys):
    """Verify automatic downgrade to HTTP/1.1 when an HTTP/2 connection fails (e.g. corporate firewall reset)."""
    connection_attempts = []

    def server_handler(client_sock, tick):
        alpn = client_sock.selected_alpn_protocol()
        connection_attempts.append(alpn)
        if alpn == "h2":
            # Simulate firewall/proxy terminating the connection on HTTP/2 preface/stream
            client_sock.close()
            tick(None)
            return

        # On HTTP/1.1 fallback, serve the request successfully
        buf = tests.BufferedReader(client_sock)
        req = tests.HttpRequest.from_buffered(buf)
        client_sock.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 16\r\n\r\n"
            b"auto-fallback-ok"
        )
        tick(req)

    old_debuglevel = httplib2.debuglevel
    try:
        httplib2.debuglevel = 1
        httplib2.reset_downgraded_hosts()

        with tests.server_socket(server_handler, request_count=2, tls=_make_h2_tls_wrapper) as uri:
            http_obj = httplib2.Http(timeout=5, ca_certs=tests.CA_CERTS, auto_downgrade_http2=True)

            # First request: starts with h2, fails, auto-downgrades to HTTP/1.1 and succeeds!
            resp, content = http_obj.request(uri + "api-endpoint")
            assert resp.status == 200
            assert resp.version == 11
            assert content == b"auto-fallback-ok"

            # Check debug logging reported auto-downgrade
            captured = capsys.readouterr().out
            assert "auto-downgrade: HTTP/2 failed for" in captured
            assert "falling back to HTTP/1.1 and retrying" in captured

            # Verify the two connections: first was h2, second was http/1.1
            assert connection_attempts == ["h2", "http/1.1"]

            http_obj.close()
    finally:
        httplib2.debuglevel = old_debuglevel
        httplib2.reset_downgraded_hosts()


def test_auto_downgrade_http2_module_level_helpers():
    try:
        httplib2.auto_downgrade_http2(True)
        assert httplib2.AUTO_DOWNGRADE_HTTP2 is True
        assert httplib2.Http.auto_downgrade_http2 is True

        httplib2.set_auto_downgrade_http2(False)
        assert httplib2.AUTO_DOWNGRADE_HTTP2 is False
        assert httplib2.Http.auto_downgrade_http2 is False
    finally:
        httplib2.set_auto_downgrade_http2(True)


def test_lazy_imports_compatibility():
    """Verify that importing modern_httplib2 is safe even when sys.set_lazy_imports('all') is active."""
    import sys
    import importlib
    if hasattr(sys, "set_lazy_imports"):
        orig_mode = sys.get_lazy_imports() if hasattr(sys, "get_lazy_imports") else "none"
        try:
            sys.set_lazy_imports("all")
            import modern_httplib2
            importlib.reload(modern_httplib2)
            assert modern_httplib2.__version__.startswith("1.32.")
        finally:
            sys.set_lazy_imports(orig_mode)



