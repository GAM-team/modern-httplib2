"""Security audit regression and hardening tests for modern-httplib2.

Covers historical vulnerability classes across httplib2, urllib3, requests, and httpx:
- TLS certificate, hostname, IP SAN, and TLS version policy enforcement
- Stale TLS connection invalidation when Http security attributes change
- Pre-connected TLS stream hostname validation
- CRLF, null-byte, whitespace, and control-character injection in URLs, methods, and headers (CVE-2020-13936)
- HTTP/2 pseudo-header injection (:authority, :path, :method, :scheme)
- Redirect security: Authorization stripping on cross-origin and HTTPS->HTTP downgrade,
  Cookie/Host stripping on cross-origin redirects, and Content-Length/Content-Type/Transfer-Encoding
  removal on 302/303 POST->GET redirects (CVE-2014-1829, CVE-2018-20060, CVE-2023-45803)
- Decompression bomb protection (DecodeRatioError / DecodeLimitError) and empty payload edge cases
- WWW-Authenticate ReDoS resilience (CVE-2021-21240)
- FileCache key sanitization against path traversal
"""

import contextlib
import http.client
import os
import socket
import ssl
import threading
import time
import urllib.parse
import zlib

import h2.config
import h2.connection
import h2.events
import pytest

import httplib2
from modern_httplib2.decode import DecodeLimitError, DecodeRatioError, ZlibDecoder, LimitDecoder
import tests


import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@contextlib.contextmanager
def _h2_tls_server(max_tls_version=None, certfile=None, keyfile=None):
    """Minimal TLS + HTTP/2 server that records request headers and responds 200 OK."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(
        certfile=certfile or tests.SERVER_CHAIN,
        keyfile=keyfile or tests.SERVER_PEM,
    )
    server_ctx.set_alpn_protocols(["h2", "http/1.1"])
    if max_tls_version is not None:
        server_ctx.maximum_version = max_tls_version

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("localhost", 0))
    srv_sock.listen(5)
    port = srv_sock.getsockname()[1]
    stop_event = threading.Event()
    received_headers = []

    def handle_client(raw_conn):
        try:
            tls_conn = server_ctx.wrap_socket(raw_conn, server_side=True)
            negotiated = tls_conn.selected_alpn_protocol()
            if negotiated == "h2":
                config = h2.config.H2Configuration(client_side=False)
                h2_conn = h2.connection.H2Connection(config=config)
                h2_conn.initiate_connection()
                tls_conn.sendall(h2_conn.data_to_send())
                while not stop_event.is_set():
                    data = tls_conn.recv(65535)
                    if not data:
                        break
                    events = h2_conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.RequestReceived):
                            received_headers.append(dict(event.headers))
                            h2_conn.send_headers(
                                event.stream_id,
                                [(":status", "200"), ("content-length", "2")],
                            )
                            h2_conn.send_data(event.stream_id, b"ok", end_stream=True)
                    out = h2_conn.data_to_send()
                    if out:
                        tls_conn.sendall(out)
            else:
                data = tls_conn.recv(65535)
                if data:
                    tls_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                raw_conn.close()

    def serve():
        srv_sock.settimeout(0.2)
        while not stop_event.is_set():
            try:
                client, _ = srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{port}/", port, received_headers
    finally:
        stop_event.set()
        srv_sock.close()
        thread.join(timeout=2.0)


def _generate_ca_and_localhost_cert(tmp_path, name):
    """Generate an isolated Root CA and a localhost leaf certificate signed by that CA."""
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Test Root CA {name}")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf_ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(leaf_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem_bytes = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_key_bytes = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    ca_file = tmp_path / f"{name}_ca.pem"
    server_cert_file = tmp_path / f"{name}_server_cert.pem"
    server_key_file = tmp_path / f"{name}_server_key.pem"

    ca_file.write_bytes(ca_pem_bytes)
    server_cert_file.write_bytes(leaf_pem_bytes + ca_pem_bytes)
    server_key_file.write_bytes(leaf_key_bytes)

    return ca_file, server_cert_file, server_key_file, ca_pem_bytes


# ---------------------------------------------------------------------------
# 1. TLS & Certificate Verification Security Tests
# ---------------------------------------------------------------------------


def test_custom_ca_list_replaces_default_ca_store_entirely():
    """Passing a custom ca_certs file must load ONLY the CAs in that file into the SSLContext,
    without merging the default certifi/cacerts.txt bundle or OS system roots.
    """
    default_conn = httplib2.HTTPSConnectionWithTimeout("localhost")
    default_ca_list = default_conn._context.get_ca_certs()
    assert len(default_ca_list) > 50

    custom_conn = httplib2.HTTPSConnectionWithTimeout("localhost", ca_certs=tests.CA_CERTS)
    custom_ca_list = custom_conn._context.get_ca_certs()
    assert len(custom_ca_list) == 1


def test_custom_ca_list_trusts_included_ca_and_rejects_excluded_ca(tmp_path, monkeypatch):
    """When a shorter custom CA list is passed (like GAM's cacerts.pem), CAs in the custom list
    must be trusted, and CAs NOT in the custom list must be rejected EVEN IF they exist in
    modern-httplib2's default CA bundle.
    """
    ca1_file, srv1_cert, srv1_key, ca1_bytes = _generate_ca_and_localhost_cert(tmp_path, "included")
    ca2_file, srv2_cert, srv2_key, ca2_bytes = _generate_ca_and_localhost_cert(tmp_path, "excluded")

    # Simulate default bundle containing BOTH CA 1 and CA 2
    full_default_bundle = tmp_path / "full_default_cacerts.pem"
    full_default_bundle.write_bytes(ca1_bytes + b"\n" + ca2_bytes)
    monkeypatch.setattr(httplib2, "CA_CERTS", str(full_default_bundle))

    # Custom shorter CA list (like GAM's cacerts.pem) contains ONLY CA 1
    gam_short_ca_bundle = str(ca1_file)

    with (
        _h2_tls_server(certfile=str(srv1_cert), keyfile=str(srv1_key)) as (uri_srv1, _, _),
        _h2_tls_server(certfile=str(srv2_cert), keyfile=str(srv2_key)) as (uri_srv2, _, _),
    ):
        # 1. Default Http() (no custom ca_certs) uses full_default_bundle -> trusts BOTH Server 1 and Server 2
        h_default = httplib2.Http()
        resp1, _ = h_default.request(uri_srv1, "GET")
        assert resp1.status == 200
        resp2, _ = h_default.request(uri_srv2, "GET")
        assert resp2.status == 200

        # 2. Http(ca_certs=gam_short_ca_bundle) over HTTP/2 -> trusts Server 1, rejects Server 2
        h_custom_h2 = httplib2.Http(ca_certs=gam_short_ca_bundle, enable_http2=True)
        resp1_h2, content1_h2 = h_custom_h2.request(uri_srv1, "GET")
        assert resp1_h2.status == 200
        assert resp1_h2.version == 20
        assert content1_h2 == b"ok"

        with pytest.raises(ssl.SSLError) as exc_info_h2:
            h_custom_h2.request(uri_srv2, "GET")
        assert exc_info_h2.value.reason == "CERTIFICATE_VERIFY_FAILED"

        # 3. Http(ca_certs=gam_short_ca_bundle) over HTTP/1.1 -> trusts Server 1, rejects Server 2
        h_custom_h1 = httplib2.Http(ca_certs=gam_short_ca_bundle, enable_http2=False)
        resp1_h1, content1_h1 = h_custom_h1.request(uri_srv1, "GET")
        assert resp1_h1.status == 200
        assert resp1_h1.version == 11
        assert content1_h1 == b"ok"

        with pytest.raises(ssl.SSLError) as exc_info_h1:
            h_custom_h1.request(uri_srv2, "GET")
        assert exc_info_h1.value.reason == "CERTIFICATE_VERIFY_FAILED"


def test_httplib2_ca_certs_env_var_restricts_trust_store(tmp_path, monkeypatch):
    """Setting HTTPLIB2_CA_CERTS at runtime must also restrict default Http() instances
    to trust only the CAs in that file.
    """
    ca1_file, srv1_cert, srv1_key, _ = _generate_ca_and_localhost_cert(tmp_path, "env_included")
    _, srv2_cert, srv2_key, _ = _generate_ca_and_localhost_cert(tmp_path, "env_excluded")

    monkeypatch.setenv("HTTPLIB2_CA_CERTS", str(ca1_file))

    with (
        _h2_tls_server(certfile=str(srv1_cert), keyfile=str(srv1_key)) as (uri_srv1, _, _),
        _h2_tls_server(certfile=str(srv2_cert), keyfile=str(srv2_key)) as (uri_srv2, _, _),
    ):
        h = httplib2.Http()
        resp, _ = h.request(uri_srv1, "GET")
        assert resp.status == 200

        with pytest.raises(ssl.SSLError) as exc_info:
            h.request(uri_srv2, "GET")
        assert exc_info.value.reason == "CERTIFICATE_VERIFY_FAILED"


def test_tls_untrusted_ca_rejected_and_not_downgraded():
    """Untrusted CA certificates must raise SSLError and never trigger HTTP/1.1 fallback."""
    httplib2.DOWNGRADED_HOSTS.clear()
    h = httplib2.Http(ca_certs=tests.CA_UNUSED_CERTS)
    with _h2_tls_server() as (uri, _, _):
        with pytest.raises(ssl.SSLError):
            h.request(uri, "GET")
        assert "localhost" not in httplib2.DOWNGRADED_HOSTS
        assert "localhost" not in h._http2_downgraded_hosts


def test_tls_hostname_mismatch_rejected_and_not_downgraded():
    """Connecting via IP when cert is only valid for DNS:localhost must fail hostname verification."""
    httplib2.DOWNGRADED_HOSTS.clear()
    h = httplib2.Http(ca_certs=tests.CA_CERTS)
    with _h2_tls_server() as (_, port, _):
        ip_uri = f"https://127.0.0.1:{port}/"
        with pytest.raises((ssl.CertificateError, ssl.SSLError)):
            h.request(ip_uri, "GET")
        assert "127.0.0.1" not in httplib2.DOWNGRADED_HOSTS


def test_tls_version_policy_failure_not_downgraded():
    """When tls_minimum_version=TLSv1_3 blocks a TLSv1_2 server, it must fail without HTTP/1.1 downgrade."""
    httplib2.DOWNGRADED_HOSTS.clear()
    with _h2_tls_server(max_tls_version=ssl.TLSVersion.TLSv1_2) as (uri, _, _):
        h = httplib2.Http(ca_certs=tests.CA_CERTS, tls_minimum_version="TLSv1_3")
        with pytest.raises(ssl.SSLError):
            h.request(uri, "GET")
        assert "localhost" not in httplib2.DOWNGRADED_HOSTS
        assert "localhost" not in h._http2_downgraded_hosts


def test_tls_revalidation_when_disable_ssl_toggled_off():
    """Toggling disable_ssl_certificate_validation from True to False on an Http instance
    must invalidate the cached unverified connection and enforce cert verification.
    """
    with _h2_tls_server() as (uri, _, _):
        # Start with untrusted CA but validation disabled -> succeeds
        h = httplib2.Http(ca_certs=tests.CA_UNUSED_CERTS, disable_ssl_certificate_validation=True)
        resp, content = h.request(uri, "GET")
        assert resp.status == 200
        assert content == b"ok"

        # Re-enable SSL certificate validation on the same Http instance -> must NOT reuse unverified socket
        h.disable_ssl_certificate_validation = False
        with pytest.raises(ssl.SSLError):
            h.request(uri, "GET")


def test_tls_revalidation_when_ca_certs_changed():
    """Changing ca_certs on an existing Http instance must invalidate the cached connection pool."""
    with _h2_tls_server() as (uri, _, _):
        h = httplib2.Http(ca_certs=tests.CA_CERTS)
        resp, _ = h.request(uri, "GET")
        assert resp.status == 200

        # Switch to an untrusted CA bundle -> must close cached connection and fail verification
        h.ca_certs = tests.CA_UNUSED_CERTS
        with pytest.raises(ssl.SSLError):
            h.request(uri, "GET")


def test_preconnected_tls_stream_hostname_mismatch_rejected():
    """If conn.connect() is called for one host and conn.host is mutated before conn.request(),
    start_tls must reject the pre-connected socket due to server_hostname mismatch.
    """
    with _h2_tls_server() as (_, port, _):
        conn = httplib2.HTTPSConnectionWithTimeout("localhost", port=port, ca_certs=tests.CA_CERTS)
        conn.connect()
        conn.host = "evil.example.com"
        with pytest.raises((ssl.CertificateError, ssl.SSLError)):
            conn.request("GET", "/")


def test_ipv6_bracket_stripped_with_explicit_port():
    """Passing bracketed IPv6 literal with explicit port must strip brackets from conn.host."""
    conn_http = httplib2.HTTPConnectionWithTimeout("[::1]", port=8080)
    assert conn_http.host == "::1"
    conn_https = httplib2.HTTPSConnectionWithTimeout("[::1]", port=8443, ca_certs=tests.CA_CERTS)
    assert conn_https.host == "::1"


# ---------------------------------------------------------------------------
# 2. CRLF, Null-Byte, Control Character & HTTP/2 Pseudo-Header Injection Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "/path\r\nX-Injected: true",
        "/path\nX-Injected: true",
        "/path\rX-Injected: true",
        "/path\x00hidden",
        "/path with spaces",
        "/path\twith\ttabs",
    ],
)
def test_direct_connection_rejects_control_chars_in_url(bad_url):
    """Direct HTTPConnectionWithTimeout.request and HTTPSConnectionWithTimeout.request
    must reject URLs containing CRLF, null bytes, or unencoded whitespace.
    """
    conn = httplib2.HTTPConnectionWithTimeout("localhost", 80)
    with pytest.raises(http.client.InvalidURL):
        conn.request("GET", bad_url)


@pytest.mark.parametrize(
    "bad_method",
    [
        "",
        "GET\r\nX-Injected: 1",
        "GET /evil HTTP/1.1\r\n",
        "GET POST",
        "GET\x00",
        "GET\t",
    ],
)
def test_direct_connection_rejects_invalid_method(bad_method):
    """Methods containing whitespace, CRLF, or control characters must be rejected."""
    conn = httplib2.HTTPConnectionWithTimeout("localhost", 80)
    with pytest.raises(http.client.InvalidURL):
        conn.request(bad_method, "/")


@pytest.mark.parametrize(
    "bad_headers",
    [
        {"X-Test\r\nInjected": "val"},
        {"X-Test\nInjected": "val"},
        {"X-Test\x00": "val"},
        {"X-Test Space": "val"},
        {"": "val"},
        {"X-Test": "val\r\nX-Injected: evil"},
        {"X-Test": "val\nX-Injected: evil"},
        {"X-Test": "val\rX-Injected: evil"},
        {"X-Test": "val\x00evil"},
    ],
)
def test_rejects_crlf_and_null_bytes_in_headers(bad_headers):
    """Headers with CRLF, null bytes, or whitespace in names/values must raise HTTPException."""
    conn = httplib2.HTTPConnectionWithTimeout("localhost", 80)
    with pytest.raises(http.client.HTTPException):
        conn.request("GET", "/", headers=bad_headers)


@pytest.mark.parametrize(
    "pseudo_header",
    [
        ":authority",
        ":path",
        ":method",
        ":scheme",
        ":status",
        ":protocol",
    ],
)
def test_http2_pseudo_header_injection_rejected(pseudo_header):
    """User-supplied HTTP/2 pseudo-headers (starting with ':') must be rejected."""
    with _h2_tls_server() as (uri, port, _):
        h = httplib2.Http(ca_certs=tests.CA_CERTS)
        with pytest.raises(http.client.HTTPException):
            h.request(uri, "GET", headers={pseudo_header: "injected"})

        conn = httplib2.HTTPSConnectionWithTimeout("localhost", port=port, ca_certs=tests.CA_CERTS)
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", "/", headers={pseudo_header: "injected"})


# ---------------------------------------------------------------------------
# 3. Redirect Security Tests
# ---------------------------------------------------------------------------


def test_redirect_strips_authorization_by_default():
    """Authorization header must be stripped on redirects when forward_authorization_headers is False."""
    seen_requests = []

    def handler(request):
        seen_requests.append(request)
        if request.uri == "/start":
            return tests.http_response_bytes(status="302 Found", headers={"Location": "/target"})
        return tests.http_response_bytes(status="200 OK", body=b"done")

    http = httplib2.Http()
    with tests.server_request(handler, request_count=2) as uri:
        start_uri = urllib.parse.urljoin(uri, "/start")
        resp, content = http.request(start_uri, "GET", headers={"Authorization": "Bearer secret-token"})
        assert resp.status == 200
        assert content == b"done"
    assert len(seen_requests) == 2
    assert seen_requests[0].headers.get("authorization") == "Bearer secret-token"
    assert "authorization" not in seen_requests[1].headers


def test_redirect_https_to_http_downgrade_always_strips_authorization():
    """Even when forward_authorization_headers=True, redirecting from https:// to http://
    must strip the Authorization header to prevent cleartext credential leakage.
    """
    seen_http_requests = []

    def http_handler(request):
        seen_http_requests.append(request)
        return tests.http_response_bytes(status="200 OK", body=b"plain-http")

    with tests.server_request(http_handler, request_count=1) as plain_uri:
        def https_handler(request):
            return tests.http_response_bytes(status="302 Found", headers={"Location": plain_uri})

        with tests.server_request(https_handler, request_count=1, tls=True) as secure_uri:
            http = httplib2.Http(ca_certs=tests.CA_CERTS)
            http.forward_authorization_headers = True
            resp, content = http.request(secure_uri, "GET", headers={"Authorization": "Bearer top-secret"})
            assert resp.status == 200
            assert content == b"plain-http"

    assert len(seen_http_requests) == 1
    assert "authorization" not in seen_http_requests[0].headers


def test_redirect_cross_origin_strips_cookie_and_host_headers():
    """Cross-origin redirects must strip caller-supplied Cookie and Host headers."""
    seen_dest_requests = []

    def dest_handler(request):
        seen_dest_requests.append(request)
        return tests.http_response_bytes(status="200 OK", body=b"dest")

    with tests.server_request(dest_handler, request_count=1) as dest_uri:
        def orig_handler(request):
            return tests.http_response_bytes(status="302 Found", headers={"Location": dest_uri})

        with tests.server_request(orig_handler, request_count=1) as orig_uri:
            http = httplib2.Http()
            resp, _ = http.request(
                orig_uri,
                "GET",
                headers={"Cookie": "session=secret123", "Host": "custom.local"},
            )
            assert resp.status == 200

    assert len(seen_dest_requests) == 1
    assert "cookie" not in seen_dest_requests[0].headers
    assert seen_dest_requests[0].headers.get("host") != "custom.local"


def test_redirect_302_303_post_to_get_strips_body_headers():
    """302/303 redirects that convert POST to GET must strip Content-Length, Content-Type,
    and Transfer-Encoding headers from the redirected GET request (CVE-2023-45803 class).
    """
    seen_requests = []

    def handler(request):
        seen_requests.append(request)
        if request.uri == "/post":
            return tests.http_response_bytes(status="303 See Other", headers={"Location": "/get"})
        return tests.http_response_bytes(status="200 OK", body=b"ok")

    http = httplib2.Http()
    with tests.server_request(handler, request_count=2) as uri:
        post_uri = urllib.parse.urljoin(uri, "/post")
        resp, content = http.request(
            post_uri,
            "POST",
            body=b'{"secret": "payload"}',
            headers={"Content-Type": "application/json", "Content-Length": "21"},
        )
        assert resp.status == 200
        assert content == b"ok"

    assert len(seen_requests) == 2
    assert seen_requests[0].method == "POST"
    assert seen_requests[1].method == "GET"
    assert "content-type" not in seen_requests[1].headers
    assert seen_requests[1].headers.get("content-length") in (None, "0")


# ---------------------------------------------------------------------------
# 4. Decompression Bomb & Malformed Compression Protection Tests
# ---------------------------------------------------------------------------


def test_decompression_bomb_ratio_limit():
    """Highly compressed payloads exceeding the safe amplification ratio must be aborted."""
    uncompressed = b"\x00" * (2 * 1024 * 1024)  # 2 MiB of zeros
    compressed = zlib.compress(uncompressed, level=9)
    decoder = LimitDecoder(
        ZlibDecoder(ZlibDecoder.WBITS_ZLIB),
        hard_limit=10 * 1024 * 1024,
        safe_limit=64 * 1024,
        ratio=10.0,
    )
    with pytest.raises(DecodeRatioError):
        decoder.consume_bytes(compressed)


def test_decompression_bomb_hard_limit():
    """Payloads exceeding the hard decompression limit must raise DecodeLimitError."""
    uncompressed = os.urandom(128 * 1024)
    compressed = zlib.compress(uncompressed, level=1)
    decoder = LimitDecoder(
        ZlibDecoder(ZlibDecoder.WBITS_ZLIB),
        hard_limit=64 * 1024,
        safe_limit=64 * 1024,
        ratio=100.0,
    )
    with pytest.raises(DecodeLimitError):
        decoder.consume_bytes(compressed)


def test_empty_compressed_payload_with_zero_chunk_size():
    """consume_bytes(b'', chunk_size=0) must not raise ValueError: range() arg 3 must not be zero."""
    decoder = LimitDecoder(ZlibDecoder(ZlibDecoder.WBITS_DEFLATE))
    assert decoder.consume_bytes(b"", chunk_size=0) == b""


# ---------------------------------------------------------------------------
# 5. ReDoS Resilience in WWW-Authenticate Header Parsing (CVE-2021-21240)
# ---------------------------------------------------------------------------


def test_cve_2021_21240_redos_www_authenticate():
    """Pathological WWW-Authenticate headers with thousands of spaces/non-printable chars
    must complete in milliseconds without catastrophic backtracking.
    """
    evil_header = {"www-authenticate": "Basic " + (" " * 5000) + "\xa0"}
    t0 = time.perf_counter()
    with contextlib.suppress(httplib2.MalformedHeader):
        httplib2.auth._parse_www_authenticate(evil_header)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.2, f"WWW-Authenticate parsing took too long: {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# 6. FileCache Path Traversal Sanitization Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "malicious_uri",
    [
        "https://example.com/../../../../etc/passwd",
        "https://example.com/..\\..\\..\\windows\\win.ini",
        "https://../../evil.com/payload",
        "https://example.com/path\x00/../../secret",
    ],
)
def test_safename_prevents_path_traversal(malicious_uri):
    """safename() must never produce path separators or escape the cache directory."""
    safe = httplib2.safename(malicious_uri)
    assert "/" not in safe
    assert "\\" not in safe
    assert "\x00" not in safe
    assert os.path.dirname(os.path.normpath(os.path.join("/cache", safe))) == "/cache"
