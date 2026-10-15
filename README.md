# modern-httplib2

A 100% compatible, zero-code-change drop-in replacement for Python's [`httplib2`](https://github.com/httplib2/httplib2) library, powered under the hood by [`httpx`](https://www.python-httpx.org/) and [`httpcore`](https://www.encode.io/httpcore/).

## Why `modern-httplib2`?

Legacy `httplib2` is deeply embedded across the Python ecosystem (notably via `google-api-python-client`, `google-auth-httplib2`, and multi-threaded tools like GAM), but its original transport layer is built directly on Python's low-level `http.client` with single-socket state per `Http()` instance.

`modern-httplib2` keeps the exact `httplib2` public API, module layout, exception hierarchy, RFC 2616 caching, authentication schemes (`Basic`, `Digest`, `WSSE`, `GoogleLogin`, `HmacDigest`), and `ProxyInfo` semantics while replacing the underlying transport engine with **`httpx` (`httpcore` + `h2`)**:

- **Python Package & PyPI Name**: Published as [`modern-httplib2`](https://pypi.org/project/modern-httplib2/), importing as `modern_httplib2`.
- **Transparent Interceptor / Auto-Patching**: Providing `import modern_httplib2.auto` or `modern_httplib2.patch()` which mounts `modern_httplib2` into `sys.modules["httplib2"]`. Existing dependencies like `google-api-python-client` and `google-auth-httplib2` automatically and transparently use `modern_httplib2` without any code changes to Google's libraries.
- **Direct Import Support**: Use directly via `import modern_httplib2` or `import modern_httplib2 as httplib2`.
- **Modern `httpx` / `httpcore` Transport**: Uses `httpx`'s `httpcore` connection pool and `h11`/`h2` protocol state machines.
- **True Multi-Threaded HTTP/2 Multiplexing**: Multiple threads sharing a single `Http()` instance multiplex concurrent requests over a **single TCP+TLS HTTP/2 connection** (up to 100 concurrent streams per connection), even on cold start.
- **Thread-Safe Connection Pooling**: Unlike upstream `httplib2.Http()` (which is notorious for thread-safety crashes when shared across threads), `modern-httplib2` uses thread-local active request dispatch backed by a thread-safe per-origin `httpcore.ConnectionPool` (`pool_maxsize=16` by default).
- **Transparent HTTP/2 over TLS (ALPN `h2`)**: Automatically negotiates HTTP/2 on HTTPS connections when the server advertises `h2` via TLS ALPN, with seamless fallback to HTTP/1.1.
- **Python 3.11+ Native**: Built exclusively for supported Python versions (3.11+), free of legacy Python 2 / early Python 3 compatibility shims.
- **100% Upstream Test Suite Compatibility**: Passes all 526+ upstream `httplib2` unit and integration tests.

---

## Installation

Install from PyPI:

```bash
pip install modern-httplib2
```

---

## Usage

### 1. Transparent Interception in Existing Projects (e.g. GAM)

To automatically redirect all `import httplib2` calls across your application and its dependencies (like `google-api-python-client` and `google-auth-httplib2`) to `modern_httplib2`, import `modern_httplib2.auto` at your application entrypoint:

```python
try:
    import modern_httplib2.auto
except ImportError:
    pass

# All downstream imports now transparently use modern_httplib2!
import google_auth_httplib2
import googleapiclient.discovery
import httplib2

http = httplib2.Http()
```

### 2. Direct Import Usage

```python
import modern_httplib2 as httplib2

http = httplib2.Http(".cache")
resp, content = http.request("https://httpbin.org/get", "GET")
print(resp.status, resp.version)  # e.g. 200, 20 (HTTP/2) or 11 (HTTP/1.1)
```

### 2. Thread-Safe Concurrent Requests

You can safely share a single `httplib2.Http` instance across multiple threads:

```python
from concurrent.futures import ThreadPoolExecutor
import httplib2

http = httplib2.Http(pool_maxsize=16)

def fetch(url):
    resp, body = http.request(url)
    return resp.status, len(body)

with ThreadPoolExecutor(max_workers=8) as pool:
    results = list(pool.map(fetch, ["https://example.com"] * 32))
```

### 3. Controlling HTTP/2 Negotiation & Corporate Firewall Downgrade

HTTP/2 over TLS is enabled by default (`enable_http2=True`). For environments where corporate firewalls, deep packet inspection (DPI) middleboxes, or legacy proxies reject, reset, or misbehave with HTTP/2 traffic, `modern-httplib2` provides multiple ways to force HTTP/1.1:

#### Automatic Firewall Fallback (Enabled by Default)
By default (`auto_downgrade_http2=True`), if an HTTP/2 connection fails due to a network or protocol reset (e.g. proxy RST on HTTP/2 preface, stream errors, or closed connections), `modern-httplib2` will:
1. Automatically downgrade the connection to HTTP/1.1.
2. Remember that host for subsequent requests in the session.
3. Transparently retry the request without raising an exception to the caller.

#### Global / Application-Wide Toggle
Disable HTTP/2 globally in your application (for example, when a user sets `force_http11 = true` in their configuration file):
```python
import httplib2

# Any of these can be called at startup:
httplib2.force_http11()
# or:
httplib2.ENABLE_HTTP2 = False
# or:
httplib2.set_enable_http2(False)
```

#### Environment Variable (Zero Code Change)
Set the environment variable in your shell or configuration:
```bash
export MODERN_HTTPLIB2_ENABLE_HTTP2=0
# or
export HTTPLIB2_ENABLE_HTTP2=0
```

#### Per-Instance Control
```python
import httplib2

http_v1 = httplib2.Http(enable_http2=False)
# or dynamically on an existing instance:
http_v1.force_http11()

resp, content = http_v1.request("https://example.com")
assert resp.version == 11
```

### 4. Using with `google-auth-httplib2`

```python
import google.auth
import google_auth_httplib2
import httplib2

credentials, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
authed_http = google_auth_httplib2.AuthorizedHttp(credentials, http=httplib2.Http())
resp, content = authed_http.request("https://www.googleapis.com/oauth2/v1/ tokeninfo")
```

---

## Running Tests

```bash
.venv/bin/pytest
```
