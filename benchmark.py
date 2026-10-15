#!/usr/bin/env python3
"""
Performance Benchmark Suite: modern-httplib2 vs. standard httplib2
==================================================================

Evaluates real-world network and CPU performance of `modern-httplib2`
(powered by httpx / httpcore with HTTP/2 ALPN multiplexing and thread-safe connection pooling)
against upstream `httplib2` (powered by stdlib http.client, HTTP/1.1 only,
single unpooled socket per origin).

Benchmarks include:
  1. Single-Endpoint Cold & Warm Keep-Alive Latency across keyless Google APIs
     (Chrome Version History API, Google Discovery API, Google OAuth2/OIDC)
     and high-performance HTTP/2 servers (Cloudflare Edge, cdnjs, nghttp2.org).
  2. Sequential Multi-Endpoint Traversal on the Chrome Version History API.
  3. Multi-Threaded Concurrent Fan-Out (24 Chrome Version History endpoints
     across 8 worker threads) comparing:
       - modern-httplib2 (shared Http(), lock-free multiplexed HTTP/2)
       - modern-httplib2 (shared Http(), lock-free pooled HTTP/1.1)
       - standard httplib2 (shared Http() with required threading.Lock)
       - standard httplib2 (per-request Http() instance workaround)
       - Unsynchronized shared Http() thread-safety stress test
  4. Local RFC 2616 FileCache Hits & URI/IRI Processing Microbenchmarks.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import importlib.util
import json
import math
import os
import platform
import signal
import site
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable

# Ensure workspace root is first in sys.path so `import httplib2` loads modern-httplib2
WORKSPACE_ROOT = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import httplib2 as modern_httplib2  # noqa: E402
import httpcore  # noqa: E402
import httpx  # noqa: E402


def load_legacy_httplib2():
    """Load unmodified upstream httplib2 from site-packages as `legacy_httplib2`."""
    search_dirs = list(site.getsitepackages())
    user_site = site.getusersitepackages()
    if isinstance(user_site, str):
        search_dirs.append(user_site)

    # Also check virtual environment site-packages relative to sys.prefix
    for root, dirs, _ in os.walk(os.path.join(sys.prefix, "lib")):
        if "site-packages" in dirs:
            candidate = os.path.join(root, "site-packages")
            if candidate not in search_dirs:
                search_dirs.append(candidate)

    for sp in search_dirs:
        init_py = os.path.join(sp, "httplib2", "__init__.py")
        if os.path.isfile(init_py) and os.path.abspath(sp) != WORKSPACE_ROOT:
            pkg_dir = os.path.join(sp, "httplib2")
            spec = importlib.util.spec_from_file_location(
                "legacy_httplib2",
                init_py,
                submodule_search_locations=[pkg_dir],
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules["legacy_httplib2"] = module
                spec.loader.exec_module(module)
                return module
    raise RuntimeError(
        "Could not locate upstream `httplib2` in site-packages for comparison. "
        "Install it in the virtualenv via `pip install httplib2`."
    )


legacy_httplib2 = load_legacy_httplib2()


# ---------------------------------------------------------------------------
# Statistical Helpers
# ---------------------------------------------------------------------------


def percentile(sorted_values: list[float], pct: float) -> float:
    """Compute linear-interpolated percentile (0..100) from a sorted list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)


@dataclass
class LatencyStats:
    """Rich descriptive statistics for a sample of request latencies (in ms)."""

    name: str
    protocol: str
    count: int
    errors: int
    total_wall_ms: float
    total_bytes: int
    cold_ms: float
    mean_ms: float
    stdev_ms: float
    cv_pct: float
    min_ms: float
    p10_ms: float
    p25_ms: float
    median_ms: float
    p75_ms: float
    iqr_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    rps: float
    throughput_kbps: float
    samples_ms: list[float] = field(repr=False, default_factory=list)

    @classmethod
    def from_samples(
        cls,
        name: str,
        protocol: str,
        samples_ms: list[float],
        *,
        cold_ms: float = 0.0,
        total_wall_ms: float | None = None,
        total_bytes: int = 0,
        errors: int = 0,
    ) -> LatencyStats:
        if not samples_ms:
            return cls(
                name=name,
                protocol=protocol,
                count=0,
                errors=errors,
                total_wall_ms=total_wall_ms or 0.0,
                total_bytes=total_bytes,
                cold_ms=cold_ms,
                mean_ms=0.0,
                stdev_ms=0.0,
                cv_pct=0.0,
                min_ms=0.0,
                p10_ms=0.0,
                p25_ms=0.0,
                median_ms=0.0,
                p75_ms=0.0,
                iqr_ms=0.0,
                p90_ms=0.0,
                p95_ms=0.0,
                p99_ms=0.0,
                max_ms=0.0,
                rps=0.0,
                throughput_kbps=0.0,
                samples_ms=[],
            )
        s = sorted(samples_ms)
        n = len(s)
        mean = statistics.fmean(s)
        stdev = statistics.stdev(s) if n > 1 else 0.0
        cv = (stdev / mean * 100.0) if mean > 0 else 0.0
        p25 = percentile(s, 25)
        p75 = percentile(s, 75)
        wall_ms = total_wall_ms if total_wall_ms is not None else sum(s)
        wall_s = wall_ms / 1000.0 if wall_ms > 0 else 1e-9
        rps = n / wall_s
        kbps = (total_bytes / 1024.0) / wall_s
        return cls(
            name=name,
            protocol=protocol,
            count=n,
            errors=errors,
            total_wall_ms=wall_ms,
            total_bytes=total_bytes,
            cold_ms=cold_ms,
            mean_ms=mean,
            stdev_ms=stdev,
            cv_pct=cv,
            min_ms=s[0],
            p10_ms=percentile(s, 10),
            p25_ms=p25,
            median_ms=percentile(s, 50),
            p75_ms=p75,
            iqr_ms=p75 - p25,
            p90_ms=percentile(s, 90),
            p95_ms=percentile(s, 95),
            p99_ms=percentile(s, 99),
            max_ms=s[-1],
            rps=rps,
            throughput_kbps=kbps,
            samples_ms=s,
        )


def welch_t_test(samples_a: list[float], samples_b: list[float]) -> tuple[float, float]:
    """Compute Welch's t-statistic and approximate two-tailed p-value (normal approx)."""
    if len(samples_a) < 2 or len(samples_b) < 2:
        return 0.0, 1.0
    mean_a = statistics.fmean(samples_a)
    mean_b = statistics.fmean(samples_b)
    var_a = statistics.variance(samples_a)
    var_b = statistics.variance(samples_b)
    se = math.sqrt(var_a / len(samples_a) + var_b / len(samples_b))
    if se == 0:
        return 0.0, 1.0
    t_stat = (mean_b - mean_a) / se
    # Complementary error function normal tail approximation for two-tailed p-value
    p_val = math.erfc(abs(t_stat) / math.sqrt(2.0))
    return t_stat, p_val


def format_protocol(version: int) -> str:
    return {20: "HTTP/2", 11: "HTTP/1.1", 10: "HTTP/1.0"}.get(version, f"v{version}")


def ascii_bar(value: float, max_value: float, width: int = 24, char: str = "█") -> str:
    if max_value <= 0 or value <= 0:
        return ""
    filled = max(1, min(width, round((value / max_value) * width)))
    return char * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# Benchmark Endpoints
# ---------------------------------------------------------------------------

ENDPOINTS = [
    {
        "id": "chrome_platforms",
        "title": "Chrome Version History API: Platforms",
        "url": "https://versionhistory.googleapis.com/v1/chrome/platforms",
        "category": "Google Version History API",
    },
    {
        "id": "chrome_channels",
        "title": "Chrome Version History API: All Channels",
        "url": "https://versionhistory.googleapis.com/v1/chrome/platforms/all/channels",
        "category": "Google Version History API",
    },
    {
        "id": "chrome_active_releases",
        "title": "Chrome Version History API: Live Stable Releases",
        "url": "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions/all/releases?filter=endtime=none",
        "category": "Google Version History API",
    },
    {
        "id": "google_oauth2_certs",
        "title": "Google Identity: OAuth2 JWK Public Certs",
        "url": "https://www.googleapis.com/oauth2/v3/certs",
        "category": "Google Keyless API",
    },
    {
        "id": "google_oidc_config",
        "title": "Google Identity: OpenID Connect Discovery",
        "url": "https://accounts.google.com/.well-known/openid-configuration",
        "category": "Google Keyless API",
    },
    {
        "id": "google_discovery_apis",
        "title": "Google APIs Discovery Directory (Large JSON)",
        "url": "https://discovery.googleapis.com/discovery/v1/apis?preferred=true",
        "category": "Google Keyless API",
    },
    {
        "id": "gcs_public_landsat",
        "title": "Google Cloud Storage API: Public Landsat Bucket Metadata",
        "url": "https://storage.googleapis.com/storage/v1/b/gcp-public-data-landsat",
        "category": "Google Keyless API",
    },
    {
        "id": "cloudflare_trace",
        "title": "Cloudflare Global Anycast Edge (cdn-cgi/trace)",
        "url": "https://www.cloudflare.com/cdn-cgi/trace",
        "category": "Modern HTTP/2 Edge",
    },
    {
        "id": "cdnjs_api",
        "title": "Cloudflare CDNJS API (jQuery Metadata)",
        "url": "https://api.cdnjs.com/libraries/jquery?fields=version,description,homepage",
        "category": "Modern HTTP/2 Edge",
    },
]

# 10 distinct Chrome Version History URLs for multi-endpoint traversal
CHROME_TRAVERSAL_URLS = [
    "https://versionhistory.googleapis.com/v1/chrome/platforms",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/all/channels",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/mac_arm64/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/android/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/ios/channels/stable/versions",
    "https://versionhistory.googleapis.com/v1/chrome/platforms/webview/channels/stable/versions",
]

# 24 Chrome Version History URLs across 8 platforms x 3 channels for concurrent fan-out
CHROME_FANOUT_URLS = [
    f"https://versionhistory.googleapis.com/v1/chrome/platforms/{plat}/channels/{chan}/versions?pageSize=10"
    for plat in ("win", "win64", "mac", "mac_arm64", "linux", "android", "ios", "webview")
    for chan in ("stable", "beta", "dev")
]


# ---------------------------------------------------------------------------
# Benchmark Runners
# ---------------------------------------------------------------------------


def benchmark_single_endpoint(url: str, warm_iterations: int = 8) -> dict[str, LatencyStats]:
    """
    Benchmark a single endpoint across:
      1. modern-httplib2 (HTTP/2 enabled)
      2. modern-httplib2 (HTTP/1.1 forced)
      3. standard httplib2 (HTTP/1.1)

    Measures cold-start (initial connect + TLS + request) first, then interleaves
    warm keep-alive requests across all three clients so any transient network
    fluctuations affect all clients equally.
    """
    clients = {
        "modern (HTTP/2)": modern_httplib2.Http(timeout=15, enable_http2=True),
        "modern (HTTP/1.1)": modern_httplib2.Http(timeout=15, enable_http2=False),
        "standard httplib2": legacy_httplib2.Http(timeout=15),
    }
    cold_times: dict[str, float] = {}
    warm_samples: dict[str, list[float]] = {k: [] for k in clients}
    total_bytes: dict[str, int] = {k: 0 for k in clients}
    protocols: dict[str, str] = {k: "HTTP/1.1" for k in clients}
    errors: dict[str, int] = {k: 0 for k in clients}

    # 1. Cold-start measurement (fresh TCP + TLS + ALPN handshake)
    for name, client in clients.items():
        t0 = time.perf_counter()
        try:
            resp, body = client.request(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            cold_times[name] = elapsed_ms
            protocols[name] = format_protocol(getattr(resp, "version", 11))
            if resp.status >= 400:
                errors[name] += 1
        except Exception:
            cold_times[name] = (time.perf_counter() - t0) * 1000.0
            errors[name] += 1

    # 2. Interleaved warm keep-alive iterations
    client_names = list(clients.keys())
    for i in range(warm_iterations):
        # Rotate starting client each round to eliminate ordering bias
        rotated = client_names[i % len(client_names) :] + client_names[: i % len(client_names)]
        for name in rotated:
            client = clients[name]
            t0 = time.perf_counter()
            try:
                resp, body = client.request(url)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                warm_samples[name].append(elapsed_ms)
                total_bytes[name] += len(body)
                protocols[name] = format_protocol(getattr(resp, "version", 11))
                if resp.status >= 400:
                    errors[name] += 1
            except Exception:
                errors[name] += 1

    for client in clients.values():
        client.close()

    return {
        name: LatencyStats.from_samples(
            name=name,
            protocol=protocols[name],
            samples_ms=warm_samples[name],
            cold_ms=cold_times.get(name, 0.0),
            total_bytes=total_bytes[name],
            errors=errors[name],
        )
        for name in clients
    }


def benchmark_sequential_traversal(urls: list[str], rounds: int = 2) -> dict[str, LatencyStats]:
    """
    Benchmark walking a sequence of Chrome Version History API endpoints over a single
    persistent Http() session.
    """
    configs: list[tuple[str, Callable[[], Any]]] = [
        ("modern (HTTP/2)", lambda: modern_httplib2.Http(timeout=15, enable_http2=True)),
        ("modern (HTTP/1.1)", lambda: modern_httplib2.Http(timeout=15, enable_http2=False)),
        ("standard httplib2", lambda: legacy_httplib2.Http(timeout=15)),
    ]
    results: dict[str, LatencyStats] = {}

    for name, factory in configs:
        client = factory()
        samples: list[float] = []
        total_bytes = 0
        err_count = 0
        proto = "HTTP/1.1"

        # Cold connect on first URL
        t_cold0 = time.perf_counter()
        resp, body = client.request(urls[0])
        cold_ms = (time.perf_counter() - t_cold0) * 1000.0
        proto = format_protocol(getattr(resp, "version", 11))

        wall_t0 = time.perf_counter()
        for _ in range(rounds):
            for u in urls:
                t0 = time.perf_counter()
                try:
                    resp, body = client.request(u)
                    samples.append((time.perf_counter() - t0) * 1000.0)
                    total_bytes += len(body)
                    proto = format_protocol(getattr(resp, "version", 11))
                    if resp.status >= 400:
                        err_count += 1
                except Exception:
                    err_count += 1
        wall_ms = (time.perf_counter() - wall_t0) * 1000.0
        client.close()

        results[name] = LatencyStats.from_samples(
            name=name,
            protocol=proto,
            samples_ms=samples,
            cold_ms=cold_ms,
            total_wall_ms=wall_ms,
            total_bytes=total_bytes,
            errors=err_count,
        )

    return results


def benchmark_concurrent_fanout(
    urls: list[str],
    workers: int = 8,
    rounds: int = 2,
) -> dict[str, LatencyStats]:
    """
    Benchmark concurrent multi-threaded requests across `workers` threads fetching
    all `urls` for `rounds` bursts.

    Evaluates:
      1. modern-httplib2 (Shared Http(), Lock-Free Pooled HTTP/2)
      2. modern-httplib2 (Shared Http(), Lock-Free Pooled HTTP/1.1)
      3. standard httplib2 (Per-Task Http() Instance — thread-safe workaround, unpooled)
      4. standard httplib2 (Shared Http() + threading.Lock — serialized workaround)
    """
    workload = urls * rounds
    results: dict[str, LatencyStats] = {}

    # --- 1. modern-httplib2 (Shared Http(), Pooled HTTP/2) ---
    http_m2 = modern_httplib2.Http(timeout=15, enable_http2=True, pool_maxsize=workers * 2)
    samples_m2: list[float] = []
    bytes_m2 = 0
    errs_m2 = 0
    proto_m2 = "HTTP/2"

    def _warm_pool(client: Any) -> None:
        barrier = threading.Barrier(workers)

        def _warm_worker(idx: int) -> None:
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
            client.request(urls[idx % len(urls)])

        with ThreadPoolExecutor(max_workers=workers) as warm_exec:
            list(warm_exec.map(_warm_worker, range(workers)))

    _warm_pool(http_m2)

    def _task_m2(u: str) -> tuple[float, int, int, int]:
        t0 = time.perf_counter()
        resp, body = http_m2.request(u)
        return (time.perf_counter() - t0) * 1000.0, len(body), resp.status, getattr(resp, "version", 20)

    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_task_m2, u) for u in workload]
        for f in as_completed(futs):
            try:
                ms, b_len, st, ver = f.result()
                samples_m2.append(ms)
                bytes_m2 += b_len
                proto_m2 = format_protocol(ver)
                if st >= 400:
                    errs_m2 += 1
            except Exception:
                errs_m2 += 1
    wall_m2 = (time.perf_counter() - t_wall0) * 1000.0
    http_m2.close()
    results["modern (Shared Http, Pooled H2)"] = LatencyStats.from_samples(
        name="modern (Shared Http, Pooled H2)",
        protocol=proto_m2,
        samples_ms=samples_m2,
        total_wall_ms=wall_m2,
        total_bytes=bytes_m2,
        errors=errs_m2,
    )

    # --- 2. modern-httplib2 (Shared Http(), Pooled HTTP/1.1) ---
    http_m1 = modern_httplib2.Http(timeout=15, enable_http2=False, pool_maxsize=workers * 2)
    samples_m1: list[float] = []
    bytes_m1 = 0
    errs_m1 = 0
    proto_m1 = "HTTP/1.1"

    _warm_pool(http_m1)

    def _task_m1(u: str) -> tuple[float, int, int, int]:
        t0 = time.perf_counter()
        resp, body = http_m1.request(u)
        return (time.perf_counter() - t0) * 1000.0, len(body), resp.status, getattr(resp, "version", 11)

    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_task_m1, u) for u in workload]
        for f in as_completed(futs):
            try:
                ms, b_len, st, ver = f.result()
                samples_m1.append(ms)
                bytes_m1 += b_len
                proto_m1 = format_protocol(ver)
                if st >= 400:
                    errs_m1 += 1
            except Exception:
                errs_m1 += 1
    wall_m1 = (time.perf_counter() - t_wall0) * 1000.0
    http_m1.close()
    results["modern (Shared Http, Pooled H1)"] = LatencyStats.from_samples(
        name="modern (Shared Http, Pooled H1)",
        protocol=proto_m1,
        samples_ms=samples_m1,
        total_wall_ms=wall_m1,
        total_bytes=bytes_m1,
        errors=errs_m1,
    )

    # --- 3. standard httplib2 (Fresh Http() per request — official thread-safe pattern) ---
    samples_leg_isolated: list[float] = []
    bytes_leg_isolated = 0
    errs_leg_isolated = 0

    def _task_leg_isolated(u: str) -> tuple[float, int, int]:
        t0 = time.perf_counter()
        h = legacy_httplib2.Http(timeout=15)
        try:
            resp, body = h.request(u)
            return (time.perf_counter() - t0) * 1000.0, len(body), resp.status
        finally:
            h.close()

    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_task_leg_isolated, u) for u in workload]
        for f in as_completed(futs):
            try:
                ms, b_len, st = f.result()
                samples_leg_isolated.append(ms)
                bytes_leg_isolated += b_len
                if st >= 400:
                    errs_leg_isolated += 1
            except Exception:
                errs_leg_isolated += 1
    wall_leg_isolated = (time.perf_counter() - t_wall0) * 1000.0
    results["standard (New Http() per task)"] = LatencyStats.from_samples(
        name="standard (New Http() per task)",
        protocol="HTTP/1.1",
        samples_ms=samples_leg_isolated,
        total_wall_ms=wall_leg_isolated,
        total_bytes=bytes_leg_isolated,
        errors=errs_leg_isolated,
    )

    # --- 4. standard httplib2 (Shared Http() + threading.Lock) ---
    http_leg_locked = legacy_httplib2.Http(timeout=15)
    # Pre-warm the single socket on standard httplib2 as well
    http_leg_locked.request(urls[0])
    lock_leg = threading.Lock()
    samples_leg_locked: list[float] = []
    bytes_leg_locked = 0
    errs_leg_locked = 0

    def _task_leg_locked(u: str) -> tuple[float, int, int]:
        t0 = time.perf_counter()
        with lock_leg:
            resp, body = http_leg_locked.request(u)
        return (time.perf_counter() - t0) * 1000.0, len(body), resp.status

    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_task_leg_locked, u) for u in workload]
        for f in as_completed(futs):
            try:
                ms, b_len, st = f.result()
                samples_leg_locked.append(ms)
                bytes_leg_locked += b_len
                if st >= 400:
                    errs_leg_locked += 1
            except Exception:
                errs_leg_locked += 1
    wall_leg_locked = (time.perf_counter() - t_wall0) * 1000.0
    http_leg_locked.close()
    results["standard (Shared Http + Lock)"] = LatencyStats.from_samples(
        name="standard (Shared Http + Lock)",
        protocol="HTTP/1.1",
        samples_ms=samples_leg_locked,
        total_wall_ms=wall_leg_locked,
        total_bytes=bytes_leg_locked,
        errors=errs_leg_locked,
    )

    return results


def benchmark_thread_safety_probe(urls: list[str], workers: int = 8) -> dict[str, dict[str, Any]]:
    """
    Demonstrate what happens when a single `Http()` instance is shared across threads
    WITHOUT external locking in `modern-httplib2` vs `standard httplib2`.

    Runs in an isolated child process because sharing a single `ssl.SSLSocket`
    across threads in `standard httplib2` frequently triggers either Python
    `SSLError`/`ResponseNotReady`/`BadStatusLine` exceptions OR a fatal C-level
    OpenSSL crash (`SIGTRAP` / `SIGSEGV` / `SIGABRT`).
    """
    probe_urls = urls[:16]
    report: dict[str, dict[str, Any]] = {}

    probe_code = """
import json, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import benchmark

mode = sys.argv[1]
urls = json.loads(sys.argv[2])
workers = int(sys.argv[3])
mod = benchmark.modern_httplib2 if mode == "modern" else benchmark.legacy_httplib2

client = mod.Http(timeout=10)
# Establish initial socket so threads race on the active connection
client.request(urls[0])

successes = 0
failures = []

def _worker(u):
    resp, body = client.request(u)
    return resp.status

t0 = time.perf_counter()
with ThreadPoolExecutor(max_workers=workers) as pool:
    futs = [pool.submit(_worker, u) for u in urls]
    for f in as_completed(futs):
        try:
            st = f.result()
            if st == 200:
                successes += 1
            else:
                failures.append(f"HTTP {st}")
        except Exception as exc:
            failures.append(f"{type(exc).__name__}: {exc}")
elapsed_ms = (time.perf_counter() - t0) * 1000.0
try:
    client.close()
except Exception:
    pass

print("PROBE_JSON:" + json.dumps({
    "total": len(urls),
    "successes": successes,
    "failures": len(failures),
    "failure_types": sorted(set(failures))[:5],
    "wall_ms": elapsed_ms,
}))
"""

    for label, mode_arg in [("modern-httplib2", "modern"), ("standard httplib2", "legacy")]:
        t0 = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-c", probe_code, mode_arg, json.dumps(probe_urls), str(workers)],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        wall_ms = (time.perf_counter() - t0) * 1000.0
        parsed = None
        for line in proc.stdout.splitlines():
            if line.startswith("PROBE_JSON:"):
                parsed = json.loads(line[len("PROBE_JSON:") :])
                break

        if parsed is not None and proc.returncode == 0:
            report[label] = parsed
        else:
            if proc.returncode < 0:
                sig_num = -proc.returncode
                try:
                    sig_name = signal.Signals(sig_num).name
                except ValueError:
                    sig_name = f"SIG{sig_num}"
                reason = f"Fatal C-level OpenSSL crash ({sig_name}, exit code {proc.returncode})"
            else:
                stderr_tail = (proc.stderr or "").strip().splitlines()[-1:] or ["Subprocess failed"]
                reason = f"Process exited with code {proc.returncode}: {stderr_tail[0]}"
            report[label] = {
                "total": len(probe_urls),
                "successes": parsed["successes"] if parsed else 0,
                "failures": len(probe_urls) - (parsed["successes"] if parsed else 0),
                "failure_types": ([reason] + (parsed["failure_types"] if parsed else []))[:5],
                "wall_ms": wall_ms,
            }

    return report


def benchmark_local_cache_and_cpu(iterations: int = 2000) -> dict[str, dict[str, float]]:
    """
    Microbenchmark local CPU-bound operations:
      1. RFC 2616 FileCache hit latency & throughput (using a real cached Chrome Version History response)
      2. iri2uri + urlnorm + safename throughput
    """
    test_url = "https://versionhistory.googleapis.com/v1/chrome/platforms"
    results: dict[str, dict[str, float]] = {}

    for label, mod in [("modern-httplib2", modern_httplib2), ("standard httplib2", legacy_httplib2)]:
        with tempfile.TemporaryDirectory() as tmpdir:
            client = mod.Http(cache=tmpdir, timeout=15)
            # Populate cache with one live request (force Cache-Control max-age so hits are served locally)
            resp, body = client.request(test_url)
            # Ensure the cached entry has a long max-age for pure local FileCache hit benchmarking
            cache_key = mod.urlnorm(test_url)[-1]
            raw_cached = client.cache.get(cache_key)
            if raw_cached:
                lines = raw_cached.split(b"\r\n\r\n", 1)
                if len(lines) == 2:
                    hdr_block, payload = lines
                    hdr_text = hdr_block.decode("iso-8859-1")
                    hdr_lines = [
                        ln for ln in hdr_text.splitlines() if not ln.lower().startswith("cache-control:")
                    ]
                    hdr_lines.append("cache-control: public, max-age=86400")
                    client.cache.set(
                        cache_key,
                        ("\r\n".join(hdr_lines) + "\r\n\r\n").encode("iso-8859-1") + payload,
                    )

            # Warm cache hit loop
            t0 = time.perf_counter()
            cache_hits = 0
            for _ in range(iterations):
                r, _ = client.request(test_url)
                if r.fromcache:
                    cache_hits += 1
            cache_elapsed_s = time.perf_counter() - t0
            client.close()

        # IRI / URI / safename CPU benchmark
        sample_iris = [
            "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?filter=name=120",
            "https://example.org/путь/к/ресурсу?запрос=значение&page=1",
            "https://אלף.example.com/path/to/resource?q=café&lang=fr",
        ]
        t0 = time.perf_counter()
        for _ in range(iterations):
            for iri in sample_iris:
                u = mod.iri2uri(iri)
                _, _, _, defrag = mod.urlnorm(u)
                mod.safename(defrag)
        iri_elapsed_s = time.perf_counter() - t0

        results[label] = {
            "cache_hit_us": (cache_elapsed_s / iterations) * 1_000_000.0,
            "cache_hits_per_sec": iterations / cache_elapsed_s,
            "cache_hit_ratio": cache_hits / iterations,
            "iri_ops_us": (iri_elapsed_s / (iterations * len(sample_iris))) * 1_000_000.0,
            "iri_ops_per_sec": (iterations * len(sample_iris)) / iri_elapsed_s,
        }

    return results


# ---------------------------------------------------------------------------
# Rich Console Formatter
# ---------------------------------------------------------------------------


def print_banner(warm_iterations: int, workers: int, fanout_rounds: int) -> None:
    print("=" * 108)
    print("  MODERN-HTTPLIB2 vs. STANDARD HTTPLIB2 — PERFORMANCE BENCHMARK SUITE")
    print("=" * 108)
    print(f"  Python Runtime       : Python {platform.python_version()} ({platform.python_implementation()}) on {platform.platform()}")
    print(
        f"  modern-httplib2      : v{modern_httplib2.__version__} (author: {modern_httplib2.__author__}) "
        f"| backend: httpx v{httpx.__version__} / httpcore v{httpcore.__version__} (HTTP/2 Multiplexing + Pool)"
    )
    print(
        f"  standard httplib2    : v{legacy_httplib2.__version__} (author: {legacy_httplib2.__author__}) "
        f"| backend: stdlib http.client (HTTP/1.1 Single Socket)"
    )
    print(
        f"  Configuration        : {warm_iterations} interleaved warm iterations/endpoint | "
        f"{workers} concurrent worker threads | {fanout_rounds}x24 fan-out requests"
    )
    print("=" * 108)
    print()


def print_single_endpoint_section(
    all_endpoint_stats: list[tuple[dict[str, str], dict[str, LatencyStats]]]
) -> None:
    print("─" * 108)
    print("  SUITE 1: SINGLE-ENDPOINT COLD & WARM KEEP-ALIVE LATENCY (INTERLEAVED ROUNDS)")
    print("─" * 108)

    for ep, stats_map in all_endpoint_stats:
        m_h2 = stats_map["modern (HTTP/2)"]
        m_h1 = stats_map["modern (HTTP/1.1)"]
        leg = stats_map["standard httplib2"]

        speedup_mean = leg.mean_ms / m_h2.mean_ms if m_h2.mean_ms > 0 else 0.0
        speedup_p50 = leg.median_ms / m_h2.median_ms if m_h2.median_ms > 0 else 0.0
        pct_diff = ((leg.mean_ms - m_h2.mean_ms) / leg.mean_ms * 100.0) if leg.mean_ms > 0 else 0.0
        t_stat, p_val = welch_t_test(m_h2.samples_ms, leg.samples_ms)

        print(f"\n  ▸ {ep['title']} [{ep['category']}]")
        print(f"    URL: {ep['url']}")
        print(
            f"    {'Client':<20} {'Proto':<8} {'Cold(ms)':>9} {'Mean(ms)':>9} {'P50(ms)':>9} "
            f"{'P90(ms)':>9} {'P95(ms)':>9} {'P99(ms)':>9} {'Min(ms)':>9} {'Max(ms)':>9} "
            f"{'StdDev':>8} {'IQR':>7} {'RPS':>8}"
        )
        print("    " + "-" * 132)
        for s in (m_h2, m_h1, leg):
            print(
                f"    {s.name:<20} {s.protocol:<8} {s.cold_ms:>9.2f} {s.mean_ms:>9.2f} {s.median_ms:>9.2f} "
                f"{s.p90_ms:>9.2f} {s.p95_ms:>9.2f} {s.p99_ms:>9.2f} {s.min_ms:>9.2f} {s.max_ms:>9.2f} "
                f"{s.stdev_ms:>8.2f} {s.iqr_ms:>7.2f} {s.rps:>8.1f}"
            )
        print(
            f"    Summary: modern-httplib2 ({m_h2.protocol}) Warm Mean is {speedup_mean:.2f}x vs standard "
            f"({pct_diff:+.1f}% latency change, P50 {speedup_p50:.2f}x, Welch t={t_stat:.2f}, p={p_val:.3f})"
        )
    print()


def print_traversal_section(traversal_stats: dict[str, LatencyStats]) -> None:
    print("─" * 108)
    print("  SUITE 2: SEQUENTIAL MULTI-ENDPOINT TRAVERSAL (10 CHROME VERSION HISTORY ENDPOINTS x 2 ROUNDS)")
    print("─" * 108)
    print(
        f"    {'Client':<22} {'Proto':<8} {'Wall(ms)':>9} {'Mean(ms)':>9} {'P50(ms)':>9} "
        f"{'P90(ms)':>9} {'P95(ms)':>9} {'P99(ms)':>9} {'StdDev':>8} {'RPS':>8} {'KB/s':>9}"
    )
    print("    " + "-" * 114)
    max_rps = max((s.rps for s in traversal_stats.values()), default=1.0)
    for s in traversal_stats.values():
        bar = ascii_bar(s.rps, max_rps, width=16)
        print(
            f"    {s.name:<22} {s.protocol:<8} {s.total_wall_ms:>9.1f} {s.mean_ms:>9.2f} {s.median_ms:>9.2f} "
            f"{s.p90_ms:>9.2f} {s.p95_ms:>9.2f} {s.p99_ms:>9.2f} {s.stdev_ms:>8.2f} {s.rps:>8.1f} "
            f"{s.throughput_kbps:>9.1f}  {bar}"
        )
    m2 = traversal_stats["modern (HTTP/2)"]
    leg = traversal_stats["standard httplib2"]
    if m2.total_wall_ms > 0 and leg.total_wall_ms > 0:
        speedup = leg.total_wall_ms / m2.total_wall_ms
        reduction = (leg.total_wall_ms - m2.total_wall_ms) / leg.total_wall_ms * 100.0
        print(
            f"\n    ▸ Result: modern-httplib2 (HTTP/2) completed the 20-endpoint Chrome Version History walk in "
            f"{m2.total_wall_ms:.1f} ms vs {leg.total_wall_ms:.1f} ms ({speedup:.2f}x throughput, {reduction:+.1f}% wall time)."
        )
    print()


def print_concurrent_section(
    fanout_stats: dict[str, LatencyStats],
    probe_report: dict[str, dict[str, Any]],
    workers: int,
) -> None:
    print("─" * 108)
    print(
        f"  SUITE 3: MULTI-THREADED CONCURRENT FAN-OUT ({workers} THREADS, 48 CHROME VERSION HISTORY API CALLS)"
    )
    print("─" * 108)
    print(
        f"    {'Architecture / Mode':<31} {'Proto':<8} {'Wall(ms)':>9} {'Mean(ms)':>9} {'P50(ms)':>9} "
        f"{'P90(ms)':>9} {'P95(ms)':>9} {'P99(ms)':>9} {'RPS':>8} {'KB/s':>9} {'Err':>4}"
    )
    print("    " + "-" * 124)
    max_rps = max((s.rps for s in fanout_stats.values()), default=1.0)
    for s in fanout_stats.values():
        bar = ascii_bar(s.rps, max_rps, width=18)
        print(
            f"    {s.name:<31} {s.protocol:<8} {s.total_wall_ms:>9.1f} {s.mean_ms:>9.2f} {s.median_ms:>9.2f} "
            f"{s.p90_ms:>9.2f} {s.p95_ms:>9.2f} {s.p99_ms:>9.2f} {s.rps:>8.1f} "
            f"{s.throughput_kbps:>9.1f} {s.errors:>4}  {bar}"
        )

    m2 = fanout_stats["modern (Shared Http, Pooled H2)"]
    leg_new = fanout_stats["standard (New Http() per task)"]
    leg_lock = fanout_stats["standard (Shared Http + Lock)"]

    speedup_vs_new = leg_new.total_wall_ms / m2.total_wall_ms if m2.total_wall_ms > 0 else 0.0
    speedup_vs_lock = leg_lock.total_wall_ms / m2.total_wall_ms if m2.total_wall_ms > 0 else 0.0
    p50_gain_vs_new = (leg_new.median_ms - m2.median_ms) / leg_new.median_ms * 100.0 if leg_new.median_ms > 0 else 0.0
    p50_gain_vs_lock = (leg_lock.median_ms - m2.median_ms) / leg_lock.median_ms * 100.0 if leg_lock.median_ms > 0 else 0.0

    print("\n    ▸ Key Concurrency Comparisons:")
    print(
        f"      • vs. standard (Shared Http + Lock)  : {speedup_vs_lock:.2f}x faster wall-clock "
        f"({m2.rps:.1f} RPS vs {leg_lock.rps:.1f} RPS; P50 per-call queueing+latency reduced by {p50_gain_vs_lock:.1f}%)"
    )
    print(
        f"      • vs. standard (New Http() per task) : {speedup_vs_new:.2f}x faster wall-clock "
        f"({m2.rps:.1f} RPS vs {leg_new.rps:.1f} RPS; P50 per-call latency reduced by {p50_gain_vs_new:.1f}% by avoiding repeated TLS handshakes)"
    )

    print("\n    ▸ Unsynchronized Shared `Http()` Thread-Safety Probe (16 concurrent requests, 0 user locks):")
    for label, info in probe_report.items():
        status_str = "PASS (100% thread-safe)" if info["failures"] == 0 else f"FAIL ({info['failures']}/{info['total']} failed)"
        print(
            f"      • {label:<20}: {info['successes']}/{info['total']} succeeded, "
            f"{info['failures']} errors -> {status_str}"
        )
        if info["failure_types"]:
            print(f"        Sample exceptions : {', '.join(info['failure_types'])}")
    print()


def print_local_microbenchmark_section(cpu_stats: dict[str, dict[str, float]]) -> None:
    print("─" * 108)
    print("  SUITE 4: LOCAL RFC 2616 FILECACHE HITS & URI/IRI NORMALIZATION MICROBENCHMARK")
    print("─" * 108)
    m = cpu_stats["modern-httplib2"]
    l = cpu_stats["standard httplib2"]

    cache_speedup = m["cache_hits_per_sec"] / l["cache_hits_per_sec"] if l["cache_hits_per_sec"] > 0 else 1.0
    iri_speedup = m["iri_ops_per_sec"] / l["iri_ops_per_sec"] if l["iri_ops_per_sec"] > 0 else 1.0

    print(
        f"    {'Library':<22} {'FileCache Hit (µs)':>20} {'FileCache (req/s)':>20} "
        f"{'IRI+urlnorm+safename (µs)':>27} {'IRI Ops/sec':>16}"
    )
    print("    " + "-" * 107)
    for label, d in cpu_stats.items():
        print(
            f"    {label:<22} {d['cache_hit_us']:>20.2f} {d['cache_hits_per_sec']:>20,.0f} "
            f"{d['iri_ops_us']:>27.2f} {d['iri_ops_per_sec']:>16,.0f}"
        )
    print(
        f"\n    ▸ Relative Speed: FileCache hits {cache_speedup:.2f}x | "
        f"IRI/URI normalization + safename {iri_speedup:.2f}x"
    )
    print("=" * 108)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark modern-httplib2 vs standard httplib2")
    parser.add_argument(
        "--iterations",
        type=int,
        default=8,
        help="Number of interleaved warm keep-alive requests per endpoint (default: 8)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of concurrent worker threads for Suite 3 fan-out (default: 8)",
    )
    parser.add_argument(
        "--fanout-rounds",
        type=int,
        default=2,
        help="Number of rounds over the 24 Chrome Version History endpoints in Suite 3 (default: 2 -> 48 requests)",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Optional path to write full benchmark statistics as JSON",
    )
    args = parser.parse_args()

    print_banner(args.iterations, args.workers, args.fanout_rounds)

    # Fast preflight check to verify direct external HTTPS connectivity
    preflight_http = modern_httplib2.Http(timeout=5)
    try:
        pf_resp, _ = preflight_http.request(ENDPOINTS[0]["url"])
        if pf_resp.status >= 400:
            raise RuntimeError(f"Preflight check returned HTTP {pf_resp.status}")
    finally:
        preflight_http.close()

    # Suite 1: Single-Endpoint Cold & Warm Keep-Alive Latency
    all_endpoint_stats: list[tuple[dict[str, str], dict[str, LatencyStats]]] = []
    for idx, ep in enumerate(ENDPOINTS, 1):
        print(f"  [{idx}/{len(ENDPOINTS)}] Benchmarking {ep['title']} ...", flush=True)
        stats_map = benchmark_single_endpoint(ep["url"], warm_iterations=args.iterations)
        all_endpoint_stats.append((ep, stats_map))
    print()
    print_single_endpoint_section(all_endpoint_stats)

    # Suite 2: Chrome Version History Sequential Multi-Endpoint Traversal
    print("  [Suite 2] Running Chrome Version History 10-endpoint sequential traversal ...", flush=True)
    traversal_stats = benchmark_sequential_traversal(CHROME_TRAVERSAL_URLS, rounds=2)
    print()
    print_traversal_section(traversal_stats)

    # Suite 3: Concurrent Multi-Threaded Fan-Out
    print(
        f"  [Suite 3] Running {args.workers}-thread concurrent fan-out across "
        f"{len(CHROME_FANOUT_URLS) * args.fanout_rounds} Chrome Version History requests ...",
        flush=True,
    )
    fanout_stats = benchmark_concurrent_fanout(
        CHROME_FANOUT_URLS,
        workers=args.workers,
        rounds=args.fanout_rounds,
    )
    probe_report = benchmark_thread_safety_probe(CHROME_FANOUT_URLS, workers=args.workers)
    print()
    print_concurrent_section(fanout_stats, probe_report, workers=args.workers)

    # Suite 4: Local FileCache & CPU Microbenchmarks
    print("  [Suite 4] Running local RFC 2616 FileCache & IRI/URI normalization microbenchmarks ...", flush=True)
    cpu_stats = benchmark_local_cache_and_cpu(iterations=1500)
    print()
    print_local_microbenchmark_section(cpu_stats)

    if args.json_out:
        payload = {
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "modern_httplib2_version": modern_httplib2.__version__,
                "httpx_version": httpx.__version__,
                "httpcore_version": httpcore.__version__,
                "standard_httplib2_version": legacy_httplib2.__version__,
            },
            "suite1_endpoints": {
                ep["id"]: {k: asdict(v) for k, v in smap.items()} for ep, smap in all_endpoint_stats
            },
            "suite2_traversal": {k: asdict(v) for k, v in traversal_stats.items()},
            "suite3_concurrent_fanout": {k: asdict(v) for k, v in fanout_stats.items()},
            "suite3_thread_safety_probe": probe_report,
            "suite4_local_cpu": cpu_stats,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\n  Saved JSON report to: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
