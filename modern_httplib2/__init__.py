"""Small, fast, modern HTTP client library for Python 3.11+ powered by httpx."""

import base64
import calendar
import contextlib
import copy
import email
import email.feedparser
from email import header
import email.message
import email.utils
import errno
import functools
from gettext import gettext as _
from hashlib import md5 as _md5
from hashlib import sha1 as _sha
import hmac
import http.client
import os
import queue
import random
import re
import select
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import zlib

if sys.version_info < (3, 11):
    raise RuntimeError("modern-httplib2 requires Python 3.11 or newer")

from .decode import DecoderProtocol, DeflateDecoder, LimitDecoder, ZlibDecoder
from .patch import is_patched, patch, unpatch

__author__ = "Jay Lee"
__email__ = "jay0lee@gmail.com"
__copyright__ = "Copyright 2026, Jay Lee"
__contributors__ = ["Jay Lee"]
__license__ = "MIT"
__version__ = "1.32.0"

import httpcore
from httpcore._backends.base import (
    NetworkBackend as _HttpcoreNetworkBackend,
    NetworkStream as _HttpcoreNetworkStream,
)
from httpcore._exceptions import (
    ConnectError as _HttpcoreConnectError,
    ConnectTimeout as _HttpcoreConnectTimeout,
    LocalProtocolError as _HttpcoreLocalProtocolError,
    PoolTimeout as _HttpcorePoolTimeout,
    ProtocolError as _HttpcoreProtocolError,
    ProxyError as _HttpcoreProxyError,
    ReadError as _HttpcoreReadError,
    ReadTimeout as _HttpcoreReadTimeout,
    RemoteProtocolError as _HttpcoreRemoteProtocolError,
    TimeoutException as _HttpcoreTimeoutException,
    WriteError as _HttpcoreWriteError,
    WriteTimeout as _HttpcoreWriteTimeout,
)
from httpcore._models import (
    Origin as _HttpcoreOrigin,
    Request as _HttpcoreRequest,
    Response as _HttpcoreResponse,
    URL as _HttpcoreURL,
)
import httpcore._sync.connection as _httpcore_connection_mod
from httpcore._sync.connection import HTTPConnection as _HttpcoreHTTPConnection
from httpcore._sync.connection_pool import ConnectionPool as _HttpcoreConnectionPool
from httpcore._sync.http2 import HTTP2Connection as _HttpcoreHTTP2Connection
from httpcore._synchronization import Semaphore as _HttpcoreSemaphore
from httpcore._utils import is_socket_readable as _is_socket_readable
import httpx

try:
    import socks
except ImportError:
    socks = None

from . import auth, certs
from .error import *
from .iri2uri import iri2uri


def has_timeout(timeout):
    return timeout is not None and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT


__all__ = [
    "AUTO_DOWNGRADE_HTTP2",
    "ENABLE_HTTP2",
    "FailedToDecompressContent",
    "Http",
    "HttpLib2Error",
    "ProxyInfo",
    "REDIRECT_CODES",
    "RETRIES",
    "RedirectLimit",
    "RedirectMissingLocation",
    "Response",
    "debug_print",
    "debuglevel",
    "disable_http2",
    "enable_http2",
    "force_http11",
    "is_patched",
    "patch",
    "reset_downgraded_hosts",
    "set_auto_downgrade_http2",
    "set_enable_http2",
    "unpatch",
    "UnimplementedDigestAuthOptionError",
    "UnimplementedHmacDigestAuthOptionError",
]

# The httplib debug level, set to a non-zero value to get debug output
debuglevel = 0


def _debug_print(*args, **kwargs):
    """Output debug messages, honoring custom print monkey-patches on httplib2, modern_httplib2, or http.client."""
    httplib2_mod = sys.modules.get("httplib2") or sys.modules.get(__name__)
    printer = getattr(httplib2_mod, "debug_print", None)
    if printer is None or printer is _debug_print:
        printer = getattr(httplib2_mod, "print", None)
    if printer is None:
        printer = getattr(http.client, "print", None)
    if printer is None:
        printer = print
    str_args = tuple(str(a) if not isinstance(a, str) else a for a in args)
    printer(*str_args, **kwargs)


debug_print = _debug_print


def _env_bool(var_name: str, default: bool) -> bool:
    val = os.environ.get(var_name)
    if val is None:
        return default
    val = val.strip().lower()
    return val not in ("0", "false", "no", "off", "")


# Global flags to enable or disable HTTP/2 and auto-downgrade fallback
ENABLE_HTTP2 = _env_bool(
    "MODERN_HTTPLIB2_ENABLE_HTTP2",
    _env_bool("HTTPLIB2_ENABLE_HTTP2", True),
)

AUTO_DOWNGRADE_HTTP2 = _env_bool(
    "MODERN_HTTPLIB2_AUTO_DOWNGRADE",
    _env_bool("HTTPLIB2_AUTO_DOWNGRADE", True),
)

# Thread-safe set of hosts (authorities) that have been downgraded to HTTP/1.1
DOWNGRADED_HOSTS = set()
_DOWNGRADE_LOCK = threading.Lock()


def force_http11():
    """Globally force all modern-httplib2 connections to HTTP/1.1."""
    set_enable_http2(False)


def disable_http2():
    """Globally disable HTTP/2 for all modern-httplib2 connections."""
    set_enable_http2(False)


def enable_http2():
    """Globally enable HTTP/2 for modern-httplib2 connections."""
    set_enable_http2(True)


def set_enable_http2(enabled: bool):
    """Globally enable or disable HTTP/2.

    When disabled, ALPN will only advertise HTTP/1.1 and connections will use
    standard HTTP/1.1 pooling.
    """
    global ENABLE_HTTP2
    ENABLE_HTTP2 = bool(enabled)
    Http.enable_http2 = bool(enabled)
    HTTPSConnectionWithTimeout.enable_http2 = bool(enabled)


def set_auto_downgrade_http2(enabled: bool):
    """Globally enable or disable automatic fallback to HTTP/1.1 when HTTP/2 fails."""
    global AUTO_DOWNGRADE_HTTP2
    AUTO_DOWNGRADE_HTTP2 = bool(enabled)
    Http.auto_downgrade_http2 = bool(enabled)


def reset_downgraded_hosts():
    """Reset the set of hosts that were automatically downgraded to HTTP/1.1."""
    with _DOWNGRADE_LOCK:
        DOWNGRADED_HOSTS.clear()


# A request will be tried 'RETRIES' times if it fails at the socket/connection level.
RETRIES = 2

# The number of redirections to follow before giving up.
# Note that only GET redirects are automatically followed.
# Will also honor 301 requests by saving that info and never
# requesting that URI again.
DEFAULT_MAX_REDIRECTS = 5

# Default connection pool size per (scheme, authority)
DEFAULT_POOL_MAXSIZE = 16

# Which headers are hop-by-hop headers by default
HOP_BY_HOP = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
]

# https://tools.ietf.org/html/rfc7231#section-8.1.3
SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")

# To change, assign to `Http().redirect_codes`
REDIRECT_CODES = frozenset((300, 301, 302, 303, 307, 308))

CA_CERTS = certs.where()


def _resolve_ca_certs(ca_certs):
    if ca_certs:
        return ca_certs
    if "HTTPLIB2_CA_CERTS" in os.environ:
        return certs.where()
    return CA_CERTS


DEFAULT_TLS_VERSION = ssl.PROTOCOL_TLS_CLIENT


def _build_ssl_context(
    disable_ssl_certificate_validation,
    ca_certs,
    cert_file=None,
    key_file=None,
    maximum_version=None,
    minimum_version=None,
    key_password=None,
    enable_http2=False,
):
    context = ssl.SSLContext(DEFAULT_TLS_VERSION)
    context.check_hostname = not disable_ssl_certificate_validation
    context.verify_mode = ssl.CERT_NONE if disable_ssl_certificate_validation else ssl.CERT_REQUIRED

    if maximum_version is not None:
        context.maximum_version = (
            getattr(ssl.TLSVersion, maximum_version)
            if isinstance(maximum_version, str)
            else maximum_version
        )
    if minimum_version is not None:
        context.minimum_version = (
            getattr(ssl.TLSVersion, minimum_version)
            if isinstance(minimum_version, str)
            else minimum_version
        )

    if not disable_ssl_certificate_validation:
        context.load_verify_locations(ca_certs)

    if cert_file:
        context.load_cert_chain(cert_file, key_file, key_password)

    if enable_http2 and ENABLE_HTTP2:
        with contextlib.suppress(NotImplementedError, ssl.SSLError):
            context.set_alpn_protocols(["h2", "http/1.1"])
    else:
        with contextlib.suppress(NotImplementedError, ssl.SSLError):
            context.set_alpn_protocols(["http/1.1"])

    return context


def _get_end2end_headers(response):
    hopbyhop = set(HOP_BY_HOP)
    hopbyhop.update(x.strip() for x in response.get("connection", "").split(","))
    return [header for header in response if header not in hopbyhop]


def _errno_from_exception(e):
    try:
        return e.errno
    except AttributeError:
        pass

    # socket.error and common wrap in .args
    try:
        if e.args:
            return _errno_from_exception(e.args[0])
    except AttributeError:
        pass

    # pysocks.ProxyError wraps in .socket_err
    try:
        if e.socket_err:
            return _errno_from_exception(e.socket_err)
    except AttributeError:
        pass

    return None


URI = re.compile(r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?")


def parse_uri(uri):
    """Parses a URI using the regex given in Appendix B of RFC 3986.

    (scheme, authority, path, query, fragment) = parse_uri(uri)
    """
    groups = URI.match(uri).groups()
    return (groups[1], groups[3], groups[4], groups[6], groups[8])


def urlnorm(uri):
    scheme, authority, path, query, fragment = parse_uri(uri)
    if not scheme or not authority:
        raise RelativeURIError(f"Only absolute URIs are allowed. uri = {uri}")
    authority = authority.lower()
    scheme = scheme.lower()
    if not path:
        path = "/"
    request_uri = f"{path}?{query}" if query else path
    defrag_uri = f"{scheme}://{authority}{request_uri}"
    return scheme, authority, request_uri, defrag_uri


# Cache filename construction
re_url_scheme = re.compile(r"^\w+://")
re_unsafe = re.compile(r"[^\w\-_.()=!]+", re.ASCII)


def safename(filename):
    """Return a filename suitable for the cache.
    Strips dangerous and common characters to create a filename we
    can use to store the cache in.
    """
    if isinstance(filename, bytes):
        filename_bytes = filename
        filename = filename.decode("utf-8")
    else:
        filename_bytes = filename.encode("utf-8")
    filemd5 = _md5(filename_bytes).hexdigest()
    filename = re_url_scheme.sub("", filename)
    filename = re_unsafe.sub("", filename)

    # Limit length of filename to 90 chars (plus 1 comma + 32 md5 = 123 chars)
    return f"{filename[:90]},{filemd5}"


NORMALIZE_SPACE = re.compile(r"(?:\r\n)?[ \t]+")


def _normalize_headers(headers):
    return {
        _convert_byte_str(key).lower(): NORMALIZE_SPACE.sub(_convert_byte_str(value), " ").strip()
        for key, value in headers.items()
    }


def _convert_byte_str(s):
    if not isinstance(s, str):
        return str(s, "utf-8")
    return s


def _parse_cache_control(headers):
    if "cache-control" not in headers:
        return {}
    retval = {}
    for part in headers["cache-control"].split(","):
        if "=" in part:
            name, _, val = part.partition("=")
            retval[name.strip().lower()] = val.strip().lower()
        else:
            retval[part.strip().lower()] = 1
    return retval


# Whether to use a strict mode to parse WWW-Authenticate headers
# Might lead to bad results in case of ill-formed header value,
# so disabled by default, falling back to relaxed parsing.
# Set to true to turn on, useful for testing servers.
USE_WWW_AUTH_STRICT_PARSING = 0


def _entry_disposition(response_headers, request_headers):
    """Determine freshness from the Date, Expires and Cache-Control headers."""
    retval = "STALE"
    cc = _parse_cache_control(request_headers)
    cc_response = _parse_cache_control(response_headers)

    if "pragma" in request_headers and request_headers["pragma"].lower().find("no-cache") != -1:
        retval = "TRANSPARENT"
        if "cache-control" not in request_headers:
            request_headers["cache-control"] = "no-cache"
    elif "no-cache" in cc:
        retval = "TRANSPARENT"
    elif "no-cache" in cc_response:
        retval = "STALE"
    elif "only-if-cached" in cc:
        retval = "FRESH"
    elif "date" in response_headers:
        date = calendar.timegm(email.utils.parsedate_tz(response_headers["date"]))
        now = time.time()
        current_age = max(0, now - date)
        if "max-age" in cc_response:
            try:
                freshness_lifetime = int(cc_response["max-age"])
            except ValueError:
                freshness_lifetime = 0
        elif "expires" in response_headers:
            expires = email.utils.parsedate_tz(response_headers["expires"])
            if None == expires:
                freshness_lifetime = 0
            else:
                freshness_lifetime = max(0, calendar.timegm(expires) - date)
        else:
            freshness_lifetime = 0
        if "max-age" in cc:
            try:
                freshness_lifetime = int(cc["max-age"])
            except ValueError:
                freshness_lifetime = 0
        if "min-fresh" in cc:
            try:
                min_fresh = int(cc["min-fresh"])
            except ValueError:
                min_fresh = 0
            current_age += min_fresh
        if freshness_lifetime > current_age:
            retval = "FRESH"
    return retval


def _decompressContent(response, new_content, limit_kwargs):
    content = new_content
    encoding_header = "content-encoding"
    encoding = response.get(encoding_header, None)
    limit_wrap = functools.partial(LimitDecoder, **limit_kwargs)
    try:
        if encoding in ["gzip", "deflate", "zlib"]:
            try:
                content = limit_wrap(ZlibDecoder()).consume_bytes(new_content, 0)
            except (IOError, zlib.error):
                content = limit_wrap(DeflateDecoder()).consume_bytes(new_content, 0)
            response["content-length"] = str(len(content))
            # Record the historical presence of the encoding in a way the won't interfere.
            response["-content-encoding"] = response.pop(encoding_header)
    except (IOError, zlib.error):
        content = ""
        raise FailedToDecompressContent(
            _("Content purported to be compressed with %s but failed to decompress.")
            % encoding,
            response,
            content,
        )
    return content


def _bind_write_headers(msg):
    def _write_headers(self):
        # Self refers to the Generator object.
        for h, v in msg.items():
            print("%s:" % h, end=" ", file=self._fp)
            if isinstance(v, header.Header):
                print(v.encode(maxlinelen=self._maxheaderlen), file=self._fp)
            else:
                # email.Header got lots of smarts, so use it.
                headers = header.Header(v, maxlinelen=self._maxheaderlen, charset="utf-8", header_name=h)
                print(headers.encode(), file=self._fp)
        # A blank line always separates headers from body.
        print(file=self._fp)

    return _write_headers


def _updateCache(request_headers, response_headers, content, cache, cachekey):
    if cachekey:
        cc = _parse_cache_control(request_headers)
        cc_response = _parse_cache_control(response_headers)
        if "no-store" in cc or "no-store" in cc_response:
            cache.delete(cachekey)
        else:
            info = email.message.Message()
            for key, value in response_headers.items():
                if key not in ["status", "content-encoding", "transfer-encoding"]:
                    info[key] = value

            # Add annotations to the cache to indicate what headers
            # are variant for this request.
            vary = response_headers.get("vary", None)
            if vary:
                vary_headers = vary.lower().replace(" ", "").split(",")
                for header in vary_headers:
                    key = "-varied-%s" % header
                    try:
                        info[key] = request_headers[header]
                    except KeyError:
                        pass

            status = response_headers.status
            if status == 304:
                status = 200

            status_header = "status: %d\r\n" % status

            try:
                header_str = info.as_string()
            except UnicodeEncodeError:
                setattr(info, "_write_headers", _bind_write_headers(info))
                header_str = info.as_string()

            header_str = re.sub("\r(?!\n)|(?<!\r)\n", "\r\n", header_str)
            text = b"".join([status_header.encode("utf-8"), header_str.encode("utf-8"), content])

            cache.set(cachekey, text)


def _cnonce():
    dig = _md5(
        ("%s:%s" % (time.ctime(), ["0123456789"[random.randrange(0, 9)] for i in range(20)])).encode("utf-8")
    ).hexdigest()
    return dig[:16]


def _wsse_username_token(cnonce, iso_now, password):
    return (
        base64.b64encode(_sha(f"{cnonce}{iso_now}{password}".encode("utf-8")).digest()).strip().decode("utf-8")
    )


class Authentication:
    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        (scheme, authority, path, query, fragment) = parse_uri(request_uri)
        self.path = path
        self.host = host
        self.credentials = credentials
        self.http = http

    def depth(self, request_uri):
        (scheme, authority, path, query, fragment) = parse_uri(request_uri)
        return request_uri[len(self.path) :].count("/")

    def inscope(self, host, request_uri):
        (scheme, authority, path, query, fragment) = parse_uri(request_uri)
        return (host == self.host) and path.startswith(self.path)

    def request(self, method, request_uri, headers, content):
        """Modify the request headers to add the appropriate
        Authorization header. Override this in sub-classes."""
        pass

    def response(self, response, content):
        """Gives us a chance to update with new nonces
        or such returned from the last authorized response.
        Override this in sub-classes if necessary.

        Return TRUE if the request is to be retried, for
        example Digest may return stale=true.
        """
        return False

    def __eq__(self, auth):
        return False

    def __ne__(self, auth):
        return True

    def __lt__(self, auth):
        return True

    def __gt__(self, auth):
        return False

    def __le__(self, auth):
        return True

    def __ge__(self, auth):
        return False

    def __bool__(self):
        return True


class BasicAuthentication(Authentication):
    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        super().__init__(credentials, host, request_uri, headers, response, content, http)

    def request(self, method, request_uri, headers, content):
        """Modify the request headers to add the appropriate
        Authorization header."""
        user, password = self.credentials
        encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).strip().decode("utf-8")
        headers["authorization"] = f"Basic {encoded}"


class DigestAuthentication(Authentication):
    """Only do qop='auth' and MD5, since that
    is all Apache currently implements"""

    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        super().__init__(credentials, host, request_uri, headers, response, content, http)
        self.challenge = auth._parse_www_authenticate(response, "www-authenticate")["digest"]
        qop = self.challenge.get("qop", "auth")
        self.challenge["qop"] = "auth" if "auth" in [x.strip() for x in qop.split()] else None
        if self.challenge["qop"] is None:
            raise UnimplementedDigestAuthOptionError(_(f"Unsupported value for qop: {qop}."))
        self.challenge["algorithm"] = self.challenge.get("algorithm", "MD5").upper()
        if self.challenge["algorithm"] != "MD5":
            raise UnimplementedDigestAuthOptionError(
                _(f"Unsupported value for algorithm: {self.challenge['algorithm']}.")
            )
        self.A1 = "".join([self.credentials[0], ":", self.challenge["realm"], ":", self.credentials[1]])
        self.challenge["nc"] = 1

    def request(self, method, request_uri, headers, content, cnonce=None):
        """Modify the request headers"""
        H = lambda x: _md5(x.encode("utf-8")).hexdigest()
        KD = lambda s, d: H(f"{s}:{d}")
        A2 = f"{method}:{request_uri}"
        self.challenge["cnonce"] = cnonce or _cnonce()
        request_digest = '"%s"' % KD(
            H(self.A1),
            f"{self.challenge['nonce']}:{self.challenge['nc']:08x}:{self.challenge['cnonce']}:{self.challenge['qop']}:{H(A2)}",
        )
        headers["authorization"] = (
            f'Digest username="{self.credentials[0]}", realm="{self.challenge["realm"]}", '
            f'nonce="{self.challenge["nonce"]}", uri="{request_uri}", '
            f'algorithm={self.challenge["algorithm"]}, response={request_digest}, '
            f'qop={self.challenge["qop"]}, nc={self.challenge["nc"]:08x}, '
            f'cnonce="{self.challenge["cnonce"]}"'
        )
        if self.challenge.get("opaque"):
            headers["authorization"] += f', opaque="{self.challenge["opaque"]}"'
        self.challenge["nc"] += 1

    def response(self, response, content):
        if "authentication-info" not in response:
            challenge = auth._parse_www_authenticate(response, "www-authenticate").get("digest", {})
            if "true" == challenge.get("stale"):
                self.challenge["nonce"] = challenge["nonce"]
                self.challenge["nc"] = 1
                return True
        else:
            updated_challenge = auth._parse_authentication_info(response, "authentication-info")

            if "nextnonce" in updated_challenge:
                self.challenge["nonce"] = updated_challenge["nextnonce"]
                self.challenge["nc"] = 1
        return False


class HmacDigestAuthentication(Authentication):
    """HMAC Digest authentication implementation."""

    __author__ = "Jay Lee"

    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        super().__init__(credentials, host, request_uri, headers, response, content, http)
        challenge = auth._parse_www_authenticate(response, "www-authenticate")
        self.challenge = challenge["hmacdigest"]
        self.challenge["reason"] = self.challenge.get("reason", "unauthorized")
        if self.challenge["reason"] not in ["unauthorized", "integrity"]:
            self.challenge["reason"] = "unauthorized"
        self.challenge["salt"] = self.challenge.get("salt", "")
        if not self.challenge.get("snonce"):
            raise UnimplementedHmacDigestAuthOptionError(
                _("The challenge doesn't contain a server nonce, or this one is empty.")
            )
        self.challenge["algorithm"] = self.challenge.get("algorithm", "HMAC-SHA-1")
        if self.challenge["algorithm"] not in ["HMAC-SHA-1", "HMAC-MD5"]:
            raise UnimplementedHmacDigestAuthOptionError(
                _(f"Unsupported value for algorithm: {self.challenge['algorithm']}.")
            )
        self.challenge["pw-algorithm"] = self.challenge.get("pw-algorithm", "SHA-1")
        if self.challenge["pw-algorithm"] not in ["SHA-1", "MD5"]:
            raise UnimplementedHmacDigestAuthOptionError(
                _(f"Unsupported value for pw-algorithm: {self.challenge['pw-algorithm']}.")
            )
        if self.challenge["algorithm"] == "HMAC-MD5":
            self.hashmod = _md5
        else:
            self.hashmod = _sha
        if self.challenge["pw-algorithm"] == "MD5":
            self.pwhashmod = _md5
        else:
            self.pwhashmod = _sha
        self.key = "".join(
            [
                self.credentials[0],
                ":",
                self.pwhashmod.new("".join([self.credentials[1], self.challenge["salt"]])).hexdigest().lower(),
                ":",
                self.challenge["realm"],
            ]
        )
        self.key = self.pwhashmod.new(self.key).hexdigest().lower()

    def request(self, method, request_uri, headers, content):
        """Modify the request headers"""
        keys = _get_end2end_headers(headers)
        keylist = "".join([f"{k} " for k in keys])
        headers_val = "".join([headers[k] for k in keys])
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cnonce = _cnonce()
        request_digest = f"{method}:{request_uri}:{cnonce}:{self.challenge['snonce']}:{headers_val}"
        request_digest = hmac.new(self.key, request_digest, self.hashmod).hexdigest().lower()
        headers["authorization"] = (
            f'HMACDigest username="{self.credentials[0]}", realm="{self.challenge["realm"]}", '
            f'snonce="{self.challenge["snonce"]}", cnonce="{cnonce}", uri="{request_uri}", '
            f'created="{created}", response="{request_digest}", headers="{keylist}"'
        )

    def response(self, response, content):
        challenge = auth._parse_www_authenticate(response, "www-authenticate").get("hmacdigest", {})
        return challenge.get("reason") in ["integrity", "stale"]


class WsseAuthentication(Authentication):
    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        super().__init__(credentials, host, request_uri, headers, response, content, http)

    def request(self, method, request_uri, headers, content):
        """Modify the request headers to add the appropriate
        Authorization header."""
        headers["authorization"] = 'WSSE profile="UsernameToken"'
        iso_now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cnonce = _cnonce()
        password_digest = _wsse_username_token(cnonce, iso_now, self.credentials[1])
        headers["X-WSSE"] = (
            f'UsernameToken Username="{self.credentials[0]}", PasswordDigest="{password_digest}", '
            f'Nonce="{cnonce}", Created="{iso_now}"'
        )


class GoogleLoginAuthentication(Authentication):
    def __init__(self, credentials, host, request_uri, headers, response, content, http):
        from urllib.parse import urlencode

        super().__init__(credentials, host, request_uri, headers, response, content, http)
        challenge = auth._parse_www_authenticate(response, "www-authenticate")
        service = challenge["googlelogin"].get("service", "xapi")
        if service == "xapi" and request_uri.find("calendar") > 0:
            service = "cl"

        auth_dict = dict(Email=credentials[0], Passwd=credentials[1], service=service, source=headers["user-agent"])
        resp, content = self.http.request(
            "https://www.google.com/accounts/ClientLogin",
            method="POST",
            body=urlencode(auth_dict),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        lines = content.split("\n")
        d = dict(tuple(line.split("=", 1)) for line in lines if line)
        if resp.status == 403:
            self.Auth = ""
        else:
            self.Auth = d["Auth"]

    def request(self, method, request_uri, headers, content):
        """Modify the request headers to add the appropriate
        Authorization header."""
        headers["authorization"] = f"GoogleLogin Auth={self.Auth}"


AUTH_SCHEME_CLASSES = {
    "basic": BasicAuthentication,
    "wsse": WsseAuthentication,
    "digest": DigestAuthentication,
    "hmacdigest": HmacDigestAuthentication,
    "googlelogin": GoogleLoginAuthentication,
}

AUTH_SCHEME_ORDER = ["hmacdigest", "googlelogin", "digest", "wsse", "basic"]


class FileCache:
    """Uses a local directory as a store for cached files.
    Not really safe to use if multiple threads or processes are going to
    be running on the same cache.
    """

    def __init__(self, cache, safe=safename):
        self.cache = cache
        self.safe = safe
        os.makedirs(self.cache, exist_ok=True)

    def get(self, key):
        cache_full_path = os.path.join(self.cache, self.safe(key))
        with contextlib.suppress(OSError):
            with open(cache_full_path, "rb") as f:
                return f.read()
        return None

    def set(self, key, value):
        cache_full_path = os.path.join(self.cache, self.safe(key))
        with open(cache_full_path, "wb") as f:
            f.write(value)

    def delete(self, key):
        cache_full_path = os.path.join(self.cache, self.safe(key))
        with contextlib.suppress(FileNotFoundError):
            os.remove(cache_full_path)


class Credentials:
    def __init__(self):
        self.credentials = []

    def add(self, name, password, domain=""):
        self.credentials.append((domain.lower(), name, password))

    def clear(self):
        self.credentials = []

    def iter(self, domain):
        for cdomain, name, password in self.credentials:
            if cdomain == "" or domain == cdomain:
                yield (name, password)


class KeyCerts(Credentials):
    """Identical to Credentials except that
    name/password are mapped to key/cert."""

    def add(self, key, cert, domain, password):
        self.credentials.append((domain.lower(), key, cert, password))

    def iter(self, domain):
        for cdomain, key, cert, password in self.credentials:
            if cdomain == "" or domain == cdomain:
                yield (key, cert, password)


class AllHosts:
    pass


class ProxyInfo:
    """Collect information required to use a proxy."""

    bypass_hosts = ()

    def __init__(
        self, proxy_type, proxy_host, proxy_port, proxy_rdns=True, proxy_user=None, proxy_pass=None, proxy_headers=None,
    ):
        if isinstance(proxy_user, bytes):
            proxy_user = proxy_user.decode()
        if isinstance(proxy_pass, bytes):
            proxy_pass = proxy_pass.decode()
        (
            self.proxy_type,
            self.proxy_host,
            self.proxy_port,
            self.proxy_rdns,
            self.proxy_user,
            self.proxy_pass,
            self.proxy_headers,
        ) = (
            proxy_type,
            proxy_host,
            proxy_port,
            proxy_rdns,
            proxy_user,
            proxy_pass,
            proxy_headers,
        )

    def astuple(self):
        return (
            self.proxy_type,
            self.proxy_host,
            self.proxy_port,
            self.proxy_rdns,
            self.proxy_user,
            self.proxy_pass,
            self.proxy_headers,
        )

    def isgood(self):
        return socks and (self.proxy_host is not None) and (self.proxy_port is not None)

    def applies_to(self, hostname):
        return not self.bypass_host(hostname)

    def bypass_host(self, hostname):
        """Has this host been excluded from the proxy config"""
        if self.bypass_hosts is AllHosts:
            return True

        hostname = "." + hostname.lstrip(".")
        for skip_name in self.bypass_hosts:
            # *.suffix
            if skip_name.startswith(".") and hostname.endswith(skip_name):
                return True
            # exact match
            if hostname == "." + skip_name:
                return True
        return False

    def __repr__(self):
        return (
            f"<ProxyInfo type={self.proxy_type} "
            f"host:port={self.proxy_host}:{self.proxy_port} rdns={self.proxy_rdns} "
            f"user={self.proxy_user} headers={self.proxy_headers}>"
        )


def proxy_info_from_environment(method="http"):
    """Read proxy info from the environment variables."""
    if method not in ("http", "https"):
        return

    env_var = method + "_proxy"
    url = os.environ.get(env_var, os.environ.get(env_var.upper()))
    if not url:
        return
    return proxy_info_from_url(url, method, noproxy=None)


def proxy_info_from_url(url, method="http", noproxy=None):
    """Construct a ProxyInfo from a URL (such as http_proxy env var)"""
    url = urllib.parse.urlparse(url)

    proxy_type = 3  # socks.PROXY_TYPE_HTTP
    if url.scheme == "socks4":
        proxy_type = 1  # socks.PROXY_TYPE_SOCKS4
    elif url.scheme == "socks5" or url.scheme == "socks":
        proxy_type = 2  # socks.PROXY_TYPE_SOCKS5
    pi = ProxyInfo(
        proxy_type=proxy_type,
        proxy_host=url.hostname,
        proxy_port=url.port or dict(https=443, http=80)[method],
        proxy_user=url.username or None,
        proxy_pass=url.password or None,
        proxy_headers=None,
    )

    bypass_hosts = []
    # If not given an explicit noproxy value, respect values in env vars.
    if noproxy is None:
        noproxy = os.environ.get("no_proxy", os.environ.get("NO_PROXY", ""))
    # Special case: A single '*' character means all hosts should be bypassed.
    if noproxy == "*":
        bypass_hosts = AllHosts
    elif noproxy.strip():
        bypass_hosts = noproxy.split(",")
        bypass_hosts = tuple(filter(bool, bypass_hosts))  # To exclude empty string.

    pi.bypass_hosts = bypass_hosts
    return pi


import h2.connection as _h2_connection
import h2.events as _h2_events
import h2.exceptions as _h2_exceptions
from httpcore._sync.http11 import HTTP11Connection as _HttpcoreHTTP11Connection
from httpcore._sync.http2 import (
    HTTP2ConnectionByteStream as _HttpcoreHTTP2ConnectionByteStream,
     HTTPConnectionState as _HttpcoreHTTPConnectionState,
    has_body_headers as _httpcore_has_body_headers,
)


def _unwrap_httpcore_exception(exc):
    """Translate httpcore/httpx exceptions into the stdlib/socket/http.client exceptions
    expected by httplib2 callers and _conn_request retry logic.
    """
    if isinstance(
        exc,
        (
            socket.timeout,
            socket.gaierror,
            ssl.SSLError,
            ssl.CertificateError,
            http.client.HTTPException,
            HttpLib2Error,
        ),
    ):
        return exc

    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    if isinstance(
        cause,
        (
            socket.timeout,
            socket.gaierror,
            ssl.SSLError,
            ssl.CertificateError,
            http.client.HTTPException,
            HttpLib2Error,
            OSError,
        ),
    ):
        return cause

    if isinstance(exc, _HttpcoreTimeoutException):
        return socket.timeout(str(exc))

    if isinstance(exc, _HttpcoreRemoteProtocolError):
        msg = str(exc)
        if "Server disconnected" in msg or "ConnectionClosed" in msg:
            return http.client.RemoteDisconnected(msg)
        return http.client.BadStatusLine(msg)

    if isinstance(exc, (_HttpcoreLocalProtocolError, _HttpcoreProtocolError)):
        return http.client.HTTPException(str(exc))

    if isinstance(exc, (_HttpcoreConnectError, _HttpcoreReadError, _HttpcoreWriteError, _HttpcoreProxyError)):
        return OSError(str(exc))

    return exc


def _is_cert_verification_error(exc):
    """Check if exception represents an SSL certificate verification or TLS policy failure."""
    if isinstance(exc, (ssl.CertificateError, getattr(ssl, "SSLCertVerificationError", ()))):
        return True
    msg = str(exc).lower()
    non_downgrade_ssl_terms = (
        "certificate verify failed",
        "cert_has_expired",
        "certificate_unknown",
        "unknown_ca",
        "self_signed_cert",
        "self signed certificate",
        "hostname",
        "ip address mismatch",
        "wrong_version_number",
        "unsupported_protocol",
        "protocol_version",
        "no_ciphers_available",
        "no shared cipher",
        "handshake_failure",
        "insufficient_security",
    )
    return any(term in msg for term in non_downgrade_ssl_terms)


def _should_downgrade_on_error(exc):
    """Determine whether an error on an HTTP/2 connection warrants automatic fallback to HTTP/1.1."""
    if _is_cert_verification_error(exc):
        return False
    if isinstance(exc, (socket.timeout, socket.gaierror, ConnectionRefusedError)):
        return False
    if isinstance(
        exc,
        (
            http.client.BadStatusLine,
            http.client.RemoteDisconnected,
            http.client.HTTPException,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            ssl.SSLError,
        ),
    ):
        return True
    if "h2" in type(exc).__module__:
        return True
    if isinstance(exc, OSError):
        errno_ = _errno_from_exception(exc)
        if errno_ in (
            errno.ECONNREFUSED,
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.EADDRNOTAVAIL,
            errno.EACCES,
            errno.EPERM,
        ):
            return False
        if errno_ in (errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED, errno.EPROTO):
            return True
        return True
    msg = str(exc).lower()
    h2_terms = ("http/2", "h2", "protocol", "stream", "frame", "goaway", "rst_stream", "flow control")
    return any(term in msg for term in h2_terms)


_HALF_CLOSED_SOCKS = []


def _wait_socket(sock: socket.socket, for_write: bool, timeout: float | None) -> bool:
    try:
        if for_write:
            _, writable, _ = select.select([], [sock], [], timeout)
            return bool(writable)
        readable, _, _ = select.select([sock], [], [], timeout)
        return bool(readable)
    except ValueError:
        if sock.fileno() < 0:
            raise OSError(errno.EBADF, "Bad file descriptor")
        poller = select.poll()
        poller.register(sock, select.POLLOUT if for_write else select.POLLIN)
        timeout_ms = None if timeout is None else max(0, int(timeout * 1000))
        return bool(poller.poll(timeout_ms))


class _Httplib2SyncStream(_HttpcoreNetworkStream):
    """Custom httpcore NetworkStream wrapping a raw/SSL/PySocks socket while preserving
    stdlib exception types, thread-safe concurrent SSLSocket read/write multiplexing,
    and half-closed socket semantics on read timeouts.
    """

    def __init__(self, sock, owner=None, enable_http2=False):
        self._sock = sock
        self._owner = owner
        self._enable_http2 = enable_http2
        self._timed_out = False
        self._tls_started = isinstance(sock, ssl.SSLSocket)
        self._active_request = None
        self._ssl_lock = threading.Lock()

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        sock = self._sock
        if sock is None:
            return b""
        if self._active_request is not None:
            self._active_request.extensions["request_sent"] = True
        eff_timeout = timeout if has_timeout(timeout) else None
        if isinstance(sock, ssl.SSLSocket):
            deadline = (time.monotonic() + eff_timeout) if eff_timeout is not None else None
            while True:
                with self._ssl_lock:
                    if self._sock is None:
                        return b""
                    has_pending = sock.pending() > 0
                if not has_pending:
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self._timed_out = True
                            raise TimeoutError("timed out")
                    else:
                        remaining = None
                    if not _wait_socket(sock, for_write=False, timeout=remaining):
                        self._timed_out = True
                        raise TimeoutError("timed out")
                with self._ssl_lock:
                    if self._sock is None:
                        return b""
                    try:
                        sock.settimeout(0.0)
                        return sock.recv(max_bytes)
                    except (ssl.SSLWantReadError, BlockingIOError):
                        continue
                    except ssl.SSLWantWriteError:
                        pass
                    except TimeoutError:
                        self._timed_out = True
                        raise
                    finally:
                        with contextlib.suppress(OSError):
                            sock.settimeout(eff_timeout)
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._timed_out = True
                        raise TimeoutError("timed out")
                else:
                    remaining = None
                if not _wait_socket(sock, for_write=True, timeout=remaining):
                    self._timed_out = True
                    raise TimeoutError("timed out")
        try:
            sock.settimeout(eff_timeout)
            return sock.recv(max_bytes)
        except TimeoutError:
            self._timed_out = True
            raise

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        sock = self._sock
        if not buffer or sock is None:
            return
        eff_timeout = timeout if has_timeout(timeout) else None
        if isinstance(sock, ssl.SSLSocket):
            deadline = (time.monotonic() + eff_timeout) if eff_timeout is not None else None
            view = memoryview(buffer)
            sent_total = 0
            total_len = len(view)
            try:
                while sent_total < total_len:
                    want_read = False
                    with self._ssl_lock:
                        if self._sock is None:
                            raise OSError(errno.EBADF, "Socket closed")
                        try:
                            sock.settimeout(0.0)
                            sent = sock.send(view[sent_total:])
                            if sent > 0:
                                sent_total += sent
                                continue
                        except (ssl.SSLWantWriteError, BlockingIOError):
                            want_read = False
                        except ssl.SSLWantReadError:
                            want_read = True
                        finally:
                            with contextlib.suppress(OSError):
                                sock.settimeout(eff_timeout)
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self._timed_out = True
                            raise TimeoutError("timed out")
                    else:
                        remaining = None
                    if not _wait_socket(sock, for_write=not want_read, timeout=remaining):
                        self._timed_out = True
                        raise TimeoutError("timed out")
                if self._active_request is not None:
                    self._active_request.extensions["request_sent"] = True
                return
            except TimeoutError:
                self._timed_out = True
                raise
            except OSError as exc:
                if self._active_request is not None:
                    self._active_request.extensions["request_sent"] = True
                raise _HttpcoreWriteError(str(exc)) from exc
        try:
            sock.settimeout(eff_timeout)
            sock.sendall(buffer)
            if self._active_request is not None:
                self._active_request.extensions["request_sent"] = True
        except TimeoutError:
            self._timed_out = True
            raise
        except OSError as exc:
            if self._active_request is not None:
                self._active_request.extensions["request_sent"] = True
            raise _HttpcoreWriteError(str(exc)) from exc

    def close(self) -> None:
        with self._ssl_lock:
            sock = self._sock
            self._sock = None
        if sock is None:
            return
        if self._timed_out:
            self._timed_out = False
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
            _HALF_CLOSED_SOCKS.append(sock)
            while len(_HALF_CLOSED_SOCKS) > 16:
                old_sock = _HALF_CLOSED_SOCKS.pop(0)
                with contextlib.suppress(OSError):
                    old_sock.close()
        else:
            with contextlib.suppress(OSError):
                sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> _HttpcoreNetworkStream:
        if self._tls_started:
            if (
                ssl_context.check_hostname
                and server_hostname is not None
                and isinstance(self._sock, ssl.SSLSocket)
                and getattr(self._sock, "server_hostname", None) not in (None, server_hostname)
            ):
                orig_host = getattr(self._sock, "server_hostname", None)
                self.close()
                raise ssl.CertificateError(
                    f"Hostname mismatch on pre-connected TLS stream: expected {server_hostname!r}, got {orig_host!r}"
                )
            return self
        try:
            if self._enable_http2:
                with contextlib.suppress(NotImplementedError):
                    ssl_context.set_alpn_protocols(["h2", "http/1.1"])
            else:
                with contextlib.suppress(NotImplementedError):
                    ssl_context.set_alpn_protocols(["http/1.1"])
            self._sock.settimeout(timeout if has_timeout(timeout) else None)
            ssl_sock = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname)
            self._sock = ssl_sock
            self._tls_started = True
            if self._owner is not None:
                self._owner._record_sock(ssl_sock)
            return self
        except Exception:
            self.close()
            raise

    def get_extra_info(self, info: str):
        if self._sock is None:
            return None
        if info == "ssl_object" and isinstance(self._sock, ssl.SSLSocket):
            return self._sock._sslobj
        if info == "client_addr":
            return self._sock.getsockname()
        if info == "server_addr":
            return self._sock.getpeername()
        if info == "socket":
            return self._sock
        if info == "is_readable":
            return _is_socket_readable(self._sock)
        return None


class _Httplib2NetworkBackend(_HttpcoreNetworkBackend):
    """Custom httpcore NetworkBackend that uses httplib2's socket/PySocks connection logic
    and supports pre-connected streams from explicit conn.connect() calls.
    """

    def __init__(self, owner):
        self._owner = owner
        self._preconnected_streams = queue.Queue()

    def push_preconnected(self, stream: _Httplib2SyncStream) -> None:
        self._preconnected_streams.put(stream)

    def clear_preconnected(self) -> None:
        while True:
            try:
                stream = self._preconnected_streams.get_nowait()
            except queue.Empty:
                break
            with contextlib.suppress(Exception):
                stream.close()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> _HttpcoreNetworkStream:
        while True:
            try:
                stream = self._preconnected_streams.get_nowait()
            except queue.Empty:
                break
            if stream._sock is not None:
                return stream

        sock = self._owner._connect_raw_socket(
            include_flowinfo=not self._owner._is_https,
            timeout=timeout,
        )
        stream = _Httplib2SyncStream(
            sock,
            owner=self._owner,
            enable_http2=getattr(self._owner, "enable_http2", False),
        )
        self._owner._record_sock(sock)
        return stream


class _Httplib2HTTP2Connection(_HttpcoreHTTP2Connection):
    """High-concurrency thread-safe HTTP/2 connection subclass for httpcore.

    Unlocks all local concurrent streams immediately on the initial connection flight,
    strips HTTP/1.1 connection-specific headers forbidden by RFC 9113, and serializes
    all h2 state machine mutations across concurrent worker threads.
    """

    _FORBIDDEN_H2_HEADERS = frozenset(
        (
            b"host",
            b"transfer-encoding",
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"upgrade",
        )
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._write_lock = threading.RLock()

    def handle_request(self, request: _HttpcoreRequest) -> _HttpcoreResponse:
        with self._state_lock:
            if self._state in (_HttpcoreHTTPConnectionState.ACTIVE, _HttpcoreHTTPConnectionState.IDLE):
                self._request_count += 1
                self._state = _HttpcoreHTTPConnectionState.ACTIVE
            else:
                raise httpcore.ConnectionNotAvailable()

        with self._init_lock:
            if not self._sent_connection_init:
                try:
                    self._send_connection_init(request=request)
                except BaseException:
                    self.close()
                    raise
                self._sent_connection_init = True
                local_settings_max_streams = self._h2_state.local_settings.max_concurrent_streams
                self._max_streams = local_settings_max_streams
                self._max_streams_semaphore = _HttpcoreSemaphore(local_settings_max_streams)

        self._max_streams_semaphore.acquire()
        stream_id = None
        try:
            with self._write_lock:
                if (
                    self._state == _HttpcoreHTTPConnectionState.CLOSED
                    or self._connection_error
                    or self._connection_terminated
                ):
                    self._request_count -= 1
                    self._max_streams_semaphore.release()
                    raise httpcore.ConnectionNotAvailable()
                try:
                    stream_id = self._h2_state.get_next_available_stream_id()
                    self._events[stream_id] = []
                except _h2_exceptions.NoAvailableStreamIDError:
                    self._used_all_stream_ids = True
                    self._request_count -= 1
                    self._max_streams_semaphore.release()
                    raise httpcore.ConnectionNotAvailable()
                self._send_request_headers(request=request, stream_id=stream_id)

            self._send_request_body(request=request, stream_id=stream_id)
            status, headers = self._receive_response(request=request, stream_id=stream_id)
            return _HttpcoreResponse(
                status=status,
                headers=headers,
                content=_HttpcoreHTTP2ConnectionByteStream(self, request, stream_id=stream_id),
                extensions={
                    "http_version": b"HTTP/2",
                    "network_stream": self._network_stream,
                    "stream_id": stream_id,
                },
            )
        except BaseException as exc:
            if stream_id is not None:
                self._response_closed(stream_id=stream_id)
            if isinstance(exc, _h2_exceptions.ProtocolError):
                if self._connection_terminated:
                    raise _HttpcoreRemoteProtocolError(self._connection_terminated)
                raise _HttpcoreLocalProtocolError(exc)
            raise

    def _send_request_headers(self, request: _HttpcoreRequest, stream_id: int) -> None:
        has_nonempty_body = request.extensions.get("has_nonempty_body")
        if has_nonempty_body is None:
            end_stream = not _httpcore_has_body_headers(request)
        else:
            end_stream = not has_nonempty_body

        hosts = [v for k, v in request.headers if k.lower() == b"host"]
        authority = hosts[0] if hosts else request.url.origin.host

        headers = [
            (b":method", request.method),
            (b":authority", authority),
            (b":scheme", request.url.scheme),
            (b":path", request.url.target),
        ]
        for k, v in request.headers:
            kl = k.lower()
            if kl.startswith(b":"):
                raise _HttpcoreLocalProtocolError(f"Illegal HTTP/2 pseudo-header in request headers: {k!r}")
            if kl in self._FORBIDDEN_H2_HEADERS:
                continue
            if kl == b"te" and v.lower() != b"trailers":
                continue
            headers.append((kl, v))

        with self._write_lock:
            self._h2_state.send_headers(stream_id, headers, end_stream=end_stream)
            self._h2_state.increment_flow_control_window(2**24, stream_id=stream_id)
            self._write_outgoing_data(request)
        request.extensions["request_sent"] = True

    def _send_request_body(self, request: _HttpcoreRequest, stream_id: int) -> None:
        has_nonempty_body = request.extensions.get("has_nonempty_body")
        if has_nonempty_body is False:
            return
        if has_nonempty_body is None and not _httpcore_has_body_headers(request):
            return
        for data in request.stream:
            self._send_stream_data(request, stream_id, data)
        self._send_end_stream(request, stream_id)

    def _send_stream_data(self, request: _HttpcoreRequest, stream_id: int, data: bytes) -> None:
        while data:
            max_flow = self._wait_for_outgoing_flow(request, stream_id)
            chunk_size = min(len(data), max_flow)
            chunk, data = data[:chunk_size], data[chunk_size:]
            with self._write_lock:
                self._h2_state.send_data(stream_id, chunk)
                self._write_outgoing_data(request)

    def _send_end_stream(self, request: _HttpcoreRequest, stream_id: int) -> None:
        with self._write_lock:
            self._h2_state.end_stream(stream_id)
            self._write_outgoing_data(request)

    def _wait_for_outgoing_flow(self, request: _HttpcoreRequest, stream_id: int) -> int:
        with self._write_lock:
            local_flow = self._h2_state.local_flow_control_window(stream_id)
            max_frame_size = self._h2_state.max_outbound_frame_size
        flow = min(local_flow, max_frame_size)
        while flow == 0:
            self._receive_events(request)
            with self._write_lock:
                local_flow = self._h2_state.local_flow_control_window(stream_id)
                max_frame_size = self._h2_state.max_outbound_frame_size
            flow = min(local_flow, max_frame_size)
        return flow

    def _receive_response_body(self, request: _HttpcoreRequest, stream_id: int):
        while True:
            event = self._receive_stream_event(request, stream_id)
            if isinstance(event, _h2_events.DataReceived):
                amount = event.flow_controlled_length
                with self._write_lock:
                    self._h2_state.acknowledge_received_data(amount, stream_id)
                    with contextlib.suppress(OSError, _HttpcoreWriteError):
                        self._write_outgoing_data(request)
                yield event.data
            elif isinstance(event, _h2_events.StreamEnded):
                break

    def _read_incoming_data(self, request: _HttpcoreRequest):
        timeouts = request.extensions.get("timeout", {})
        timeout = timeouts.get("read", None)

        if self._read_exception is not None:
            raise self._read_exception

        try:
            data = self._network_stream.read(self.READ_NUM_BYTES, timeout)
            if data == b"":
                raise _HttpcoreRemoteProtocolError("Server disconnected")
        except Exception as exc:
            self._read_exception = exc
            self._connection_error = True
            raise exc

        with self._write_lock:
            events = self._h2_state.receive_data(data)
        return events

    def close(self) -> None:
        with self._write_lock:
            with contextlib.suppress(Exception):
                self._h2_state.close_connection()
        self._state = _HttpcoreHTTPConnectionState.CLOSED
        self._network_stream.close()


class _Httplib2HttpcoreConnection(_HttpcoreHTTPConnection):
    """Subclass of httpcore.HTTPConnection that instantiates _Httplib2HTTP2Connection
    when HTTP/2 is negotiated via ALPN.
    """

    def handle_request(self, request: _HttpcoreRequest) -> _HttpcoreResponse:
        if not self.can_handle_request(request.url.origin):
            raise RuntimeError(f"Cannot handle request URL '{request.url.origin}' on '{self._origin}'")

        try:
            with self._request_lock:
                if self._connection is None:
                    stream = self._connect(request)
                    ssl_object = stream.get_extra_info("ssl_object")
                    http2_negotiated = (
                        ssl_object is not None
                        and ssl_object.selected_alpn_protocol() == "h2"
                    )
                    if http2_negotiated or (self._http2 and not self._http1):
                        self._connection = _Httplib2HTTP2Connection(
                            origin=self._origin,
                            stream=stream,
                            keepalive_expiry=self._keepalive_expiry,
                        )
                    else:
                        self._connection = _HttpcoreHTTP11Connection(
                            origin=self._origin,
                            stream=stream,
                            keepalive_expiry=self._keepalive_expiry,
                        )
        except BaseException as exc:
            self._connect_failed = True
            raise exc

        if isinstance(self._connection, _HttpcoreHTTP11Connection):
            stream = getattr(self._connection, "_network_stream", None)
            if isinstance(stream, _Httplib2SyncStream):
                stream._active_request = request
        return self._connection.handle_request(request)


class _Httplib2ConnectionPool(_HttpcoreConnectionPool):
    """Subclass of httpcore.ConnectionPool that creates _Httplib2HttpcoreConnection instances."""

    def create_connection(self, origin: _HttpcoreOrigin):
        return _Httplib2HttpcoreConnection(
            origin=origin,
            ssl_context=self._ssl_context,
            keepalive_expiry=self._keepalive_expiry,
            http1=self._http1,
            http2=self._http2,
            retries=self._retries,
            local_address=self._local_address,
            uds=self._uds,
            network_backend=self._network_backend,
            socket_options=self._socket_options,
        )

    def _assign_requests_to_connections(self):
        closing_connections = []
        queued_requests = [request for request in self._requests if request.is_queued()]

        for connection in list(self._connections):
            if connection.is_closed():
                self._connections.remove(connection)
            elif queued_requests and connection.has_expired():
                self._connections.remove(connection)
                closing_connections.append(connection)
            elif (
                connection.is_idle()
                and sum(1 for c in self._connections if c.is_idle()) > self._max_keepalive_connections
            ):
                self._connections.remove(connection)
                closing_connections.append(connection)

        for pool_request in queued_requests:
            origin = pool_request.request.url.origin
            available_connections = [
                connection
                for connection in self._connections
                if connection.can_handle_request(origin) and connection.is_available()
            ]
            idle_connections = [
                connection for connection in self._connections if connection.is_idle()
            ]

            if available_connections:
                connection = available_connections[0]
                pool_request.assign_to_connection(connection)
            elif len(self._connections) < self._max_connections:
                connection = self.create_connection(origin)
                self._connections.append(connection)
                pool_request.assign_to_connection(connection)
            elif idle_connections:
                connection = idle_connections[0]
                self._connections.remove(connection)
                closing_connections.append(connection)
                connection = self.create_connection(origin)
                self._connections.append(connection)
                pool_request.assign_to_connection(connection)

        return closing_connections


class _Httplib2RawResponse:
    """Adapter around httpcore.Response providing an http.client.HTTPResponse-compatible interface."""

    def __init__(self, hc_resp: _HttpcoreResponse, method: str = "GET", debuglevel: int = 0):
        self._hc_resp = hc_resp
        self._method = method.upper()
        self.debuglevel = debuglevel
        self._stream_iter = iter(hc_resp.stream)
        self._buffer = b""
        self._closed = False

        self.status = hc_resp.status
        http_ver = hc_resp.extensions.get("http_version", b"HTTP/1.1")
        if http_ver == b"HTTP/2":
            self.version = 20
        elif http_ver == b"HTTP/1.0":
            self.version = 10
        else:
            self.version = 11

        reason_bytes = hc_resp.extensions.get("reason_phrase")
        if reason_bytes is not None:
            self.reason = (
                reason_bytes.decode("iso-8859-1")
                if isinstance(reason_bytes, bytes)
                else str(reason_bytes)
            )
        else:
            self.reason = http.client.responses.get(self.status, "OK")

        self._headers_list = [
            (
                k.decode("iso-8859-1") if isinstance(k, bytes) else str(k),
                v.decode("iso-8859-1") if isinstance(v, bytes) else str(v),
            )
            for k, v in hc_resp.headers
        ]

        self.stream_id = hc_resp.extensions.get("stream_id")

        if self.debuglevel > 0:
            proto_str = http_ver.decode("ascii") if isinstance(http_ver, bytes) else str(http_ver)
            status_line = f"{proto_str} {self.status} {self.reason}\r\n"
            _debug_print("reply:", repr(status_line))
            if self.stream_id is not None:
                _debug_print("stream:", str(self.stream_id))
            for k, v in self._headers_list:
                _debug_print("header:", k + ":", v)

    def set_debuglevel(self, level: int):
        self.debuglevel = level

    def getheaders(self):
        return list(self._headers_list)

    def getheader(self, name, default=None):
        target = name.lower()
        vals = [v for k, v in self._headers_list if k.lower() == target]
        if not vals:
            return default
        return ", ".join(vals)

    def read(self, amt=None) -> bytes:
        if self._method == "HEAD":
            self.close()
            return b""

        if amt is None:
            chunks = [self._buffer] if self._buffer else []
            self._buffer = b""
            if not self._closed:
                try:
                    for chunk in self._stream_iter:
                        if chunk:
                            chunks.append(chunk)
                except _HttpcoreRemoteProtocolError as exc:
                    if "peer closed connection without sending complete message body" not in str(exc):
                        self.close()
                        raise _unwrap_httpcore_exception(exc) from exc
                except Exception as exc:
                    self.close()
                    raise _unwrap_httpcore_exception(exc) from exc
                finally:
                    self.close()
            return b"".join(chunks)

        while len(self._buffer) < amt and not self._closed:
            try:
                chunk = next(self._stream_iter)
                if chunk:
                    self._buffer += chunk
            except StopIteration:
                self.close()
                break
            except _HttpcoreRemoteProtocolError as exc:
                if "peer closed connection without sending complete message body" in str(exc):
                    self.close()
                    break
                self.close()
                raise _unwrap_httpcore_exception(exc) from exc
            except Exception as exc:
                self.close()
                raise _unwrap_httpcore_exception(exc) from exc

        result, self._buffer = self._buffer[:amt], self._buffer[amt:]
        return result

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(Exception):
                self._hc_resp.close()


class HTTPConnectionWithTimeout(http.client.HTTPConnection):
    """HTTPConnection subclass that supports timeouts and thread-safe httpx/httpcore pooling.

    All timeouts are in seconds. If None is passed for timeout then
    Python's default timeout for sockets will be used. See for example
    the docs of socket.setdefaulttimeout():
    http://docs.python.org/library/socket.html#socket.setdefaulttimeout
    """

    _is_https = False
    _uses_httpcore_pool = True
    enable_http2 = False

    @property
    def debuglevel(self):
        if hasattr(self, "_debuglevel"):
            return self._debuglevel
        return debuglevel or getattr(http.client.HTTPConnection, "debuglevel", 0)

    @debuglevel.setter
    def debuglevel(self, val):
        self._debuglevel = val

    def __init__(self, host, port=None, timeout=None, proxy_info=None, pool_maxsize=DEFAULT_POOL_MAXSIZE):
        self._initialized = False
        self._override_sock = None
        self._last_sock = None
        self._local = threading.local()
        self._pool_maxsize = pool_maxsize

        super().__init__(host, port=port, timeout=timeout)
        if isinstance(self.host, str) and self.host.startswith("[") and self.host.endswith("]"):
            self.host = self.host[1:-1]

        self.proxy_info = proxy_info
        if proxy_info and not isinstance(proxy_info, ProxyInfo):
            self.proxy_info = proxy_info("http")

        self._backend = _Httplib2NetworkBackend(self)
        self.httpcore_pool = _Httplib2ConnectionPool(
            max_connections=pool_maxsize,
            max_keepalive_connections=pool_maxsize,
            keepalive_expiry=30.0,
            http1=True,
            http2=False,
            network_backend=self._backend,
        )
        self._initialized = True

    def _record_sock(self, sock):
        self._last_sock = sock
        if hasattr(self, "_local"):
            self._local.last_sock = sock

    @property
    def sock(self):
        if getattr(self, "_override_sock", None) is not None:
            return self._override_sock
        local_obj = getattr(self, "_local", None)
        if local_obj is not None:
            tsock = getattr(local_obj, "last_sock", None)
            if tsock is not None and tsock.fileno() != -1:
                return tsock
        lsock = getattr(self, "_last_sock", None)
        if lsock is not None and lsock.fileno() != -1:
            return lsock
        return None

    @sock.setter
    def sock(self, value):
        if not getattr(self, "_initialized", False):
            self._override_sock = value
            return
        self._override_sock = value
        if value is None:
            self._last_sock = None
            if hasattr(self, "_local"):
                self._local.last_sock = None

    def _connect_raw_socket(self, include_flowinfo=True, timeout=None):
        effective_timeout = self.timeout if timeout is None else timeout
        if self.proxy_info and socks is None:
            raise ProxiesUnavailableError("Proxy support missing but proxy use was requested!")
        if self.proxy_info and self.proxy_info.isgood() and self.proxy_info.applies_to(self.host):
            use_proxy = True
            (
                proxy_type,
                proxy_host,
                proxy_port,
                proxy_rdns,
                proxy_user,
                proxy_pass,
                proxy_headers,
            ) = self.proxy_info.astuple()
            host = proxy_host
            port = proxy_port
        else:
            use_proxy = False
            host = self.host
            port = self.port
            proxy_type = None
            proxy_headers = None

        socket_err = None
        sock = None

        addrinfos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        if isinstance(host, str) and host.lower() == "localhost":
            addrinfos.sort(key=lambda r: 0 if r[0] == socket.AF_INET else 1)

        for res in addrinfos:
            af, socktype, proto, canonname, sa = res
            try:
                if use_proxy:
                    sock = socks.socksocket(af, socktype, proto)
                    sock.setproxy(
                        proxy_type,
                        proxy_host,
                        proxy_port,
                        proxy_rdns,
                        proxy_user,
                        proxy_pass,
                    )
                else:
                    sock = socket.socket(af, socktype, proto)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if has_timeout(effective_timeout):
                    sock.settimeout(effective_timeout)
                if self.debuglevel > 0:
                    _debug_print(f"connect: ({self.host}, {self.port}) ************")
                    if use_proxy:
                        _debug_print(
                            f"proxy: {(proxy_host, proxy_port, proxy_rdns, proxy_user, proxy_pass, proxy_headers)} ************"
                        )
                target_addr = ((self.host, self.port) + sa[2:]) if include_flowinfo else (self.host, self.port)
                sock.connect(target_addr)
            except (socket.timeout, socket.gaierror):
                if sock:
                    sock.close()
                raise
            except socket.error as e:
                if socket_err is None or "PySocks doesn't support IPv6" not in str(e):
                    socket_err = e
                if self.debuglevel > 0:
                    _debug_print(f"connect fail: ({self.host}, {self.port})")
                    if use_proxy:
                        _debug_print(
                            f"proxy: {(proxy_host, proxy_port, proxy_rdns, proxy_user, proxy_pass, proxy_headers)}"
                        )
                if sock:
                    sock.close()
                sock = None
                continue
            break

        if not sock:
            raise socket_err
        return sock

    def connect(self):
        """Connect to the host and port specified in __init__."""
        sock = self._connect_raw_socket(include_flowinfo=True, timeout=self.timeout)
        stream = _Httplib2SyncStream(sock, owner=self, enable_http2=False)
        self._record_sock(sock)
        self._backend.push_preconnected(stream)

    def _clear_pending_outcome(self):
        pending = getattr(self._local, "pending_outcome", None)
        if pending is not None:
            self._local.pending_outcome = None
            hc_resp, _ = pending
            if hc_resp is not None:
                with contextlib.suppress(Exception):
                    hc_resp.close()

    def request(self, method, url, body=None, headers=None, *, encode_chunked=False):
        self._clear_pending_outcome()

        raw_headers = []
        has_host = False
        has_content_length = False
        has_transfer_encoding = False

        if headers:
            items = headers.items() if hasattr(headers, "items") else headers
            for k, v in items:
                kb = k.encode("iso-8859-1") if isinstance(k, str) else bytes(k)
                vb = v.encode("iso-8859-1") if isinstance(v, str) else bytes(v)
                if not kb or kb.startswith(b":") or any(b <= 0x20 or b == 0x7F or b == 0x3A for b in kb):
                    raise http.client.HTTPException(f"Invalid header name {kb!r}")
                if any(b in (0x00, 0x0A, 0x0D) for b in vb):
                    raise http.client.HTTPException(f"Invalid header value {vb!r}")
                kl = kb.lower()
                if kl == b"host":
                    has_host = True
                elif kl == b"content-length":
                    has_content_length = True
                elif kl == b"transfer-encoding":
                    has_transfer_encoding = True
                raw_headers.append((kb, vb))

        if not has_host:
            host_str = self.host
            if ":" in host_str and not host_str.startswith("["):
                host_str = f"[{host_str}]"
            default_port = 443 if self._is_https else 80
            if self.port and self.port != default_port:
                host_hdr = f"{host_str}:{self.port}".encode("ascii")
            else:
                host_hdr = host_str.encode("ascii")
            raw_headers.insert(0, (b"Host", host_hdr))

        method_bytes = method.encode("ascii") if isinstance(method, str) else bytes(method)
        if not method_bytes or any(b <= 0x20 or b >= 0x7F for b in method_bytes):
            raise http.client.InvalidURL(f"Invalid method {method!r}")
        upper_method = method.upper() if isinstance(method, str) else method.decode("ascii").upper()
        if body is not None and hasattr(body, "read"):
            body = body.read()
        if isinstance(body, str):
            body = body.encode("utf-8")

        has_nonempty_body = False
        if body is None:
            content_bytes = b""
            if upper_method in ("POST", "PUT", "PATCH") and not has_content_length and not has_transfer_encoding:
                raw_headers.append((b"Content-Length", b"0"))
        elif isinstance(body, (bytes, bytearray, memoryview)):
            content_bytes = bytes(body)
            has_nonempty_body = len(content_bytes) > 0
            if not has_content_length and not has_transfer_encoding:
                if has_nonempty_body or upper_method in ("POST", "PUT", "PATCH"):
                    raw_headers.append((b"Content-Length", str(len(content_bytes)).encode("ascii")))
        else:
            chunks = [c.encode("utf-8") if isinstance(c, str) else bytes(c) for c in body]
            content_bytes = b"".join(chunks)
            has_nonempty_body = len(content_bytes) > 0
            if not has_content_length and not has_transfer_encoding:
                raw_headers.append((b"Content-Length", str(len(content_bytes)).encode("ascii")))

        scheme_bytes = b"https" if self._is_https else b"http"
        host_bytes = self.host.encode("ascii")
        target_bytes = url.encode("ascii") if isinstance(url, str) else bytes(url)
        if not target_bytes:
            target_bytes = b"/"
        if any(b <= 0x20 or b == 0x7F for b in target_bytes):
            raise http.client.InvalidURL(f"URL can't contain control characters. {url!r}")

        effective_timeout = socket.getdefaulttimeout() if self.timeout is None else self.timeout
        timeout_ext = {
            "connect": effective_timeout,
            "read": effective_timeout,
            "write": effective_timeout,
            "pool": effective_timeout,
        }

        hc_req = _HttpcoreRequest(
            method=method_bytes,
            url=_HttpcoreURL(
                scheme=scheme_bytes,
                host=host_bytes,
                port=self.port,
                target=target_bytes,
            ),
            headers=raw_headers,
            content=content_bytes,
            extensions={
                "timeout": timeout_ext,
                "has_nonempty_body": has_nonempty_body,
                "request_sent": False,
            },
        )
        hc_req.method = method_bytes

        if self.debuglevel > 0:
            is_h2 = False
            if self._is_https and getattr(self, "enable_http2", False):
                pool_conns = getattr(self.httpcore_pool, "_connections", [])
                for c in pool_conns:
                    sub_c = getattr(c, "_connection", None)
                    if isinstance(sub_c, _Httplib2HTTP2Connection):
                        is_h2 = True
                        break
            proto = "HTTP/2" if is_h2 else "HTTP/1.1"
            req_line = f"{upper_method} {target_bytes.decode('ascii', errors='replace')} {proto}\r\n"
            hdr_str = "".join(
                f"{k.decode('iso-8859-1') if isinstance(k, bytes) else k}: {v.decode('iso-8859-1') if isinstance(v, bytes) else v}\r\n"
                for k, v in raw_headers
            )
            _debug_print("send:", repr((req_line + hdr_str + "\r\n").encode("iso-8859-1")))
            if has_nonempty_body:
                _debug_print("send:", repr(content_bytes))

        try:
            hc_resp = self.httpcore_pool.handle_request(hc_req)
            net_stream = hc_resp.extensions.get("network_stream")
            if net_stream is not None:
                sock_obj = net_stream.get_extra_info("socket")
                if sock_obj is not None:
                    self._record_sock(sock_obj)
            self._local.pending_outcome = (hc_resp, upper_method)
        except Exception as exc:
            unwrapped = _unwrap_httpcore_exception(exc)
            if hc_req.extensions.get("request_sent"):
                self._local.pending_outcome = (None, unwrapped)
            else:
                raise unwrapped

    def getresponse(self):
        pending = getattr(self._local, "pending_outcome", None)
        if pending is None:
            raise http.client.ResponseNotReady()
        self._local.pending_outcome = None
        hc_resp, second = pending
        if hc_resp is None:
            raise second
        return _Httplib2RawResponse(hc_resp, method=second, debuglevel=self.debuglevel)

    def close(self):
        self._override_sock = None
        self._last_sock = None
        if hasattr(self, "_local"):
            self._local.last_sock = None
            self._clear_pending_outcome()
        if hasattr(self, "_backend"):
            self._backend.clear_preconnected()
        if hasattr(self, "httpcore_pool"):
            with contextlib.suppress(Exception):
                self.httpcore_pool.close()

    def close_all(self):
        self.close()


class HTTPSConnectionWithTimeout(HTTPConnectionWithTimeout, http.client.HTTPSConnection):
    """This class allows communication via SSL using httpx/httpcore with HTTP/2 multiplexing.

    All timeouts are in seconds. If None is passed for timeout then
    Python's default timeout for sockets will be used. See for example
    the docs of socket.setdefaulttimeout():
    http://docs.python.org/library/socket.html#socket.setdefaulttimeout
    """

    _is_https = True
    enable_http2 = True

    def __init__(
        self,
        host,
        port=None,
        key_file=None,
        cert_file=None,
        timeout=None,
        proxy_info=None,
        ca_certs=None,
        disable_ssl_certificate_validation=False,
        tls_maximum_version=None,
        tls_minimum_version=None,
        key_password=None,
        enable_http2=None,
        pool_maxsize=DEFAULT_POOL_MAXSIZE,
    ):
        self._initialized = False
        self._override_sock = None
        self._last_sock = None
        self._local = threading.local()
        self._pool_maxsize = pool_maxsize

        self.disable_ssl_certificate_validation = disable_ssl_certificate_validation
        self.ca_certs = _resolve_ca_certs(ca_certs)
        self.tls_maximum_version = tls_maximum_version
        self.tls_minimum_version = tls_minimum_version
        self.key_file = key_file
        self.cert_file = cert_file
        self.key_password = key_password

        if enable_http2 is None:
            enable_http2 = getattr(self.__class__, "enable_http2", ENABLE_HTTP2)
        effective_h2 = bool(enable_http2) and bool(ENABLE_HTTP2)
        self.enable_http2 = effective_h2

        self.proxy_info = proxy_info
        if proxy_info and not isinstance(proxy_info, ProxyInfo):
            self.proxy_info = proxy_info("https")

        context = _build_ssl_context(
            self.disable_ssl_certificate_validation,
            self.ca_certs,
            cert_file,
            key_file,
            maximum_version=tls_maximum_version,
            minimum_version=tls_minimum_version,
            key_password=key_password,
            enable_http2=effective_h2,
        )
        http.client.HTTPSConnection.__init__(
            self,
            host,
            port=port,
            timeout=timeout,
            context=context,
        )
        if isinstance(self.host, str) and self.host.startswith("[") and self.host.endswith("]"):
            self.host = self.host[1:-1]

        self._backend = _Httplib2NetworkBackend(self)
        self.httpcore_pool = _Httplib2ConnectionPool(
            ssl_context=self._context,
            max_connections=pool_maxsize,
            max_keepalive_connections=pool_maxsize,
            keepalive_expiry=30.0,
            http1=True,
            http2=effective_h2,
            network_backend=self._backend,
        )
        self._initialized = True

    def downgrade_to_http1(self):
        """Downgrade connection to HTTP/1.1 by disabling HTTP/2 ALPN and recreating the connection pool."""
        self.enable_http2 = False
        self.close()
        if hasattr(self, "_context") and self._context is not None:
            with contextlib.suppress(NotImplementedError, ssl.SSLError):
                self._context.set_alpn_protocols(["http/1.1"])
        self._backend = _Httplib2NetworkBackend(self)
        self.httpcore_pool = _Httplib2ConnectionPool(
            ssl_context=self._context,
            max_connections=self._pool_maxsize,
            max_keepalive_connections=self._pool_maxsize,
            keepalive_expiry=30.0,
            http1=True,
            http2=False,
            network_backend=self._backend,
        )

    def connect(self):
        """Connect to a host on a given (SSL) port."""
        sock = None
        ssl_sock = None
        try:
            sock = self._connect_raw_socket(include_flowinfo=False, timeout=self.timeout)
            if self.enable_http2 and ENABLE_HTTP2:
                with contextlib.suppress(NotImplementedError):
                    self._context.set_alpn_protocols(["h2", "http/1.1"])
            else:
                with contextlib.suppress(NotImplementedError):
                    self._context.set_alpn_protocols(["http/1.1"])
            ssl_sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except (ssl.SSLError, ssl.CertificateError):
            if sock:
                sock.close()
            if ssl_sock:
                ssl_sock.close()
            self._last_sock = None
            raise

        stream = _Httplib2SyncStream(ssl_sock, owner=self, enable_http2=bool(self.enable_http2 and ENABLE_HTTP2))
        self._record_sock(ssl_sock)
        self._backend.push_preconnected(stream)


SCHEME_TO_CONNECTION = {
    "http": HTTPConnectionWithTimeout,
    "https": HTTPSConnectionWithTimeout,
}


_HTTP_LOCKS_GUARD = threading.RLock()


def _get_http_lock(http_instance):
    lock = getattr(http_instance, "_lock", None)
    if lock is None:
        with _HTTP_LOCKS_GUARD:
            lock = getattr(http_instance, "_lock", None)
            if lock is None:
                lock = threading.RLock()
                http_instance._lock = lock
    return lock


class Http:
    """An HTTP client that handles:

    - all methods
    - caching
    - ETags
    - compression,
    - HTTPS
    - Basic
    - Digest
    - WSSE

    and more, powered by httpx/httpcore with HTTP/2 multiplexing and thread-safe connection pooling.
    """

    enable_http2 = True
    auto_downgrade_http2 = True
    pool_maxsize = DEFAULT_POOL_MAXSIZE

    def __init__(
        self,
        cache=None,
        timeout=None,
        proxy_info=proxy_info_from_environment,
        ca_certs=None,
        disable_ssl_certificate_validation=False,
        tls_maximum_version=None,
        tls_minimum_version=None,
        decode_limit_hard=None,
        decode_limit_safe=None,
        decode_limit_ratio=None,
        decode_limit_chunk=None,
        enable_http2=None,
        auto_downgrade_http2=None,
        pool_maxsize=None,
    ):
        self.proxy_info = proxy_info
        self.ca_certs = ca_certs
        self.disable_ssl_certificate_validation = disable_ssl_certificate_validation
        self.tls_maximum_version = tls_maximum_version
        self.tls_minimum_version = tls_minimum_version
        if enable_http2 is not None:
            self.enable_http2 = bool(enable_http2)
        else:
            self.enable_http2 = getattr(self.__class__, "enable_http2", ENABLE_HTTP2)

        if auto_downgrade_http2 is not None:
            self.auto_downgrade_http2 = bool(auto_downgrade_http2)
        else:
            self.auto_downgrade_http2 = getattr(self.__class__, "auto_downgrade_http2", AUTO_DOWNGRADE_HTTP2)

        if pool_maxsize is not None:
            self.pool_maxsize = pool_maxsize

        self._http2_downgraded_hosts = set()

        # Map domain name to an httplib connection
        self.connections = {}
        # The location of the cache, for now a directory
        # where cached responses are held.
        if cache and isinstance(cache, str):
            self.cache = FileCache(cache)
        else:
            self.cache = cache

        # Name/password
        self.credentials = Credentials()

        # Key/cert
        self.certificates = KeyCerts()

        # authorization objects
        self.authorizations = []

        # If set to False then no redirects are followed, even safe ones.
        self.follow_redirects = True

        self.redirect_codes = REDIRECT_CODES

        # Which HTTP methods do we apply optimistic concurrency to, i.e.
        # which methods get an "if-match:" etag header added to them.
        self.optimistic_concurrency_methods = ["PUT", "PATCH"]

        self.safe_methods = list(SAFE_METHODS)

        # If 'follow_redirects' is True, and this is set to True then
        # all redirecs are followed, including unsafe ones.
        self.follow_all_redirects = False

        self.ignore_etag = False

        self.force_exception_to_status_code = False

        self.timeout = timeout

        # Keep Authorization: headers on a redirect.
        self.forward_authorization_headers = False

        limit_kwargs = dict(
            hard_limit=try_value_or_env(
                int, decode_limit_hard, "httplib2_decode_limit_hard"
            ),
            safe_limit=try_value_or_env(
                int, decode_limit_safe, "httplib2_decode_limit_safe"
            ),
            ratio=try_value_or_env(
                float, decode_limit_ratio, "httplib2_decode_limit_ratio"
            ),
            chunk_size=try_value_or_env(
                int, decode_limit_chunk, "httplib2_decode_limit_chunk"
            ),
        )
        self.limit_kwargs = {k: v for k, v in limit_kwargs.items() if v is not None}

    def close(self):
        """Close persistent connections, clear sensitive data."""
        with _get_http_lock(self):
            existing, self.connections = self.connections, {}
        for _, c in existing.items():
            getattr(c, "close_all", c.close)()
        self.certificates.clear()
        self.clear_credentials()

    def force_http11(self):
        """Force this Http instance to use HTTP/1.1 only and downgrade all active connections."""
        self.enable_http2 = False
        with _get_http_lock(self):
            for conn in self.connections.values():
                if hasattr(conn, "downgrade_to_http1"):
                    conn.downgrade_to_http1()

    def downgrade_to_http1(self):
        """Alias for force_http11()."""
        self.force_http11()

    def downgrade_host_to_http1(self, authority):
        """Force connections to a specific host:port authority to downgrade to HTTP/1.1."""
        self._record_host_downgrade(authority)
        host_only = authority.split(":")[0]
        with _get_http_lock(self):
            for scheme in ("https", "http"):
                for key in (f"{scheme}:{authority}", f"{scheme}:{host_only}"):
                    conn = self.connections.get(key)
                    if conn is not None and hasattr(conn, "downgrade_to_http1"):
                        conn.downgrade_to_http1()

    def _record_host_downgrade(self, host_or_authority):
        self._http2_downgraded_hosts.add(host_or_authority)
        with _DOWNGRADE_LOCK:
            DOWNGRADED_HOSTS.add(host_or_authority)
        if ":" not in host_or_authority or host_or_authority.endswith(":443"):
            host_only = host_or_authority.split(":")[0]
            self._http2_downgraded_hosts.add(host_only)
            with _DOWNGRADE_LOCK:
                DOWNGRADED_HOSTS.add(host_only)

    def _is_host_downgraded(self, host_or_authority):
        host_only = host_or_authority.split(":")[0]
        if host_or_authority in self._http2_downgraded_hosts or host_only in self._http2_downgraded_hosts:
            return True
        with _DOWNGRADE_LOCK:
            return host_or_authority in DOWNGRADED_HOSTS or host_only in DOWNGRADED_HOSTS

    def __getstate__(self):
        state_dict = copy.copy(self.__dict__)
        if "request" in state_dict:
            del state_dict["request"]
        if "connections" in state_dict:
            del state_dict["connections"]
        if "_lock" in state_dict:
            del state_dict["_lock"]
        return state_dict

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.connections = {}

    def _auth_from_challenge(self, host, request_uri, headers, response, content):
        """A generator that creates Authorization objects
           that can be applied to requests.
        """
        challenges = auth._parse_www_authenticate(response, "www-authenticate")
        for cred in self.credentials.iter(host):
            for scheme in AUTH_SCHEME_ORDER:
                if scheme in challenges:
                    yield AUTH_SCHEME_CLASSES[scheme](cred, host, request_uri, headers, response, content, self)

    def add_credentials(self, name, password, domain=""):
        """Add a name and password that will be used
        any time a request requires authentication."""
        self.credentials.add(name, password, domain)

    def add_certificate(self, key, cert, domain, password=None):
        """Add a key and cert that will be used
        any time a request requires authentication."""
        self.certificates.add(key, cert, domain, password)

    def clear_credentials(self):
        """Remove all the names and passwords
        that are used for authentication"""
        self.credentials.clear()
        self.authorizations = []

    def _conn_request(self, conn, request_uri, method, body, headers):
        i = 0
        seen_bad_status_line = False
        uses_pool = getattr(conn, "_uses_httpcore_pool", False)
        initial_body_pos = body.tell() if hasattr(body, "tell") else None
        while i < RETRIES:
            i += 1
            if initial_body_pos is not None and hasattr(body, "seek"):
                with contextlib.suppress(Exception):
                    body.seek(initial_body_pos)
            try:
                if not uses_pool and conn.sock is None:
                    conn.connect()
                conn.request(method, request_uri, body, headers)
                response = conn.getresponse()
            except socket.timeout:
                conn.close()
                raise
            except socket.gaierror:
                conn.close()
                raise ServerNotFoundError("Unable to find the server at %s" % conn.host)
            except Exception as exc:
                can_downgrade = (
                    getattr(conn, "_is_https", False)
                    and getattr(conn, "enable_http2", False)
                    and getattr(self, "auto_downgrade_http2", False)
                )
                if can_downgrade and _should_downgrade_on_error(exc):
                    if getattr(conn, "debuglevel", 0) > 0 or getattr(self, "debuglevel", 0) > 0:
                        _debug_print(
                            f"auto-downgrade: HTTP/2 failed for {conn.host} ({type(exc).__name__}: {exc}), "
                            f"falling back to HTTP/1.1 and retrying"
                        )
                    conn_authority = (
                        f"{conn.host}:{conn.port}"
                        if getattr(conn, "port", None) not in (None, 443)
                        else conn.host
                    )
                    self._record_host_downgrade(conn_authority)
                    conn.downgrade_to_http1()
                    i = 0
                    continue

                if isinstance(exc, (http.client.BadStatusLine, http.client.ResponseNotReady)):
                    if not seen_bad_status_line and i == 1:
                        i = 0
                        seen_bad_status_line = True
                        conn.close()
                        if not uses_pool:
                            conn.connect()
                        continue
                    else:
                        conn.close()
                        raise exc

                if isinstance(exc, socket.error):
                    errno_ = _errno_from_exception(exc)
                    if errno_ in (errno.ENETUNREACH, errno.EADDRNOTAVAIL) and i < RETRIES:
                        continue  # retry on potentially transient errors
                    conn.close()
                    raise exc

                if isinstance(exc, http.client.HTTPException):
                    if conn.sock is None:
                        if i < RETRIES - 1:
                            conn.close()
                            conn.connect()
                            continue
                        else:
                            conn.close()
                            raise exc
                    if i < RETRIES - 1:
                        conn.close()
                        conn.connect()
                        continue
                    conn.close()
                    raise exc

                conn.close()
                raise exc
            else:
                content = b""
                if method == "HEAD":
                    if hasattr(response, "close"):
                        response.close()
                    if getattr(response, "version", 11) != 20:
                        conn.close()
                else:
                    content = response.read()
                response = Response(response)
                if method != "HEAD":
                    content = _decompressContent(response, content, self.limit_kwargs)

            break
        return (response, content)

    def _request(
        self, conn, host, absolute_uri, request_uri, method, body, headers, redirections, cachekey,
    ):
        """Do the actual request using the connection object
        and also follow one level of redirects if necessary"""

        auths = [(auth.depth(request_uri), auth) for auth in self.authorizations if auth.inscope(host, request_uri)]
        auth_obj = auths and sorted(auths)[0][1] or None
        if auth_obj:
            auth_obj.request(method, request_uri, headers, body)

        (response, content) = self._conn_request(conn, request_uri, method, body, headers)

        if auth_obj:
            if auth_obj.response(response, body):
                auth_obj.request(method, request_uri, headers, body)
                (response, content) = self._conn_request(conn, request_uri, method, body, headers)
                response._stale_digest = 1

        if response.status == 401:
            for authorization in self._auth_from_challenge(host, request_uri, headers, response, content):
                authorization.request(method, request_uri, headers, body)
                (response, content) = self._conn_request(conn, request_uri, method, body, headers)
                if response.status != 401:
                    self.authorizations.append(authorization)
                    authorization.response(response, body)
                    break

        if self.follow_all_redirects or method in self.safe_methods or response.status in (303, 308):
            if self.follow_redirects and response.status in self.redirect_codes:
                if redirections:
                    if "location" not in response and response.status != 300:
                        raise RedirectMissingLocation(
                            _("Redirected but the response is missing a Location: header."), response, content,
                        )
                    if "location" in response:
                        location = response["location"]
                        (scheme, authority, path, query, fragment) = parse_uri(location)
                        if authority == None:
                            response["location"] = urllib.parse.urljoin(absolute_uri, location)
                    if response.status == 308 or (response.status == 301 and (method in self.safe_methods)):
                        response["-x-permanent-redirect-url"] = response["location"]
                        if "content-location" not in response:
                            response["content-location"] = absolute_uri
                        _updateCache(headers, response, content, self.cache, cachekey)
                    if "if-none-match" in headers:
                        del headers["if-none-match"]
                    if "if-modified-since" in headers:
                        del headers["if-modified-since"]
                    if "authorization" in headers and not self.forward_authorization_headers:
                        del headers["authorization"]
                    if "location" in response:
                        location = response["location"]
                        old_response = copy.deepcopy(response)
                        if "content-location" not in old_response:
                            old_response["content-location"] = absolute_uri
                        redirect_method = method
                        if response.status in [302, 303]:
                            redirect_method = "GET"
                            body = None
                            for body_hdr in ("content-length", "content-type", "transfer-encoding"):
                                if body_hdr in headers:
                                    del headers[body_hdr]
                        orig_scheme, orig_authority = parse_uri(absolute_uri)[:2]
                        dest_scheme, dest_authority = parse_uri(location)[:2]
                        if (
                            "authorization" in headers
                            and orig_scheme
                            and dest_scheme
                            and orig_scheme.lower() == "https"
                            and dest_scheme.lower() == "http"
                        ):
                            del headers["authorization"]
                        if dest_authority and orig_authority and dest_authority.lower() != orig_authority.lower():
                            if "cookie" in headers:
                                del headers["cookie"]
                            if "host" in headers:
                                del headers["host"]
                        (response, content) = self.request(
                            location, method=redirect_method, body=body, headers=headers, redirections=redirections - 1,
                        )
                        response.previous = old_response
                else:
                    raise RedirectLimit(
                        "Redirected more times than redirection_limit allows.", response, content,
                    )
            elif response.status in [200, 203] and method in self.safe_methods:
                if "content-location" not in response:
                    response["content-location"] = absolute_uri
                _updateCache(headers, response, content, self.cache, cachekey)

        return (response, content)

    def _normalize_headers(self, headers):
        return _normalize_headers(headers)

    def request(
        self, uri, method="GET", body=None, headers=None, redirections=DEFAULT_MAX_REDIRECTS, connection_type=None,
    ):
        """Performs a single HTTP request."""
        conn_key = ""

        try:
            if headers is None:
                headers = {}
            else:
                headers = self._normalize_headers(headers)

            if "user-agent" not in headers:
                headers["user-agent"] = "Python-httplib2/%s (gzip)" % __version__

            uri = iri2uri(uri)
            # Prevent CWE-75 space injection to manipulate request via part of uri.
            # Prevent CWE-93 CRLF injection to modify headers via part of uri.
            uri = uri.replace(" ", "%20").replace("\r", "%0D").replace("\n", "%0A")

            (scheme, authority, request_uri, defrag_uri) = urlnorm(uri)

            conn_key = scheme + ":" + authority
            with _get_http_lock(self):
                conn = self.connections.get(conn_key)
                is_downgraded = self._is_host_downgraded(authority)
                should_h2 = (
                    bool(self.enable_http2)
                    and bool(ENABLE_HTTP2)
                    and not is_downgraded
                )
                if conn is not None and type(conn) is HTTPSConnectionWithTimeout:
                    expected_ca_certs = _resolve_ca_certs(self.ca_certs)
                    if (
                        bool(conn.disable_ssl_certificate_validation) != bool(self.disable_ssl_certificate_validation)
                        or conn.ca_certs != expected_ca_certs
                        or conn.tls_minimum_version != self.tls_minimum_version
                        or conn.tls_maximum_version != self.tls_maximum_version
                    ):
                        conn.close()
                        conn = None
                        del self.connections[conn_key]
                if conn is not None:
                    if getattr(conn, "_is_https", False) and getattr(conn, "enable_http2", False) and not should_h2:
                        conn.downgrade_to_http1()
                if conn is None:
                    if not connection_type:
                        connection_type = SCHEME_TO_CONNECTION[scheme]
                    certs = list(self.certificates.iter(authority))
                    if issubclass(connection_type, HTTPSConnectionWithTimeout):
                        extra_https_kwargs = {}
                        if connection_type is HTTPSConnectionWithTimeout:
                            extra_https_kwargs["enable_http2"] = should_h2
                            extra_https_kwargs["pool_maxsize"] = self.pool_maxsize
                        if certs:
                            conn = self.connections[conn_key] = connection_type(
                                authority,
                                key_file=certs[0][0],
                                cert_file=certs[0][1],
                                timeout=self.timeout,
                                proxy_info=self.proxy_info,
                                ca_certs=self.ca_certs,
                                disable_ssl_certificate_validation=self.disable_ssl_certificate_validation,
                                tls_maximum_version=self.tls_maximum_version,
                                tls_minimum_version=self.tls_minimum_version,
                                key_password=certs[0][2],
                                **extra_https_kwargs,
                            )
                        else:
                            conn = self.connections[conn_key] = connection_type(
                                authority,
                                timeout=self.timeout,
                                proxy_info=self.proxy_info,
                                ca_certs=self.ca_certs,
                                disable_ssl_certificate_validation=self.disable_ssl_certificate_validation,
                                tls_maximum_version=self.tls_maximum_version,
                                tls_minimum_version=self.tls_minimum_version,
                                **extra_https_kwargs,
                            )
                    else:
                        extra_http_kwargs = {}
                        if connection_type is HTTPConnectionWithTimeout:
                            extra_http_kwargs["pool_maxsize"] = self.pool_maxsize
                        conn = self.connections[conn_key] = connection_type(
                            authority,
                            timeout=self.timeout,
                            proxy_info=self.proxy_info,
                            **extra_http_kwargs,
                        )
                conn.set_debuglevel(debuglevel)

            if "range" not in headers and "accept-encoding" not in headers:
                headers["accept-encoding"] = "gzip, deflate"

            info = email.message.Message()
            cachekey = None
            cached_value = None
            if self.cache:
                cachekey = defrag_uri
                cached_value = self.cache.get(cachekey)
                if cached_value:
                    try:
                        info, content = cached_value.split(b"\r\n\r\n", 1)
                        info = email.message_from_bytes(info)
                        for k, v in info.items():
                            if v.startswith("=?") and v.endswith("?="):
                                info.replace_header(k, str(*email.header.decode_header(v)[0]))
                    except (IndexError, ValueError):
                        self.cache.delete(cachekey)
                        cachekey = None
                        cached_value = None

            if (
                method in self.optimistic_concurrency_methods
                and self.cache
                and "etag" in info
                and not self.ignore_etag
                and "if-match" not in headers
            ):
                headers["if-match"] = info["etag"]

            if self.cache and cachekey and method not in self.safe_methods:
                self.cache.delete(cachekey)

            if method in self.safe_methods and "vary" in info:
                vary = info["vary"]
                vary_headers = vary.lower().replace(" ", "").split(",")
                for header in vary_headers:
                    key = "-varied-%s" % header
                    value = info[key]
                    if headers.get(header, None) != value:
                        cached_value = None
                        break

            if (
                self.cache
                and cached_value
                and (method in self.safe_methods or info["status"] == "308")
                and "range" not in headers
            ):
                redirect_method = method
                if info["status"] not in ("307", "308"):
                    redirect_method = "GET"
                if "-x-permanent-redirect-url" in info:
                    if redirections <= 0:
                        raise RedirectLimit(
                            "Redirected more times than redirection_limit allows.", {}, "",
                        )
                    (response, new_content) = self.request(
                        info["-x-permanent-redirect-url"],
                        method=redirect_method,
                        headers=headers,
                        redirections=redirections - 1,
                    )
                    response.previous = Response(info)
                    response.previous.fromcache = True
                else:
                    entry_disposition = _entry_disposition(info, headers)

                    if entry_disposition == "FRESH":
                        response = Response(info)
                        response.fromcache = True
                        return (response, content)

                    if entry_disposition == "STALE":
                        if "etag" in info and not self.ignore_etag and not "if-none-match" in headers:
                            headers["if-none-match"] = info["etag"]
                        if "last-modified" in info and not "last-modified" in headers:
                            headers["if-modified-since"] = info["last-modified"]
                    elif entry_disposition == "TRANSPARENT":
                        pass

                    (response, new_content) = self._request(
                        conn, authority, uri, request_uri, method, body, headers, redirections, cachekey,
                    )

                if response.status == 304 and method == "GET":
                    for key in _get_end2end_headers(response):
                        info[key] = response[key]
                    merged_response = Response(info)
                    if hasattr(response, "_stale_digest"):
                        merged_response._stale_digest = response._stale_digest
                    _updateCache(headers, merged_response, content, self.cache, cachekey)
                    response = merged_response
                    response.status = 200
                    response.fromcache = True

                elif response.status == 200:
                    content = new_content
                else:
                    self.cache.delete(cachekey)
                    content = new_content
            else:
                cc = _parse_cache_control(headers)
                if "only-if-cached" in cc:
                    info["status"] = "504"
                    response = Response(info)
                    content = b""
                else:
                    (response, content) = self._request(
                        conn, authority, uri, request_uri, method, body, headers, redirections, cachekey,
                    )
        except Exception as e:
            is_timeout = isinstance(e, socket.timeout)
            if is_timeout:
                with _get_http_lock(self):
                    conn = self.connections.pop(conn_key, None)
                if conn:
                    conn.close()

            if self.force_exception_to_status_code:
                if isinstance(e, HttpLib2ErrorWithResponse):
                    response = e.response
                    content = e.content
                    response.status = 500
                    response.reason = str(e)
                elif isinstance(e, socket.timeout):
                    content = b"Request Timeout"
                    response = Response({"content-type": "text/plain", "status": "408", "content-length": len(content),})
                    response.reason = "Request Timeout"
                else:
                    content = str(e).encode("utf-8")
                    response = Response({"content-type": "text/plain", "status": "400", "content-length": len(content),})
                    response.reason = "Bad Request"
            else:
                raise

        return (response, content)


class Response(dict):
    """An object more like email.message than httplib.HTTPResponse."""

    fromcache = False
    version = 11
    status = 200
    reason = "Ok"
    previous = None
    stream_id = None

    def __init__(self, info):
        # info is an email.message, an http.client.HTTPResponse,
        # a _Httplib2RawResponse, or a mapping.
        if isinstance(info, (http.client.HTTPResponse, _Httplib2RawResponse)):
            headers_iter = info.headers.items() if hasattr(info, "headers") else info.getheaders()
            for key, value in headers_iter:
                key = key.lower()
                prev = self.get(key)
                if prev is not None:
                    value = ", ".join((prev, value))
                self[key] = value
            self.status = info.status
            self["status"] = str(self.status)
            self.reason = info.reason
            self.version = info.version
            self.stream_id = getattr(info, "stream_id", None)
        elif isinstance(info, email.message.Message):
            for key, value in list(info.items()):
                self[key.lower()] = value
            self.status = int(self["status"])
        else:
            for key, value in info.items():
                self[key.lower()] = value
            self.status = int(self.get("status", self.status))

    def __getattr__(self, name):
        if name == "dict":
            return self
        else:
            raise AttributeError(name)


def try_value_or_env(to, value, env_key, default=None):
    candidates = (value, os.environ.get(env_key), os.environ.get(env_key.upper()))
    for x in candidates:
        if x is None:
            continue
        try:
            return to(x)
        except ValueError:
            pass
    return default
