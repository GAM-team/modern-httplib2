"""Exception hierarchy for modern-httplib2."""


class HttpLib2Error(Exception):
    """Base exception for all httplib2 errors."""


class HttpLib2ErrorWithResponse(HttpLib2Error):
    """Exception that carries the underlying Response and content."""

    def __init__(self, desc, response, content):
        self.response = response
        self.content = content
        super().__init__(desc)


class RedirectMissingLocation(HttpLib2ErrorWithResponse):
    pass


class RedirectLimit(HttpLib2ErrorWithResponse):
    pass


class FailedToDecompressContent(HttpLib2ErrorWithResponse):
    pass


class UnimplementedDigestAuthOptionError(HttpLib2ErrorWithResponse):
    pass


class UnimplementedHmacDigestAuthOptionError(HttpLib2ErrorWithResponse):
    pass


class MalformedHeader(HttpLib2Error):
    pass


class RelativeURIError(HttpLib2Error):
    pass


class ServerNotFoundError(HttpLib2Error):
    pass


class ProxiesUnavailableError(HttpLib2Error):
    pass
