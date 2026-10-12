"""Requests transport using system trust unless a caller selects another policy."""

import socket
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from http.client import HTTPResponse
from threading import Lock, Timer
from time import monotonic
from typing import TYPE_CHECKING, Any, cast

import requests
from urllib3.connectionpool import ConnectionPool, HTTPConnectionPool
from urllib3.util.ssltransport import SSLTransport

from iqe_library._transport import _SystemTrustAdapter

if TYPE_CHECKING:
    from requests.sessions import _Cert, _Settings, _TextMapping, _Verify


class _VaultSession(requests.Session):
    def __init__(self, timeout: float | None = None) -> None:
        super().__init__()
        self._request_timeout = timeout

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        if self._request_timeout is None:
            return super().request(*args, **kwargs)
        # hvac consumes full responses. Give each API call (including redirects
        # and body reads) its own budget, using the same transport as the IdP.
        with http_deadline(self, self._request_timeout):
            return super().request(*args, **kwargs)

    def merge_environment_settings(
        self,
        url: str | bytes | None,
        proxies: "_TextMapping | None",
        stream: bool | None,
        verify: "_Verify | None",
        cert: "_Cert | None",
    ) -> "_Settings":
        # Requests otherwise lets an environment CA override session.verify,
        # even when the session explicitly selected False or a particular CA.
        return super().merge_environment_settings(
            url, proxies, stream, self.verify if verify is None else verify, cert
        )


def create_session(verify: bool | str, *, timeout: float | None = None) -> requests.Session:
    """Honor standard proxies/CA variables and explicit verification choices."""
    session = _VaultSession(timeout)
    session.verify = verify
    session.mount("https://", _SystemTrustAdapter())
    return session


class _HTTPDeadline:
    """Interrupt socket reads, including headers and redirect response bodies."""

    def __init__(self, timeout: float) -> None:
        self.expires = monotonic() + timeout
        self._sockets: set[socket.socket] = set()
        self._lock = Lock()
        deadline = self

        class Response(HTTPResponse):
            def __init__(
                self, sock: socket.socket | SSLTransport, *args: Any, **kwargs: Any
            ) -> None:
                super().__init__(cast(socket.socket, sock), *args, **kwargs)
                # HTTPResponse is constructed before header parsing starts.
                # Retain the socket even if http.client closes its own reference
                # while a makefile reader still owns the underlying descriptor.
                # HTTPS proxies use a TLS-in-TLS wrapper without shutdown().
                while isinstance(sock, SSLTransport):
                    sock = sock.socket
                with deadline._lock:
                    deadline._sockets.add(sock)
                    deadline.remaining()

        self.response_class = Response

    def remaining(self) -> float:
        remaining = self.expires - monotonic()
        if remaining <= 0:
            raise requests.Timeout("HTTP response deadline exceeded")
        return remaining

    def interrupt(self) -> None:
        with self._lock:
            for sock in self._sockets:
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)


class _DeadlineAdapter(_SystemTrustAdapter):
    def __init__(self, deadline: _HTTPDeadline) -> None:
        super().__init__()
        self._deadline = deadline

    def get_connection_with_tls_context(
        self,
        request: requests.PreparedRequest,
        verify: bool | str | None,
        proxies: Mapping[str, str] | None = None,
        cert: str | tuple[str, str] | None = None,
    ) -> ConnectionPool:
        pool = super().get_connection_with_tls_context(request, verify, proxies, cert)
        if isinstance(pool, HTTPConnectionPool):
            connection = pool.ConnectionCls
            # Only this deadline's pools use the tracking response;
            # retain the original connection's TLS/proxy behavior.
            if getattr(connection, "response_class", None) is not self._deadline.response_class:
                pool.ConnectionCls = type(
                    "DeadlineConnection",
                    (connection,),
                    {"response_class": self._deadline.response_class},
                )
        return pool

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: float | tuple[float, float | None] | None = None,
        verify: bool | str = True,
        cert: bytes | str | tuple[bytes | str, bytes | str] | None = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        # Every redirect gets the remaining budget, rather than a fresh timeout.
        return super().send(
            request,
            stream=stream,
            timeout=self._deadline.remaining(),
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


@contextmanager
def http_deadline(session: requests.Session, timeout: float) -> Iterator[_HTTPDeadline]:
    """Bound one HTTP flow with fresh pools and no lingering HTTP worker."""
    deadline = _HTTPDeadline(timeout)
    for prefix in ("http://", "https://"):
        session.get_adapter(prefix).close()
        session.mount(prefix, _DeadlineAdapter(deadline))
    timer = Timer(deadline.remaining(), deadline.interrupt)
    timer.daemon = True
    timer.start()
    try:
        yield deadline
        deadline.remaining()
    finally:
        timer.cancel()
        deadline.interrupt()
        timer.join(timeout=0.1)
        for prefix in ("http://", "https://"):
            session.get_adapter(prefix).close()
