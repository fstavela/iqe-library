"""Neutral Requests transport using system trust for effective verify=True."""

import ssl
from collections.abc import Callable, Mapping
from typing import Any, cast

import requests
import truststore
from requests.adapters import HTTPAdapter
from urllib3.connectionpool import ConnectionPool, HTTPSConnectionPool


class _SystemTrustAdapter(HTTPAdapter):
    def __init__(self) -> None:
        super().__init__()
        self._contexts: dict[str | tuple[str, str] | None, ssl.SSLContext] = {}

    def get_connection_with_tls_context(
        self,
        request: requests.PreparedRequest,
        verify: bool | str | None,
        proxies: Mapping[str, str] | None = None,
        cert: str | tuple[str, str] | None = None,
    ) -> ConnectionPool:
        pool = super().get_connection_with_tls_context(request, verify, proxies, cert)
        if verify is True and isinstance(pool, HTTPSConnectionPool):
            if cert not in self._contexts:
                self._contexts[cert] = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # urllib3 loads client certificates into the mutable context. Never
            # share it across certificate identities, including anonymous TLS.
            # Requests already keys pools by certificate and verification policy;
            # this hook supports proxies and the Requests 2.32.2 minimum.
            pool.conn_kw["ssl_context"] = self._contexts[cert]
        return pool

    def cert_verify(self, conn: Any, url: str, verify: bool | str, cert: Any) -> None:
        # Preserve client-certificate handling without adding certifi to system
        # trust. Explicit CA paths and verify=False keep Requests' behavior.
        # types-requests leaves this upstream method unannotated.
        cert_verify = cast(Callable[[Any, str, bool | str, Any], None], super().cert_verify)
        cert_verify(conn, url, False if verify is True else verify, cert)
        if verify is True and url.lower().startswith("https"):
            conn.cert_reqs = "CERT_REQUIRED"
