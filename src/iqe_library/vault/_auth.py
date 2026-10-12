"""Token, AppRole and browserless Kerberos/OIDC authentication."""

import socket
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Lock, Thread
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import hvac
import requests

from ._http import create_session, http_deadline
from ._types import VaultAuthenticationError, VaultOptions


def _spnego_auth() -> requests.auth.AuthBase:
    try:
        from requests_gssapi import HTTPSPNEGOAuth
    except ImportError:
        raise ImportError(
            "Headless Vault OIDC requires iqe-library[kerberos] and an existing Kerberos ticket"
        ) from None
    return cast(requests.auth.AuthBase, HTTPSPNEGOAuth())


def authenticate(client: hvac.Client, options: VaultOptions) -> None:
    """Authenticate a client whose transport is configured by its owner."""
    method = "token" if options.token is not None else "OIDC"
    try:
        if options.token is not None:
            client.token = options.token
        elif options.role_id is not None or options.secret_id is not None:
            method = "AppRole"
            if not options.role_id or not options.secret_id:
                raise VaultAuthenticationError("Vault AppRole requires both role_id and secret_id")
            client.auth.approle.login(role_id=options.role_id, secret_id=options.secret_id)
        else:
            if options.oidc_token is not None:
                client.token = options.oidc_token
                if client.is_authenticated():
                    return
            client.token = None
            client.token = get_oidc_token(client, options)
        if not client.is_authenticated():
            raise VaultAuthenticationError(f"Vault {method} authentication was rejected")
    except (VaultAuthenticationError, ImportError):
        raise
    except Exception:
        raise VaultAuthenticationError(f"Vault {method} authentication failed") from None


class _CallbackServer(HTTPServer):
    """One callback, with interruptible accepted sockets and a bounded worker."""

    def __init__(self, options: VaultOptions, state: str) -> None:
        uri = urlsplit(options.oidc_redirect_uri)
        host = "127.0.0.1" if uri.hostname == "localhost" else uri.hostname
        assert host is not None  # Validated by VaultOptions.
        if ":" in host:
            self.address_family = socket.AF_INET6
        self.expected_path = uri.path
        self.expected_state = state
        self.received = Event()
        self.stop = Event()
        self.code: str | None = None
        self._connection: socket.socket | None = None
        self._lock = Lock()
        self._request_timeout = options.timeout
        super().__init__((host, uri.port or 80), _CallbackHandler)
        self.timeout = min(0.05, options.timeout)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        with self._lock:
            if self.stop.is_set():
                connection.close()
                raise OSError("Callback listener stopped")
            connection.settimeout(self._request_timeout)
            self._connection = connection
        return connection, address

    def handle_error(self, request: Any, client_address: Any) -> None:
        # BaseServer prints handler tracebacks; those may contain callback data.
        self.received.set()

    def listen(self) -> None:
        while not self.stop.is_set() and not self.received.is_set():
            self.handle_request()

    def stop_listener(self) -> None:
        self.stop.set()
        with self._lock:
            if self._connection is not None:
                with suppress(OSError):
                    self._connection.shutdown(socket.SHUT_RDWR)


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def log_message(self, format: str, *args: Any) -> None:
        # The default log includes the code and state query parameters.
        pass

    def do_GET(self) -> None:
        uri = urlsplit(self.path)
        query = parse_qs(uri.query, keep_blank_values=True)
        code = query.get("code", [])
        valid = (
            uri.path == self.server.expected_path
            and query.get("state") == [self.server.expected_state]
            and len(code) == 1
            and bool(code[0])
            and "error" not in query
        )
        if valid:
            self.server.code = code[0]
        try:
            self.send_response(200 if valid else 400)
            self.end_headers()
            self.wfile.write(b"Vault authentication callback received.")
        finally:
            self.server.received.set()


def get_oidc_token(client: hvac.Client, options: VaultOptions) -> str:
    """Use the existing ticket cache to complete Vault's OIDC redirect flow."""
    listener: _CallbackServer | None = None
    thread: Thread | None = None
    session: requests.Session | None = None
    operation = "Kerberos authentication"
    try:
        auth = _spnego_auth()
        operation = "OIDC authorization request"
        response = client.auth.oidc.oidc_authorization_url_request(
            role=options.oidc_role, redirect_uri=options.oidc_redirect_uri, path="oidc"
        )
        auth_url = response["data"]["auth_url"]
        uri = urlsplit(auth_url)
        query = parse_qs(uri.query, keep_blank_values=True)
        state, nonce = query.get("state", []), query.get("nonce", [])
        if (
            uri.scheme not in {"http", "https"}
            or not uri.hostname
            or len(state) != 1
            or not state[0]
            or len(nonce) != 1
            or not nonce[0]
        ):
            raise VaultAuthenticationError("Vault OIDC authorization response is invalid")
        operation = "OIDC callback listener setup"
        listener = _CallbackServer(options, state[0])
        thread = Thread(target=listener.listen, name="vault-oidc-callback", daemon=True)
        thread.start()
        operation = "OIDC identity-provider HTTP authentication"
        session = create_session(options.verify)
        with http_deadline(session, options.timeout) as deadline:
            http_response = session.get(
                auth_url, auth=auth, timeout=options.timeout, verify=options.verify, stream=True
            )
            try:
                deadline.remaining()
                if listener.received.is_set() and listener.code is None:
                    raise VaultAuthenticationError("Vault OIDC callback was invalid")
                http_response.raise_for_status()
                operation = "OIDC callback reception"
                if not listener.received.wait(deadline.remaining()) or listener.code is None:
                    raise VaultAuthenticationError("Vault OIDC callback was missing or invalid")
            finally:
                # The final response body is irrelevant to the OIDC callback.
                http_response.close()
        operation = "OIDC code exchange"
        response = client.auth.oidc.oidc_callback(
            code=listener.code, path="oidc", nonce=nonce[0], state=state[0]
        )
        token = response["auth"]["client_token"]
        if not isinstance(token, str) or not token:
            raise VaultAuthenticationError("Vault OIDC code exchange returned no token")
        return token
    except (ImportError, VaultAuthenticationError):
        raise
    except Exception:
        raise VaultAuthenticationError(f"Vault {operation} failed") from None
    finally:
        if listener is not None:
            listener.stop_listener()
            if thread is not None and thread.ident is not None:
                thread.join(timeout=options.timeout + 0.1)
            listener.server_close()
        if session is not None:
            try:
                session.close()
            except Exception:
                raise VaultAuthenticationError("Vault OIDC HTTP session cleanup failed") from None
