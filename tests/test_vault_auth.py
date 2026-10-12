"""Offline authentication contracts, including a real loopback callback server."""

import builtins
import dataclasses
import http.client
import socket
import ssl
import threading
import time
import traceback
from contextlib import closing, suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock

import pytest
import requests
import truststore
from urllib3.util.ssltransport import SSLTransport

from iqe_library.vault import (
    VaultAuthenticationError,
    VaultOptions,
    VaultReadError,
    VaultSecretFetcher,
    _auth,
    _http,
)
from iqe_library.vault._auth import authenticate, get_oidc_token
from iqe_library.vault._http import create_session


@pytest.fixture
def client():
    client = Mock()
    client.is_authenticated.return_value = True
    return client


@pytest.fixture
def options():
    return VaultOptions(url="https://vault.invalid")


@pytest.fixture(autouse=True)
def no_interactive_auth(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Authentication must not start a browser or subprocess")

    monkeypatch.setattr("webbrowser.open", forbidden)
    monkeypatch.setattr("webbrowser.open_new", forbidden)
    monkeypatch.setattr("webbrowser.open_new_tab", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("os.system", forbidden)


@pytest.fixture
def no_kerberos_import(monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("requests_gssapi"):
            pytest.fail("Token/AppRole authentication imported Kerberos")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)


@pytest.mark.parametrize("verify", [False, "/custom/ca.pem"])
def test_option_mapping_preserves_documented_values(verify):
    values = {
        "url": "https://vault.invalid",
        "mount_point": "custom",
        "verify": verify,
        "token": "00123",
        "role_id": "false",
        "secret_id": " secret ",
        "oidc_token": "null",
        "oidc_role": "Custom",
        "oidc_redirect_uri": "http://127.0.0.1:8251/custom/callback",
        "timeout": 1.5,
    }
    options = VaultOptions.from_mapping({**values, "unrelated": "ignored"})
    assert dataclasses.asdict(options) == values
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.timeout = 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", ""),
        ("url", 12),
        ("mount_point", ""),
        ("verify", 1),
        ("verify", ""),
        ("token", 123),
        ("role_id", False),
        ("secret_id", []),
        ("oidc_token", {}),
        ("oidc_role", None),
        ("timeout", "7"),
        ("timeout", True),
        ("timeout", 0),
        ("timeout", float("inf")),
        ("timeout", float("nan")),
        ("oidc_redirect_uri", 1),
        ("oidc_redirect_uri", "https://localhost:8250/oidc/callback"),
        ("oidc_redirect_uri", "http://example.com:8250/oidc/callback"),
        ("oidc_redirect_uri", "http://localhost.evil:8250/oidc/callback"),
        ("oidc_redirect_uri", "http://user@localhost:8250/oidc/callback"),
        ("oidc_redirect_uri", "http://localhost:bad/oidc/callback"),
        ("oidc_redirect_uri", "http://localhost:0/oidc/callback"),
        ("oidc_redirect_uri", "http://localhost:8250/oidc/callback?code=secret-sentinel"),
        ("oidc_redirect_uri", "http://localhost:8250/oidc/callback#fragment"),
    ],
)
def test_invalid_options(field, value):
    with pytest.raises(ValueError, match=field):
        VaultOptions.from_mapping({"url": "https://vault.invalid", field: value})


def test_missing_url():
    with pytest.raises(ValueError, match="url"):
        VaultOptions.from_mapping({})


@pytest.fixture
def oidc_login(monkeypatch):
    login = Mock(return_value="new-token")
    monkeypatch.setattr(_auth, "get_oidc_token", login)
    return login


def test_explicit_token_wins(client, oidc_login, no_kerberos_import):
    options = VaultOptions(
        url="https://vault.invalid", token="token", role_id="role", secret_id="secret"
    )
    authenticate(client, options)
    assert client.token == "token"
    client.auth.approle.login.assert_not_called()
    client.is_authenticated.assert_called_once_with()
    oidc_login.assert_not_called()


def test_invalid_explicit_token(client, options, oidc_login, no_kerberos_import):
    client.is_authenticated.return_value = False
    with pytest.raises(VaultAuthenticationError, match="token"):
        authenticate(client, dataclasses.replace(options, token="invalid"))
    oidc_login.assert_not_called()


def test_approle_login(client, oidc_login, no_kerberos_import):
    authenticate(
        client, VaultOptions(url="https://vault.invalid", role_id="role", secret_id="secret")
    )
    client.auth.approle.login.assert_called_once_with(role_id="role", secret_id="secret")
    client.is_authenticated.assert_called_once_with()
    oidc_login.assert_not_called()


@pytest.mark.parametrize("credentials", [{"role_id": "role"}, {"secret_id": "secret"}])
def test_incomplete_approle(client, options, credentials, oidc_login, no_kerberos_import):
    with pytest.raises(VaultAuthenticationError, match="AppRole"):
        authenticate(client, dataclasses.replace(options, **credentials))
    client.auth.approle.login.assert_not_called()
    oidc_login.assert_not_called()


def test_failed_approle_does_not_fall_back(client, options, oidc_login, no_kerberos_import):
    client.is_authenticated.return_value = False
    with pytest.raises(VaultAuthenticationError, match="AppRole"):
        authenticate(client, dataclasses.replace(options, role_id="role", secret_id="secret"))
    oidc_login.assert_not_called()


def test_cached_oidc_reuse(client, options, oidc_login, no_kerberos_import):
    authenticate(client, dataclasses.replace(options, oidc_token="cached-token"))
    assert client.token == "cached-token"
    oidc_login.assert_not_called()


def test_expired_oidc_fallback(client, options, oidc_login):
    client.is_authenticated.side_effect = [False, True]
    options = dataclasses.replace(options, oidc_token="expired-token")
    authenticate(client, options)
    assert client.token == "new-token"
    assert client.is_authenticated.call_count == 2
    oidc_login.assert_called_once_with(client, options)


def test_no_credentials_headless_login(client, options, oidc_login):
    authenticate(client, options)
    assert client.token == "new-token"
    oidc_login.assert_called_once_with(client, options)


def test_new_oidc_token_must_authenticate(client, options, oidc_login):
    client.is_authenticated.return_value = False
    with pytest.raises(VaultAuthenticationError, match="OIDC"):
        authenticate(client, options)
    oidc_login.assert_called_once_with(client, options)


@pytest.mark.parametrize("method", ["token", "approle", "oidc"])
def test_authentication_errors_hide_upstream_content(client, options, oidc_login, method, caplog):
    if method == "token":
        options = dataclasses.replace(options, token="secret-sentinel")
    elif method == "approle":
        options = dataclasses.replace(options, role_id="role", secret_id="secret-sentinel")
    client.is_authenticated.side_effect = requests.RequestException("secret-sentinel")
    with pytest.raises(VaultAuthenticationError) as error:
        authenticate(client, options)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text


@pytest.mark.parametrize(
    ("verify", "environment_ca", "expected"),
    [
        (False, None, False),
        (False, "/environment/ca.pem", False),
        ("/custom/ca.pem", None, "/custom/ca.pem"),
        ("/custom/ca.pem", "/environment/ca.pem", "/custom/ca.pem"),
        (True, "/environment/ca.pem", "/environment/ca.pem"),
        (True, None, True),
    ],
)
def test_transport_trust_selection(monkeypatch, verify, environment_ca, expected):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    if environment_ca:
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", environment_ca)
    context = Mock(spec=ssl.SSLContext)
    system_context = Mock(return_value=context)
    monkeypatch.setattr(truststore, "SSLContext", system_context)
    with create_session(verify) as session:
        settings = session.merge_environment_settings("https://vault.invalid", {}, None, None, None)
        assert settings["verify"] == expected
        request = requests.Request("GET", "https://vault.invalid").prepare()
        adapter = session.get_adapter(request.url)
        pool = adapter.get_connection_with_tls_context(request, settings["verify"])
        if expected is True:
            assert pool.conn_kw["ssl_context"] is context
            system_context.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        else:
            assert "ssl_context" not in pool.conn_kw
            system_context.assert_not_called()
            if expected is False:
                assert pool.cert_reqs == "CERT_NONE"
            else:
                assert pool.ca_certs == expected


class ListenerProbe:
    """Allocate a loopback port and track only this flow's callback thread."""

    def __init__(self):
        with closing(socket.socket()) as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.threads = []

    def thread(self, *args, **kwargs):
        thread = threading.Thread(*args, **kwargs)
        self.threads.append(thread)
        return thread

    def listener_port_can_be_rebound(self):
        with closing(socket.socket()) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", self.port))
        return True

    def callback_thread_is_alive(self):
        return any(thread.is_alive() for thread in self.threads)

    def callback(self, path="/oidc/callback?code=test-code&state=test-state"):
        with closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)) as connection:
            connection.request("GET", path)
            response = connection.getresponse()
            response.read()
            return response.status


@pytest.fixture
def listener(monkeypatch):
    probe = ListenerProbe()
    monkeypatch.setattr(_auth, "Thread", probe.thread)
    yield probe
    assert not probe.callback_thread_is_alive()
    assert probe.listener_port_can_be_rebound()


@pytest.fixture
def headless(client, listener, monkeypatch):
    options = VaultOptions(
        url="https://vault.invalid",
        oidc_role="Custom",
        oidc_redirect_uri=f"http://localhost:{listener.port}/oidc/callback",
        timeout=0.2,
        verify="/custom/ca.pem",
    )
    auth_url = "https://idp.invalid/auth?state=test-state&nonce=test-nonce"
    client.auth.oidc.oidc_authorization_url_request.return_value = {"data": {"auth_url": auth_url}}
    client.auth.oidc.oidc_callback.return_value = {"auth": {"client_token": "issued-token"}}
    spnego = requests.auth.AuthBase()
    monkeypatch.setattr(_auth, "_spnego_auth", Mock(return_value=spnego))
    session = Mock(spec=requests.Session)
    session.get.return_value = Mock(spec=requests.Response)

    def get(*args, **kwargs):
        assert listener.callback() == 200
        return session.get.return_value

    session.get.side_effect = get
    monkeypatch.setattr(_auth, "create_session", Mock(return_value=session))
    return options, session, spnego, auth_url


def test_headless_oidc_success(client, headless, listener, capsys):
    options, session, spnego, auth_url = headless
    assert get_oidc_token(client, options) == "issued-token"
    client.auth.oidc.oidc_authorization_url_request.assert_called_once_with(
        role="Custom", redirect_uri=options.oidc_redirect_uri, path="oidc"
    )
    client.auth.oidc.oidc_callback.assert_called_once_with(
        code="test-code", path="oidc", nonce="test-nonce", state="test-state"
    )
    _auth.create_session.assert_called_once_with("/custom/ca.pem")
    session.get.assert_called_once_with(
        auth_url, auth=spnego, timeout=0.2, verify="/custom/ca.pem", stream=True
    )
    session.close.assert_called_once_with()
    assert listener.threads
    assert listener.listener_port_can_be_rebound()
    assert not listener.callback_thread_is_alive()
    assert "test-code" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "failure",
    [
        "http",
        "http_status",
        "no_callback",
        "wrong_state",
        "malformed",
        "wrong_path",
        "duplicate",
        "exchange",
    ],
)
def test_headless_failure_cleanup(client, headless, listener, failure, caplog, capsys):
    options, session, _, _ = headless
    if failure == "http":
        session.get.side_effect = requests.HTTPError("secret-sentinel")
    elif failure == "http_status":
        session.get.side_effect = None
        session.get.return_value.raise_for_status.side_effect = requests.HTTPError(
            "secret-sentinel"
        )
    elif failure == "no_callback":
        session.get.side_effect = None
    elif failure in {"wrong_state", "malformed", "wrong_path", "duplicate"}:
        paths = {
            "wrong_state": "/oidc/callback?code=secret-sentinel&state=wrong",
            "malformed": "/oidc/callback?state=test-state&error=secret-sentinel",
            "wrong_path": "/wrong?code=secret-sentinel&state=test-state",
            "duplicate": "/oidc/callback?code=secret-sentinel&code=other&state=test-state",
        }

        def get(*args, **kwargs):
            assert listener.callback(paths[failure]) == 400
            return session.get.return_value

        session.get.side_effect = get
    else:
        client.auth.oidc.oidc_callback.side_effect = RuntimeError("secret-sentinel")
    with pytest.raises(VaultAuthenticationError) as error:
        get_oidc_token(client, options)
    assert listener.listener_port_can_be_rebound()
    assert not listener.callback_thread_is_alive()
    session.close.assert_called_once_with()
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text
    assert "secret-sentinel" not in capsys.readouterr().err
    if failure != "exchange":
        client.auth.oidc.oidc_callback.assert_not_called()


@pytest.mark.parametrize(
    "auth_url",
    [
        "https://idp.invalid?nonce=test-nonce",
        "https://idp.invalid?state=test-state",
        "https://idp.invalid?state=one&state=two&nonce=test-nonce",
        "https://idp.invalid?state=&nonce=test-nonce",
    ],
)
def test_invalid_authorization_response(client, headless, auth_url):
    options, session, _, _ = headless
    client.auth.oidc.oidc_authorization_url_request.return_value = {"data": {"auth_url": auth_url}}
    with pytest.raises(VaultAuthenticationError, match="authorization"):
        get_oidc_token(client, options)
    session.get.assert_not_called()
    client.auth.oidc.oidc_callback.assert_not_called()


@pytest.mark.parametrize("response", [{}, {"auth": {}}, {"auth": {"client_token": ""}}])
def test_invalid_exchange_response(client, headless, response):
    options, session, _, _ = headless
    client.auth.oidc.oidc_callback.return_value = response
    with pytest.raises(VaultAuthenticationError, match="exchange"):
        get_oidc_token(client, options)
    session.close.assert_called_once_with()


def test_listener_bind_failure_is_contextual(client, headless, listener):
    options, session, _, _ = headless
    with closing(socket.socket()) as occupied:
        occupied.bind(("127.0.0.1", listener.port))
        occupied.listen()
        with pytest.raises(VaultAuthenticationError, match="listener setup"):
            get_oidc_token(client, options)
    session.get.assert_not_called()


def test_partial_callback_is_interrupted_on_http_failure(client, headless, listener, monkeypatch):
    options, session, _, _ = headless
    options = dataclasses.replace(options, timeout=5)
    accepted = threading.Event()
    original = _auth._CallbackServer.get_request

    def get_request(server):
        result = original(server)
        accepted.set()
        return result

    monkeypatch.setattr(_auth._CallbackServer, "get_request", get_request)
    connections = []

    def get(*args, **kwargs):
        connection = socket.create_connection(("127.0.0.1", listener.port), timeout=1)
        connections.append(connection)
        connection.sendall(b"GET /oidc/callback?code=secret-sentinel HTTP/1.1\r\n")
        assert accepted.wait(1)
        raise requests.Timeout("secret-sentinel")

    session.get.side_effect = get
    started = time.monotonic()
    try:
        with pytest.raises(VaultAuthenticationError, match="HTTP authentication"):
            get_oidc_token(client, options)
        assert not listener.callback_thread_is_alive()
        assert time.monotonic() - started < 2
    finally:
        for connection in connections:
            connection.close()


def test_rejected_callback_is_reported_as_callback_failure(client, headless, listener):
    options, session, _, _ = headless

    def get(*args, **kwargs):
        assert listener.callback("/oidc/callback?code=secret-sentinel&state=wrong") == 400
        return session.get.return_value

    session.get.side_effect = get
    session.get.return_value.raise_for_status.side_effect = requests.HTTPError("secret-sentinel")
    with pytest.raises(VaultAuthenticationError, match="callback"):
        get_oidc_token(client, options)
    client.auth.oidc.oidc_callback.assert_not_called()


def test_session_cleanup_errors_are_sanitized(client, headless):
    options, session, _, _ = headless
    session.close.side_effect = RuntimeError("secret-sentinel")
    with pytest.raises(VaultAuthenticationError, match="cleanup") as error:
        get_oidc_token(client, options)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))


def test_missing_kerberos_dependency(client, options, monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "requests_gssapi":
            raise ImportError("secret-sentinel")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(ImportError, match=r"iqe-library\[kerberos\]") as error:
        get_oidc_token(client, options)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    client.auth.oidc.oidc_authorization_url_request.assert_not_called()


@pytest.mark.parametrize(
    ("operation", "response_kind"),
    [
        ("token", "body"),
        ("approle", "body"),
        ("authorization", "body"),
        ("exchange", "body"),
        ("kv", "body"),
        ("kv", "headers"),
        ("kv", "redirect_body"),
        ("kv", "redirect_chain"),
        ("idp", "body"),
        ("idp", "headers"),
        ("idp", "redirect_body"),
        ("idp", "redirect_chain"),
    ],
)
def test_vault_response_deadline_and_recovery(listener, monkeypatch, operation, response_kind):
    """Vault and IdP flows bound real reads/redirects and clean up before retrying."""
    stop = threading.Event()
    disconnected = threading.Event()
    finished = threading.Event()
    reached = threading.Event()
    timers = []
    idp_sessions = []
    requested = []
    result = {}
    slow = True
    routes = {
        "token": "/v1/auth/token/lookup-self",
        "approle": "/v1/auth/approle/login",
        "authorization": "/v1/auth/oidc/oidc/auth_url",
        "exchange": "/v1/auth/oidc/oidc/callback",
        "kv": "/v1/insights/data/users/demo",
        "idp": "/idp",
    }

    class NoopAuth(requests.auth.AuthBase):
        def __call__(self, request):
            return request

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.do_GET()

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            try:
                if slow and path == routes[operation]:
                    reached.set()
                    requested.append(path)
                    if operation == "idp" and response_kind == "body":
                        assert listener.callback() == 200
                    if response_kind == "headers":
                        self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Trickle: ")
                    else:
                        if response_kind == "redirect_chain":
                            stop.wait(0.03)
                        self.send_response(307 if response_kind.startswith("redirect") else 200)
                        if response_kind.startswith("redirect"):
                            self.send_header("Location", path)
                        self.send_header(
                            "Content-Length",
                            "0" if response_kind == "redirect_chain" else "1000000",
                        )
                        self.end_headers()
                        if response_kind == "redirect_chain":
                            return
                    while not stop.wait(0.01):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                    return
                if path == routes["authorization"]:
                    body = (
                        '{"data":{"auth_url":"'
                        + base_url
                        + '/idp?state=test-state&nonce=test-nonce"}}'
                    ).encode()
                elif path == "/idp":
                    assert listener.callback() == 200
                    body = b"ok"
                elif path == routes["kv"]:
                    body = b'{"data":{"data":{"value":7}}}'
                elif path == routes["token"]:
                    body = b'{"data":{"id":"issued-token"}}'
                else:
                    body = b'{"auth":{"client_token":"issued-token"}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                disconnected.set()

    def timer(*args, **kwargs):
        instance = threading.Timer(*args, **kwargs)
        timers.append(instance)
        return instance

    monkeypatch.setattr(_http, "Timer", timer)
    monkeypatch.setattr(_auth, "_spnego_auth", NoopAuth)

    def idp_session(verify):
        session = create_session(verify)
        session.trust_env = False
        session.close = Mock(wraps=session.close)
        idp_sessions.append(session)
        return session

    monkeypatch.setattr(_auth, "create_session", idp_session)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    server = HTTPServer(("127.0.0.1", 0), Handler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    credentials = (
        {"role_id": "role", "secret_id": "secret"}
        if operation == "approle"
        else {"token": "test-token"}
        if operation in {"token", "kv"}
        else {}
    )
    fetcher = VaultSecretFetcher(
        VaultOptions(
            url=base_url,
            timeout=0.15 if operation == "idp" else 0.1,
            oidc_redirect_uri=f"http://127.0.0.1:{listener.port}/oidc/callback",
            **credentials,
        )
    )

    def fetch():
        try:
            result["value"] = fetcher.get("users/demo")
        except Exception as error:
            result["error"] = error
        finally:
            finished.set()

    serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    fetching = threading.Thread(target=fetch)
    serving.start()
    fetching.start()
    try:
        assert reached.wait(1), f"Vault operation did not reach the real HTTP endpoint: {result}"
        assert finished.wait(0.5), "Vault response outlived its deadline"
        fetching.join(timeout=0.1)
        assert not fetching.is_alive()
        if operation == "idp" and response_kind == "body":
            # A valid callback makes the final IdP body irrelevant: never read it.
            assert result == {"value": {"value": 7}}
        else:
            error_type = VaultReadError if operation == "kv" else VaultAuthenticationError
            assert isinstance(result.get("error"), error_type)
        if response_kind != "redirect_chain":
            assert disconnected.wait(0.3), "Vault response socket was not closed"
        else:
            assert len(requested) >= 2
        assert all(session.close.call_count == 1 for session in idp_sessions)
        assert all(not instance.is_alive() for instance in timers)
        assert not listener.callback_thread_is_alive()
        assert listener.listener_port_can_be_rebound()
        # No failed-read caching or expired budget/pool may poison the next call.
        slow = False
        assert fetcher.get("users/demo") == {"value": 7}
        assert all(not instance.is_alive() for instance in timers)
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        serving.join(timeout=1)
        fetching.join(timeout=2)
        if fetcher._client is not None:
            fetcher._client.adapter.close()
        assert not serving.is_alive()
        assert not fetching.is_alive()


@pytest.mark.parametrize("times_out", [False, True], ids=["success", "timeout"])
def test_https_proxy_transport_deadline_and_cleanup(monkeypatch, times_out):
    """Exercise SSLTransport's real file/socket lifecycle with only TLS crypto stubbed."""
    stop = threading.Event()
    finished = threading.Event()
    timers = []
    result = {}

    def wrap_bio(incoming, outgoing, **kwargs):
        # A transparent TLS engine keeps this an offline transport-interface
        # test. SSLTransport's I/O loop, makefile, and real sockets remain intact.
        def read(size, buffer=None):
            data = incoming.read(size)
            if not data:
                if incoming.eof:
                    raise ssl.SSLEOFError(ssl.SSL_ERROR_EOF, "closed")
                raise ssl.SSLWantReadError(ssl.SSL_ERROR_WANT_READ, "read")
            if buffer is None:
                return data
            buffer[: len(data)] = data
            return len(data)

        engine = Mock()
        engine.do_handshake.return_value = None
        engine.read.side_effect = read
        return engine

    def timer(*args, **kwargs):
        instance = threading.Timer(*args, **kwargs)
        timers.append(instance)
        return instance

    monkeypatch.setattr(_http, "Timer", timer)
    context = Mock(spec=ssl.SSLContext)
    context.wrap_bio.side_effect = wrap_bio
    local, peer = socket.socketpair()
    transport = SSLTransport(local, context, server_hostname="idp.invalid")
    session = create_session(False)

    def serve():
        try:
            peer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            if not times_out:
                peer.sendall(b"ok")
                peer.shutdown(socket.SHUT_WR)
            else:
                while not stop.wait(0.01):
                    peer.sendall(b"x")
        except OSError:
            pass

    def request():
        try:
            with (
                closing(session),
                _http.http_deadline(session, 0.1) as deadline,
                deadline.response_class(transport) as response,
            ):
                response.begin()
                body = response.read()
            result["body"] = body
        except Exception as error:
            result["error"] = error
        finally:
            finished.set()

    serving = threading.Thread(target=serve)
    requesting = threading.Thread(target=request)
    serving.start()
    requesting.start()
    try:
        assert finished.wait(0.5), "Wrapped response read outlived the deadline"
        requesting.join(timeout=0.1)
        assert not requesting.is_alive()
        if times_out:
            assert isinstance(result.get("error"), requests.Timeout)
        else:
            assert result == {"body": b"ok"}
        # Assert cancellation before the test closes the transport itself.
        peer.settimeout(0.2)
        assert peer.recv(1) == b""
        assert all(not instance.is_alive() for instance in timers)
    finally:
        stop.set()
        # Release the old, broken implementation's read before joining it.
        with closing(peer):
            with suppress(OSError):
                peer.shutdown(socket.SHUT_WR)
            serving.join(timeout=1)
            requesting.join(timeout=1)
        transport.close()
        assert local.fileno() == -1
        assert not serving.is_alive()
        assert not requesting.is_alive()
