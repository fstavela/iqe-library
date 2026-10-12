"""Offline Requests session contracts at the adapter and pool boundaries."""

import socket
import ssl
from io import BytesIO
from pathlib import Path

import pytest
import requests
import truststore
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.response import HTTPResponse

from iqe_library.auth import CertificateAuth, IdentityAuth, NoAuth
from iqe_library.http import create_session


@pytest.fixture
def sent(http_transport):
    return http_transport.calls


def test_auth_only_session_defaults(sent):
    auth = HTTPBasicAuth("u", "p")
    with create_session(auth=auth) as session:
        assert isinstance(session, requests.Session)
        assert session.auth is auth
        assert session.verify is True
        assert session.trust_env is True
        assert "Content-Type" not in session.headers
        session.get("https://service.invalid")
    assert sent[0][1]["timeout"] == 30
    assert sent[0][0].headers["Authorization"] == "Basic dTpw"


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [({}, 30), ({"timeout": None}, None), ({"timeout": 7}, 7), ({"timeout": (2, 5)}, (2, 5))],
)
def test_request_timeout_override(sent, kwargs, expected):
    with create_session() as session:
        session.get("https://service.invalid", **kwargs)
    assert sent[0][1]["timeout"] == expected


@pytest.mark.parametrize("timeout", [None, (2, 5)])
def test_request_positional_timeout_override(sent, timeout):
    with create_session() as session:
        session.request(
            "GET", "https://service.invalid", None, None, None, None, None, None, timeout
        )
    assert sent[0][1]["timeout"] == timeout


def test_request_positional_omission_uses_default(sent):
    with create_session() as session:
        session.request("GET", "https://service.invalid", None, None, None, None, None, None)
    assert sent[0][1]["timeout"] == 30


def test_request_positional_timeout_duplicate_keeps_native_error(sent):
    with (
        create_session() as session,
        pytest.raises(TypeError, match="multiple values for argument 'timeout'"),
    ):
        session.request(
            "GET", "https://service.invalid", None, None, None, None, None, None, 7, timeout=9
        )
    assert not sent


def test_custom_timeout_and_auth_tuple(sent):
    with create_session(auth=("u", "p"), timeout=11) as session:
        session.get("https://service.invalid")
    assert sent[0][1]["timeout"] == 11
    assert sent[0][0].headers["Authorization"] == "Basic dTpw"


def test_input_mapping_isolation(sent):
    headers = {"X-Test": "original"}
    cookies = {"test": "original"}
    proxies = {"https": "http://original.invalid"}
    with create_session(headers=headers, cookies=cookies, proxies=proxies) as session:
        headers["X-Test"] = cookies["test"] = proxies["https"] = "changed"
        assert session.headers["X-Test"] == "original"
        assert session.cookies.get("test") == "original"
        assert session.proxies == {"https": "http://original.invalid"}
        session.get("https://service.invalid")
    request, settings = sent[0]
    assert request.headers["X-Test"] == "original"
    assert request.headers["Cookie"] == "test=original"
    assert settings["proxies"] == {"https": "http://original.invalid"}


def test_factory_certificate_cleanup_order(monkeypatch):
    session = create_session(auth=CertificateAuth.from_pem("cert", "key"))
    assert isinstance(session.auth, NoAuth)
    paths = tuple(Path(path) for path in session.cert)
    events = []
    original_close = HTTPAdapter.close

    def close(adapter):
        events.append(tuple(path.exists() for path in paths))
        original_close(adapter)

    monkeypatch.setattr(HTTPAdapter, "close", close)
    local, peer = socket.socketpair()
    try:
        request = requests.Request("GET", "https://service.invalid").prepare()
        pool = session.get_adapter(request.url).get_connection_with_tls_context(
            request,
            True,
            cert=session.cert,
        )
        connection = pool._get_conn()
        connection.sock = local
        pool._put_conn(connection)
        # Do not retain a test-owned pool reference: urllib3 releases its idle
        # connections when the adapter drops the pool. No endpoint is contacted.
        del pool
        session.close()
        assert events == [(True, True), (True, True)]
        assert local.fileno() == -1
        assert all(not path.exists() for path in paths)
        assert not paths[0].parent.exists()
        session.close()
    finally:
        session.close()
        local.close()
        peer.close()


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_early_adapter_failure_still_closes_later_connections_before_pem_cleanup(
    monkeypatch, failure_type
):
    session = create_session(auth=CertificateAuth.from_pem("cert", "key"))
    paths = tuple(Path(path) for path in session.cert)
    first_failure = failure_type("first adapter failed")
    prefix = "https://service.invalid/early"

    class FailingAdapter(HTTPAdapter):
        def close(self):
            super().close()
            raise first_failure

    early = FailingAdapter()
    session.mount(prefix, early)
    https = session.get_adapter("https://")
    http = session.get_adapter("http://")
    events = []
    original_close = HTTPAdapter.close

    def close(adapter):
        events.append((adapter, tuple(path.exists() for path in paths)))
        original_close(adapter)
        if adapter is http:
            raise RuntimeError("later adapter failed")

    monkeypatch.setattr(HTTPAdapter, "close", close)
    sockets = [socket.socketpair(), socket.socketpair()]
    try:
        for adapter, scheme, (local, _) in zip(
            (https, http), ("https", "http"), sockets, strict=True
        ):
            request = requests.Request("GET", f"{scheme}://service.invalid").prepare()
            pool = adapter.get_connection_with_tls_context(request, True, cert=session.cert)
            connection = pool._get_conn()
            connection.sock = local
            pool._put_conn(connection)
            del pool
        with pytest.raises(failure_type) as error:
            session.close()
        assert error.value is first_failure
        assert events == [(early, (True, True)), (https, (True, True)), (http, (True, True))]
        assert all(local.fileno() == -1 for local, _ in sockets)
        assert all(not path.exists() for path in paths)
        assert not paths[0].parent.exists()
    finally:
        session.adapters.pop(prefix)
        monkeypatch.setattr(HTTPAdapter, "close", original_close)
        session.close()
        for local, peer in sockets:
            local.close()
            peer.close()


def test_factory_failure_cleans_pem_files(monkeypatch):
    paths = []
    original_mount = requests.Session.mount

    def mount(session, prefix, adapter):
        if session.cert is not None:
            paths.extend(Path(path) for path in session.cert)
            assert all(path.exists() for path in paths)
            raise RuntimeError("initialization failed")
        original_mount(session, prefix, adapter)

    monkeypatch.setattr(requests.Session, "mount", mount)
    with pytest.raises(RuntimeError, match="initialization failed"):
        create_session(auth=CertificateAuth.from_pem("cert", "key"))
    assert len(paths) == 2
    assert all(not path.exists() for path in paths)
    assert not paths[0].parent.exists()


def test_two_sessions_from_one_certificate_description():
    auth = CertificateAuth.from_pem("cert", "key")
    with create_session(auth=auth) as first, create_session(auth=auth) as second:
        first_paths = tuple(Path(path) for path in first.cert)
        second_paths = tuple(Path(path) for path in second.cert)
        assert first_paths != second_paths
        assert first_paths[0].read_text() == second_paths[0].read_text() == "cert"
        assert first_paths[1].read_text() == second_paths[1].read_text() == "key"
        first.close()
        assert all(not path.exists() for path in first_paths)
        assert all(path.exists() for path in second_paths)
    assert all(not path.exists() for path in second_paths)


@pytest.mark.parametrize("split", [False, True])
def test_caller_owned_certificate_files_survive_close(tmp_path, sent, split):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    auth = CertificateAuth.from_files(cert, key) if split else CertificateAuth.from_files(str(cert))
    with create_session(auth=auth) as session:
        session.get("https://service.invalid")
    assert sent[0][1]["cert"] == ((str(cert), str(key)) if split else str(cert))
    assert cert.read_text() == "cert"
    assert key.read_text() == "key"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verify", None),
        ("proxies", {"https": None}),
        ("timeout", 0),
        ("trust_env", 1),
    ],
)
def test_factory_validates_options(field, value):
    with pytest.raises(ValueError, match=field):
        create_session(**{field: value})


@pytest.mark.parametrize("timeout", [10**1000, -(10**1000)], ids=["huge", "negative-huge"])
def test_factory_oversized_timeout_is_sanitized(timeout):
    with pytest.raises(ValueError, match="timeout must be a positive finite number") as error:
        create_session(timeout=timeout)
    assert str(timeout) not in str(error.value)
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("session_verify", "request_kwargs", "expected"),
    [
        (True, {}, "/environment/ca.pem"),
        (False, {}, False),
        ("/session/ca.pem", {}, "/session/ca.pem"),
        (True, {"verify": False}, False),
        (True, {"verify": "/request/ca.pem"}, "/request/ca.pem"),
        (False, {"verify": True}, "/environment/ca.pem"),
        ("/session/ca.pem", {"verify": None}, "/session/ca.pem"),
    ],
)
def test_explicit_proxy_and_ca_precedence(
    monkeypatch, sent, session_verify, request_kwargs, expected
):
    monkeypatch.setenv("HTTP_PROXY", "http://environment-http.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "http://environment-https.invalid")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/environment/ca.pem")
    proxies = {"http": "http://request.invalid"}
    with create_session(
        verify=session_verify,
        proxies={"http": "http://session-http.invalid", "https": "http://session-https.invalid"},
    ) as session:
        session.get("https://service.invalid", proxies=proxies, **request_kwargs)
    assert sent[0][1]["proxies"] == {
        "http": "http://request.invalid",
        "https": "http://session-https.invalid",
    }
    assert sent[0][1]["verify"] == expected
    assert proxies == {"http": "http://request.invalid"}


@pytest.mark.parametrize(
    ("trust_env", "request_proxies", "expected"),
    [
        (True, {}, {"https": "http://environment.invalid"}),
        (False, {}, {}),
        (True, {"https": None}, {"https": None}),
    ],
)
def test_empty_proxies_and_none_entry(monkeypatch, sent, trust_env, request_proxies, expected):
    monkeypatch.setenv("HTTPS_PROXY", "http://environment.invalid")
    with create_session(proxies={}, trust_env=trust_env) as session:
        session.get("https://service.invalid", proxies=request_proxies)
    assert sent[0][1]["proxies"] == expected


@pytest.mark.parametrize(
    "scheme,redirect_host,session_proxy",
    [("http", "service.invalid", None), ("https", "other.invalid", "http://session.invalid")],
)
def test_proxy_exclusion_survives_redirects(monkeypatch, scheme, redirect_host, session_proxy):
    monkeypatch.setenv(f"{scheme.upper()}_PROXY", "http://ambient.invalid")
    settings = []
    routes = []
    original_send = HTTPAdapter.send

    def send(adapter, request, **kwargs):
        settings.append(dict(kwargs["proxies"]))
        return original_send(adapter, request, **kwargs)

    def urlopen(pool, **kwargs):
        routes.append((pool.proxy.host, pool.proxy.port) if pool.proxy is not None else None)
        redirect = len(routes) == 1
        headers = {"Location": f"{scheme}://{redirect_host}/hop"} if redirect else {}
        return HTTPResponse(
            body=BytesIO(b""),
            status=302 if redirect else 200,
            headers=headers,
            preload_content=False,
        )

    monkeypatch.setattr(HTTPAdapter, "send", send)
    monkeypatch.setattr(HTTPConnectionPool, "urlopen", urlopen)
    session_proxies = {scheme: session_proxy} if session_proxy is not None else {}
    request_proxies = {scheme: None}
    with create_session(proxies=session_proxies) as session:
        response = session.get(f"{scheme}://service.invalid/start", proxies=request_proxies)
        assert len(response.history) == 1
        assert [proxies.get(scheme) for proxies in settings] == [None, None]
        assert routes == [None, None]
        assert request_proxies == {scheme: None}
        assert session.proxies == session_proxies
        # An exclusion belongs to one request flow, not the whole session.
        session.get(f"{scheme}://service.invalid/later")
    expected_proxy = session_proxy or "http://ambient.invalid"
    assert settings[2][scheme] == expected_proxy
    assert routes[2] == (("session.invalid", 80) if session_proxy else ("ambient.invalid", 80))


@pytest.mark.parametrize(
    "variable,trust_env",
    [("REQUESTS_CA_BUNDLE", True), ("CURL_CA_BUNDLE", True), ("REQUESTS_CA_BUNDLE", False)],
)
def test_environment_ca_fallback(monkeypatch, sent, variable, trust_env):
    monkeypatch.setenv(variable, "/environment/ca.pem")
    with create_session(trust_env=trust_env) as session:
        session.get("https://service.invalid")
    assert sent[0][1]["verify"] == ("/environment/ca.pem" if trust_env else True)


@pytest.fixture
def redirect_transport(monkeypatch):
    calls = []
    destinations = []

    def send(adapter, request, **kwargs):
        calls.append(request)
        response = requests.Response()
        response.status_code = 302 if destinations else 200
        if destinations:
            response.headers["Location"] = destinations.pop(0)
        response.url = request.url
        response.request = request
        response._content = b""
        return response

    monkeypatch.setattr(HTTPAdapter, "send", send)
    return calls, destinations


@pytest.mark.parametrize("auth_kind", ["none", "certificate", "basic", "identity"])
def test_no_netrc_on_initial_or_redirect_request(monkeypatch, redirect_transport, auth_kind):
    netrc_urls = []

    def netrc(url):
        netrc_urls.append(url)
        return "ambient-user", "ambient-password"

    monkeypatch.setattr(requests.sessions, "get_netrc_auth", netrc)
    auth = {
        "none": None,
        "certificate": CertificateAuth.from_pem("cert", "key"),
        "basic": HTTPBasicAuth("u", "p"),
        "identity": IdentityAuth({"type": "User"}),
    }[auth_kind]
    calls, destinations = redirect_transport
    destinations.append("https://other.invalid")
    with create_session(auth=auth) as session:
        session.get("https://service.invalid")
    assert len(calls) == 2
    assert "Authorization" not in calls[1].headers
    if auth_kind in {"none", "certificate", "identity"}:
        assert "Authorization" not in calls[0].headers
    assert netrc_urls == []


class HeaderAuth(requests.auth.AuthBase):
    def __init__(self):
        self.calls = 0

    def __call__(self, request):
        self.calls += 1
        request.headers.update({"Authorization": "Bearer sentinel", "X-RH-Identity": "sentinel"})
        return request


@pytest.mark.parametrize(
    ("source", "destination", "keep_authorization", "keep_identity"),
    [
        ("https://service.invalid/a", "https://other.invalid/b", False, False),
        ("https://service.invalid/a", "https://service.invalid:444/b", False, False),
        ("https://service.invalid/a", "http://service.invalid/b", False, False),
        ("http://service.invalid/a", "https://service.invalid/b", True, False),
        ("https://service.invalid/a", "https://service.invalid:443/b", True, True),
        ("http://service.invalid:80/a", "http://service.invalid/b", True, True),
        ("https://service.invalid/a", "https://SERVICE.invalid/b", True, True),
        ("https://service.invalid/a", "/b", True, True),
    ],
)
def test_cross_origin_redirect_strips_credentials(
    redirect_transport,
    source,
    destination,
    keep_authorization,
    keep_identity,
):
    calls, destinations = redirect_transport
    destinations.append(destination)
    auth = HeaderAuth()
    with create_session(auth=auth) as session:
        session.get(source)
    assert len(calls) == 2
    assert calls[0].headers["Authorization"] == "Bearer sentinel"
    assert calls[0].headers["x-rh-identity"] == "sentinel"
    assert calls[1].headers.get("Authorization") == (
        "Bearer sentinel" if keep_authorization else None
    )
    assert calls[1].headers.get("x-rh-identity") == ("sentinel" if keep_identity else None)
    assert auth.calls == 1


def test_explicit_headers_not_reapplied_after_cross_origin_redirect(redirect_transport):
    calls, destinations = redirect_transport
    destinations.extend(["https://other.invalid", "https://service.invalid/back"])
    with create_session(
        headers={"Authorization": "Bearer sentinel", "x-rh-identity": "sentinel"}
    ) as session:
        session.get("https://service.invalid")
    assert len(calls) == 3
    assert calls[0].headers["Authorization"] == "Bearer sentinel"
    for request in calls[1:]:
        assert "Authorization" not in request.headers
        assert "x-rh-identity" not in request.headers


@pytest.mark.parametrize(
    "verify,proxied",
    [(True, False), (True, True), (False, False), ("custom", True), ("environment", False)],
)
def test_system_trust_and_explicit_ca_policies(monkeypatch, tmp_path, verify, proxied):
    contexts = []
    pools = []

    def context(protocol):
        assert protocol == ssl.PROTOCOL_TLS_CLIENT
        result = ssl.SSLContext(protocol)
        contexts.append(result)
        return result

    def urlopen(pool, **kwargs):
        pools.append(pool)
        return HTTPResponse(body=BytesIO(b"ok"), status=200, preload_content=False)

    monkeypatch.setattr(truststore, "SSLContext", context)
    monkeypatch.setattr(HTTPSConnectionPool, "urlopen", urlopen)
    ca = tmp_path / "ca.pem"
    ca.write_text("ca")
    cert = tmp_path / "client.pem"
    cert.write_text("cert")
    if verify == "environment":
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca))
    verification = str(ca) if verify == "custom" else True if verify == "environment" else verify
    proxies = {"https": "http://proxy.invalid"} if proxied else None
    with create_session(
        auth=CertificateAuth.from_files(cert),
        verify=verification,
        proxies=proxies,
    ) as session:
        assert session.get("https://service.invalid").content == b"ok"
    pool = pools[0]
    assert pool.cert_file == str(cert)
    if verify is True:
        assert len(contexts) == 1
        assert pool.conn_kw["ssl_context"] is contexts[0]
        assert pool.cert_reqs == "CERT_REQUIRED"
        assert pool.ca_certs is None
    else:
        assert contexts == []
        assert "ssl_context" not in pool.conn_kw
        assert pool.cert_reqs == ("CERT_NONE" if verify is False else "CERT_REQUIRED")
        assert pool.ca_certs == (str(ca) if verify in {"custom", "environment"} else None)
    assert (pool.proxy is not None) is proxied


@pytest.mark.parametrize("proxied", [False, True])
def test_different_client_certificates_do_not_share_ssl_context(monkeypatch, proxied):
    monkeypatch.setattr(truststore, "SSLContext", ssl.SSLContext)
    with create_session() as session:
        adapter = session.get_adapter("https://")
        request = requests.Request("GET", "https://service.invalid").prepare()
        proxies = {"https": "http://proxy.invalid"} if proxied else None
        first = adapter.get_connection_with_tls_context(
            request, True, proxies, ("one.pem", "one.key")
        )
        second = adapter.get_connection_with_tls_context(
            request, True, proxies, ("two.pem", "two.key")
        )
        anonymous = adapter.get_connection_with_tls_context(request, True, proxies)
        combined = adapter.get_connection_with_tls_context(request, True, proxies, "combined.pem")
        repeated = adapter.get_connection_with_tls_context(
            request, True, proxies, ("one.pem", "one.key")
        )
        contexts = [pool.conn_kw["ssl_context"] for pool in (first, second, anonymous, combined)]
        assert len({id(context) for context in contexts}) == 4
        contexts[0].check_hostname = False
        assert all(context.check_hostname for context in contexts[1:])
        assert repeated is first
