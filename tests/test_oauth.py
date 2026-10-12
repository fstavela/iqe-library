"""Offline OAuth contracts with real request preparation and thread locking."""

import json
import logging
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import requests
from requests.auth import AuthBase

from iqe_library import auth as auth_module
from iqe_library._transport import _SystemTrustAdapter
from iqe_library.auth import NoAuth, TokenAuthenticationError, TokenEndpoint
from iqe_library.auth import _oauth as oauth_module
from iqe_library.http import create_session


def token_response(**updates):
    return {"access_token": "access-sentinel", "token_type": "Bearer", "expires_in": 120} | updates


def response(body, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body).encode()
    return result


def form(request):
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    return parse_qs(request.body, keep_blank_values=True)


def assert_sanitized(error, caplog, *sensitive):
    rendered = "".join(traceback.format_exception(error)) + caplog.text + repr(error)
    assert all(value not in rendered for value in sensitive)
    assert error.__cause__ is None
    assert getattr(error, "request", None) is None
    assert getattr(error, "response", None) is None


@pytest.fixture
def exchange(monkeypatch):
    transport = SimpleNamespace(calls=[], replies=[], closed=[])
    original_close = requests.Session.close

    def send(session, request, **kwargs):
        transport.calls.append((session, request, kwargs))
        reply = transport.replies.pop(0) if transport.replies else response(token_response())
        if isinstance(reply, Exception):
            raise reply
        reply.request = request
        reply.url = request.url
        return reply

    def close(session):
        transport.closed.append(session)
        original_close(session)

    monkeypatch.setattr(requests.Session, "send", send)
    monkeypatch.setattr(requests.Session, "close", close)
    return transport


def offline_auth(**kwargs):
    return auth_module.OIDCAuth.from_refresh_token(
        "offline-sentinel", TokenEndpoint(token_url="https://sso.invalid/token"), **kwargs
    )


@pytest.mark.parametrize(
    "grant,scope",
    [
        ("refresh_token", None),
        ("refresh_token", "openid"),
        ("client_credentials", ""),
        ("client_credentials", "openid offline_access"),
    ],
)
def test_grants_are_lazy_cached_and_not_logged(exchange, caplog, grant, scope):
    caplog.set_level(logging.INFO)
    if grant == "refresh_token":
        auth = offline_auth(scope=scope)
        expected = {"client_id": ["rhsm-api"], "refresh_token": ["offline-sentinel"]}
    else:
        auth = auth_module.OIDCAuth.from_client_credentials(
            "client-secret-sentinel",
            TokenEndpoint(token_url="https://sso.invalid/token", client_id="service-account"),
            scope=scope,
        )
        expected = {"client_id": ["service-account"], "client_secret": ["client-secret-sentinel"]}
    expected["grant_type"] = [grant]
    if scope:
        expected["scope"] = [scope]
    assert isinstance(auth, AuthBase)
    assert not exchange.calls
    assert auth.get_token() == "access-sentinel"
    for request in (
        SimpleNamespace(headers={"Accept": "text/plain", "Authorization": "replace-me"}),
        requests.Request("GET", "https://api.invalid").prepare(),
    ):
        assert auth(request) is request
        assert request.headers["Authorization"] == "Bearer access-sentinel"
        assert "offline-sentinel" not in repr(request.headers)
    assert auth.get_token() == "access-sentinel"
    session, token_request, _ = exchange.calls[0]
    assert form(token_request) == expected
    assert session.hooks == {"response": []}
    assert len(exchange.calls) == 1
    assert "sentinel" not in caplog.text + repr(auth)


@pytest.mark.parametrize(
    "verify,trust_env", [(True, True), (False, False), ("/explicit/ca.pem", True)]
)
def test_exchange_transport_is_isolated_and_closed(
    exchange, monkeypatch, tmp_path, verify, trust_env
):
    netrc = tmp_path / "netrc"
    netrc.write_text("machine sso.invalid login ambient password ambient-secret\n")
    monkeypatch.setenv("NETRC", str(netrc))
    endpoint = TokenEndpoint(
        token_url="https://sso.invalid/token",
        verify=verify,
        proxies={"https": "http://endpoint-proxy.invalid"},
        timeout=7.5,
        trust_env=trust_env,
    )
    auth = auth_module.OIDCAuth.from_refresh_token("offline-sentinel", endpoint)
    with create_session(
        auth=auth,
        headers={"X-API": "private"},
        cookies={"api": "cookie"},
        verify=False,
        timeout=99,
        trust_env=False,
        proxies={"https": "http://api-proxy.invalid"},
    ) as api:
        api.cert = ("api-cert.pem", "api-key.pem")
        prepared = api.prepare_request(requests.Request("GET", "https://api.invalid"))
        token_session, request, settings = exchange.calls[0]
        assert type(token_session) is requests.Session
        assert token_session is not api
        assert token_session.trust_env is trust_env
        assert isinstance(token_session.get_adapter(request.url), _SystemTrustAdapter)
        assert isinstance(token_session.auth, NoAuth)
        assert token_session.hooks == {"response": []}
        assert token_session in exchange.closed
        assert request.url == "https://sso.invalid/token"
        assert request.method == "POST"
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert "X-API" not in request.headers
        assert settings["verify"] == verify
        assert settings["timeout"] == 7.5
        assert settings["proxies"] == {"https": "http://endpoint-proxy.invalid"}
        assert settings["cert"] is None
        assert settings["allow_redirects"] is False
        assert prepared.headers["Authorization"] == "Bearer access-sentinel"
        assert prepared.headers["Cookie"] == "api=cookie"


@pytest.mark.parametrize(
    "factory,credential",
    [
        ("from_refresh_token", None),
        ("from_client_credentials", 1),
        ("from_refresh_token", ""),
        ("from_client_credentials", " \t"),
    ],
)
def test_invalid_credential_inputs_fail_locally(exchange, factory, credential):
    with pytest.raises(ValueError, match="nonempty string"):
        getattr(auth_module.OIDCAuth, factory)(
            credential, TokenEndpoint(token_url="https://sso.invalid/token")
        )
    assert not exchange.calls


@pytest.mark.parametrize("factory", ["from_refresh_token", "from_client_credentials"])
@pytest.mark.parametrize("scope", [1])
def test_invalid_scope_fails_locally(exchange, factory, scope):
    with pytest.raises(ValueError, match="scope"):
        getattr(auth_module.OIDCAuth, factory)(
            "credential-sentinel", TokenEndpoint(token_url="https://sso.invalid/token"), scope=scope
        )
    assert not exchange.calls


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        token_response(access_token=None),
        token_response(access_token=""),
        token_response(token_type=None),
        token_response(token_type="Basic"),
        *[
            token_response(expires_in=value)
            for value in (
                None,
                True,
                "120",
                0,
                float("nan"),
                float("inf"),
                10**1000,
            )
        ],
        *[token_response(refresh_token=value) for value in (1, " \t")],
    ],
)
def test_invalid_token_response_is_rejected(exchange, body):
    exchange.replies.append(response(body))
    with pytest.raises(TokenAuthenticationError):
        offline_auth().get_token()
    assert len(exchange.calls) == 1
    assert exchange.closed == [exchange.calls[0][0]]


# Exercise each unsafe character once, covering both request interfaces and cache states
# without repeating the same validator for their full Cartesian product.
@pytest.mark.parametrize(
    "unsafe,prepared,renewal",
    [
        ("\r", False, False),
        ("\n", True, True),
        ("\r\n", True, False),
        ("\x00", False, True),
        ("\t", False, False),
        ("\x7f", True, True),
        ("\u0100", True, False),
        ("\ud800", False, True),
    ],
    ids=["cr", "lf", "crlf", "nul", "tab", "del", "unicode", "surrogate"],
)
def test_unsafe_bearer_is_sanitized_before_cache_or_rotation(
    exchange, clock, caplog, prepared, renewal, unsafe
):
    caplog.set_level(logging.DEBUG)
    auth = offline_auth()
    if renewal:
        exchange.replies.append(response(token_response(refresh_token="committed-refresh")))
        assert auth.get_token() == "access-sentinel"
        clock.now = 90
    exchange.replies.extend(
        [
            response(
                token_response(
                    access_token=f"unsafe-access-sentinel{unsafe}",
                    refresh_token="uncommitted-refresh",
                )
            ),
            response(token_response(access_token="retry-valid")),
        ]
    )
    request = (
        requests.Request(
            "GET", "https://api.invalid", headers={"Authorization": "unchanged-on-failure"}
        ).prepare()
        if prepared
        else SimpleNamespace(headers={"Authorization": "unchanged-on-failure"})
    )
    with pytest.raises(TokenAuthenticationError, match="invalid access token") as error:
        auth(request)
    assert request.headers["Authorization"] == "unchanged-on-failure"
    assert_sanitized(
        error.value,
        caplog,
        "unsafe-access-sentinel",
        "offline-sentinel",
        "committed-refresh",
        "uncommitted-refresh",
    )
    assert auth.get_token() == "retry-valid"
    credential = "committed-refresh" if renewal else "offline-sentinel"
    assert [form(call[1])["refresh_token"] for call in exchange.calls[-2:]] == [
        [credential],
        [credential],
    ]


@pytest.mark.parametrize("token", ["opaque+/~._-==", "not.a.jwt!#$%&'()*,:;<>?@[]^`{|}"])
def test_header_safe_bearer_remains_opaque(exchange, token):
    exchange.replies.append(response(token_response(access_token=token)))
    auth = offline_auth()
    prepared = requests.Request("GET", "https://api.invalid", auth=auth).prepare()
    assert prepared.headers["Authorization"] == f"Bearer {token}"
    assert auth.get_token() == token
    assert len(exchange.calls) == 1


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(oauth_module, "monotonic", lambda: clock.now, raising=False)
    return clock


def test_rotation_and_omitted_refresh_token(exchange, clock):
    exchange.replies.extend(
        [
            response(token_response(access_token="access-first", refresh_token="refresh-first")),
            response(token_response(access_token="access-second")),
            response(token_response(access_token="access-third", refresh_token="refresh-third")),
            response(token_response(access_token="access-fourth")),
        ]
    )
    auth = offline_auth()
    for now, expected in [
        (0, "access-first"),
        (90, "access-second"),
        (180, "access-third"),
        (270, "access-fourth"),
    ]:
        clock.now = now
        assert auth.get_token() == expected
    assert [form(call[1])["refresh_token"] for call in exchange.calls] == [
        ["offline-sentinel"],
        ["refresh-first"],
        ["refresh-first"],
        ["refresh-third"],
    ]
    assert len({id(call[0]) for call in exchange.calls}) == 4
    assert exchange.closed == [call[0] for call in exchange.calls]


@pytest.mark.parametrize("lifetime,before,renew", [(120, 89.999, 90), (10, 4.999, 5)])
def test_monotonic_expiry_and_short_lifetime_margin(
    exchange, clock, monkeypatch, lifetime, before, renew
):
    exchange.replies.extend(
        [
            response(token_response(access_token="first", expires_in=lifetime)),
            response(token_response(access_token="renewed", expires_in=lifetime)),
        ]
    )
    wall = SimpleNamespace(now=1_000_000)
    monkeypatch.setattr(time, "time", lambda: wall.now)
    auth = offline_auth()
    assert auth.get_token() == "first"
    wall.now = -1_000_000
    clock.now = before
    assert auth.get_token() == "first"
    wall.now = 9_000_000
    assert auth.get_token() == "first"
    assert len(exchange.calls) == 1
    clock.now = renew
    assert auth.get_token() == "renewed"
    assert len(exchange.calls) == 2


def test_slow_exchange_uses_start_time_for_expiry(monkeypatch, clock):
    calls = []

    def send(session, request, **kwargs):
        calls.append(request)
        clock.now += 40
        return response(token_response(access_token=f"access-{len(calls)}"))

    monkeypatch.setattr(requests.Session, "send", send)
    auth = offline_auth()
    assert auth.get_token() == "access-1"
    clock.now = 89
    assert auth.get_token() == "access-1"
    clock.now = 90
    assert auth.get_token() == "access-2"
    assert len(calls) == 2


@pytest.mark.parametrize("elapsed", [120])
def test_slow_exchange_cannot_publish_expired_token(monkeypatch, clock, elapsed):
    calls = []

    def send(session, request, **kwargs):
        calls.append(request)
        if len(calls) == 1:
            clock.now += elapsed
            return response(token_response(access_token="expired", refresh_token="uncommitted"))
        return response(token_response(access_token="valid"))

    monkeypatch.setattr(requests.Session, "send", send)
    auth = offline_auth()
    with pytest.raises(TokenAuthenticationError, match="expired"):
        auth.get_token()
    assert auth.get_token() == "valid"
    assert [form(request)["refresh_token"] for request in calls] == [
        ["offline-sentinel"],
        ["offline-sentinel"],
    ]


@pytest.mark.parametrize(
    "invalid",
    [
        {"refresh_token": "", "expires_in": 999},
        {"refresh_token": "uncommitted-refresh", "expires_in": 0},
        {"refresh_token": "uncommitted-refresh", "token_type": "Basic"},
    ],
)
def test_invalid_rotated_token_does_not_partially_update_cache(exchange, clock, invalid):
    exchange.replies.extend(
        [
            response(token_response(access_token="first", refresh_token="committed-refresh")),
            response(token_response(access_token="uncommitted-access", **invalid)),
            response(token_response(access_token="retry-valid")),
        ]
    )
    auth = offline_auth()
    assert auth.get_token() == "first"
    clock.now = 90
    request = SimpleNamespace(headers={"Authorization": "unchanged-on-failure"})
    with pytest.raises(TokenAuthenticationError):
        auth(request)
    assert request.headers == {"Authorization": "unchanged-on-failure"}
    assert auth.get_token() == "retry-valid"
    assert len(exchange.calls) == 3
    assert [form(call[1])["refresh_token"] for call in exchange.calls] == [
        ["offline-sentinel"],
        ["committed-refresh"],
        ["committed-refresh"],
    ]


@pytest.mark.parametrize(
    "factory,failure",
    [
        ("from_refresh_token", "network"),
        ("from_client_credentials", "oserror"),
        ("from_refresh_token", "http"),
        ("from_client_credentials", "redirect"),
        ("from_refresh_token", "json"),
        ("from_client_credentials", "payload"),
    ],
)
def test_failed_renewal_raises_without_stale_fallback(exchange, clock, caplog, factory, failure):
    caplog.set_level(logging.DEBUG)
    exchange.replies.append(response(token_response(refresh_token="committed-refresh")))
    auth = getattr(auth_module.OIDCAuth, factory)(
        "credential-sentinel", TokenEndpoint(token_url="https://sso.invalid/token")
    )
    assert auth.get_token() == "access-sentinel"
    if failure == "network":
        sensitive = response({"error": "upstream-body-sentinel"}, 400)
        bad_reply = requests.ConnectionError(
            "upstream-message-sentinel credential-sentinel access-sentinel",
            request=exchange.calls[0][1],
            response=sensitive,
        )
    elif failure == "oserror":
        bad_reply = OSError("upstream-message-sentinel credential-sentinel")
    elif failure in {"http", "redirect"}:
        bad_reply = response(
            token_response(error="upstream-body-sentinel"), 400 if failure == "http" else 302
        )
        bad_reply.headers["Location"] = "https://redirect.invalid/credential-sentinel"
    elif failure == "json":
        bad_reply = response({})
        bad_reply._content = b"upstream-body-sentinel credential-sentinel access-sentinel"
    else:
        bad_reply = response(token_response(token_type="upstream-body-sentinel"))
    exchange.replies.append(bad_reply)
    clock.now = 90
    with pytest.raises(TokenAuthenticationError) as error:
        auth.get_token()
    assert_sanitized(
        error.value,
        caplog,
        "upstream-body-sentinel",
        "upstream-message-sentinel",
        "credential-sentinel",
        "access-sentinel",
        "committed-refresh",
    )
    if failure in {"http", "redirect"}:
        assert str(bad_reply.status_code) in str(error.value)
    assert len(exchange.calls) == 2
    assert exchange.closed == [call[0] for call in exchange.calls]
    exchange.replies.append(response(token_response(access_token="retry-valid")))
    assert auth.get_token() == "retry-valid"
    data = form(exchange.calls[-1][1])
    if factory == "from_refresh_token":
        assert data["refresh_token"] == ["committed-refresh"]
    else:
        assert data["client_secret"] == ["credential-sentinel"]
        assert data["grant_type"] == ["client_credentials"]
        assert "refresh_token" not in data


@pytest.mark.parametrize(
    "factory,location",
    [
        ("from_refresh_token", "https://redirect.invalid/credential-sentinel"),
        ("from_client_credentials", "https://[credential-sentinel/path"),
        ("from_refresh_token", "https://sso.invalid:credential-sentinel/path"),
    ],
)
def test_redirect_metadata_failures_are_sanitized_without_following(
    http_transport, clock, caplog, factory, location
):
    caplog.set_level(logging.DEBUG)
    redirected = response(
        token_response(
            access_token="uncommitted-access",
            refresh_token="uncommitted-refresh",
            expires_in=999,
            error="upstream-body-sentinel",
        ),
        302,
    )
    redirected.headers["Location"] = location
    http_transport.replies = [
        response(token_response(refresh_token="committed-refresh")),
        redirected,
        response(token_response(access_token="retry-valid")),
    ]

    # Preserve Session.send, including its preparation of Response.next even
    # with allow_redirects=False. Only replace the external network boundary.
    auth = getattr(auth_module.OIDCAuth, factory)(
        "credential-sentinel", TokenEndpoint(token_url="https://sso.invalid/token")
    )
    assert auth.get_token() == "access-sentinel"
    clock.now = 90
    request = SimpleNamespace(headers={"Authorization": "unchanged-on-failure"})
    with pytest.raises(TokenAuthenticationError) as error:
        auth(request)
    assert request.headers == {"Authorization": "unchanged-on-failure"}
    assert_sanitized(
        error.value,
        caplog,
        location,
        "credential-sentinel",
        "access-sentinel",
        "committed-refresh",
        "uncommitted-access",
        "uncommitted-refresh",
        "upstream-body-sentinel",
        "Invalid IPv6 URL",
        "Port could not be cast",
    )
    # No follow or retry occurred; a later explicit call still exchanges using
    # committed credentials rather than publishing any fields from the 302.
    assert len(http_transport.calls) == 2
    assert auth.get_token() == "retry-valid"
    calls = [request for request, _ in http_transport.calls]
    assert len(calls) == 3
    assert [call.url for call in calls] == ["https://sso.invalid/token"] * 3
    assert all(call.method == "POST" and "Authorization" not in call.headers for call in calls)
    if factory == "from_refresh_token":
        assert [form(call)["refresh_token"] for call in calls] == [
            ["credential-sentinel"],
            ["committed-refresh"],
            ["committed-refresh"],
        ]
    else:
        assert all(
            form(call)
            == {
                "grant_type": ["client_credentials"],
                "client_id": ["rhsm-api"],
                "client_secret": ["credential-sentinel"],
            }
            for call in calls
        )


@pytest.mark.parametrize("renewal", [False, True])
def test_concurrent_get_token_has_one_exchange(monkeypatch, clock, renewal):
    auth = offline_auth()
    if renewal:
        monkeypatch.setattr(
            requests.Session, "send", lambda *args, **kwargs: response(token_response())
        )
        assert auth.get_token() == "access-sentinel"
        clock.now = 90
    count = 6
    start = Barrier(count + 1)
    attempted = [Event() for _ in range(count)]
    entered, release = Event(), Event()
    calls = []
    calls_lock = Lock()

    def send(session, request, **kwargs):
        with calls_lock:
            calls.append(request)
        entered.set()
        assert release.wait(5), "test did not release blocked exchange"
        return response(token_response(access_token="concurrent-access"))

    def acquire(index):
        start.wait(timeout=5)
        attempted[index].set()
        return auth.get_token()

    monkeypatch.setattr(requests.Session, "send", send)
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(acquire, index) for index in range(count)]
        try:
            start.wait(timeout=5)
            assert all(event.wait(5) for event in attempted)
            assert entered.wait(5)
            assert not any(future.done() for future in futures)
        finally:
            release.set()
        assert [future.result(timeout=5) for future in futures] == ["concurrent-access"] * count
    assert len(calls) == 1


def test_auth_instances_are_independent(exchange, clock):
    exchange.replies.extend(
        [
            response(token_response(access_token="first", refresh_token="first-rotation")),
            response(token_response(access_token="second", refresh_token="second-rotation")),
            response(token_response(access_token="first-renewed")),
            response(token_response(access_token="second-renewed")),
        ]
    )
    first, second = offline_auth(), offline_auth()
    assert first.get_token() == "first"
    assert second.get_token() == "second"
    clock.now = 90
    assert first.get_token() == "first-renewed"
    assert second.get_token() == "second-renewed"
    assert [form(call[1])["refresh_token"] for call in exchange.calls] == [
        ["offline-sentinel"],
        ["offline-sentinel"],
        ["first-rotation"],
        ["second-rotation"],
    ]
    assert "offline-sentinel" not in repr(first)
    assert "first-renewed" not in repr(first)


def test_auth_instances_do_not_share_a_lock(monkeypatch):
    endpoint = TokenEndpoint(token_url="https://sso.invalid/token")
    first = auth_module.OIDCAuth.from_refresh_token("first-offline", endpoint)
    second = auth_module.OIDCAuth.from_refresh_token("second-offline", endpoint)
    entered, release = Event(), Event()

    def send(session, request, **kwargs):
        credential = form(request)["refresh_token"][0]
        if credential == "first-offline":
            entered.set()
            assert release.wait(5)
        return response(token_response(access_token=credential.replace("offline", "access")))

    monkeypatch.setattr(requests.Session, "send", send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(first.get_token)
        try:
            assert entered.wait(5)
            assert pool.submit(second.get_token).result(timeout=5) == "second-access"
            assert not first_future.done()
        finally:
            release.set()
        assert first_future.result(timeout=5) == "first-access"


def test_api_401_is_not_replayed_and_token_traffic_is_not_logged(http_transport, caplog):
    denied = response({"detail": "expired"}, 401)
    caplog.set_level(logging.INFO)
    http_transport.replies = [response(token_response()), denied]
    token_url = "https://sso.invalid/token?token-query-secret"
    auth = auth_module.OIDCAuth.from_refresh_token(
        "offline-sentinel", TokenEndpoint(token_url=token_url)
    )
    with create_session(auth=auth) as api:
        observed = api.get("https://api.invalid/items")
    assert observed is denied
    assert observed.status_code == 401
    assert observed.content == b'{"detail": "expired"}'
    calls = [request for request, _ in http_transport.calls]
    assert [request.url for request in calls] == [
        token_url,
        "https://api.invalid/items",
    ]
    assert calls[1].headers["Authorization"] == "Bearer access-sentinel"
    assert "https://api.invalid/items" in caplog.text
    assert len(caplog.records) == 1
    assert "sso.invalid" not in caplog.text
    assert "token-query-secret" not in caplog.text
    assert "offline-sentinel" not in caplog.text
    assert "access-sentinel" not in caplog.text
