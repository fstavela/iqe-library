"""Offline contracts for independent header auth and token endpoint settings."""

import base64
import dataclasses
import json
from types import SimpleNamespace

import pytest
import requests
from requests.auth import AuthBase

from iqe_library.auth import IdentityAuth, NoAuth, TokenEndpoint


def test_identity_auth_snapshot_and_namespace():
    identity = {"type": "test-only", "user": {"name": "démo"}}
    entitlements = {"inventory": {"is_entitled": True}}
    auth = IdentityAuth(identity, entitlements)
    identity["user"]["name"] = "changed"
    entitlements["inventory"]["is_entitled"] = False

    request = SimpleNamespace(headers={"x-rh-identity": "replace-me", "Accept": "text/plain"})
    assert auth(request) is request
    assert json.loads(base64.b64decode(request.headers["x-rh-identity"])) == {
        "identity": {"type": "test-only", "user": {"name": "démo"}},
        "entitlements": {"inventory": {"is_entitled": True}},
    }
    assert request.headers["Accept"] == "text/plain"


@pytest.mark.parametrize("entitlements", [None, {}])
def test_identity_auth_accepts_partial_identity(entitlements):
    request = SimpleNamespace(headers={})
    IdentityAuth({"deliberately_invalid": 3}, entitlements)(request)
    assert json.loads(base64.b64decode(request.headers["x-rh-identity"])) == {
        "identity": {"deliberately_invalid": 3},
        "entitlements": {},
    }


def test_no_auth_preserves_explicit_headers():
    request = requests.Request(
        "GET", "https://api.invalid", headers={"Authorization": "Bearer explicit"}
    ).prepare()
    auth = NoAuth()
    assert isinstance(auth, AuthBase)
    assert auth(request) is request
    assert request.headers["Authorization"] == "Bearer explicit"


def test_token_endpoint_defaults_and_mapping_copy():
    proxies = {"https": "http://proxy.invalid:3128"}
    endpoint = TokenEndpoint(token_url="https://sso.invalid/token", proxies=proxies)
    proxies["https"] = "http://changed.invalid:3128"
    assert endpoint.client_id == "rhsm-api"
    assert endpoint.verify is True
    assert endpoint.timeout == 30
    assert endpoint.trust_env is True
    assert endpoint.proxies["https"] == "http://proxy.invalid:3128"
    assert TokenEndpoint(token_url="https://sso.invalid/token").proxies is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        endpoint.client_id = "changed"
    with pytest.raises(TypeError):
        TokenEndpoint("https://sso.invalid/token")


@pytest.mark.parametrize("verify", [False, "ca-bundle.pem"])
def test_token_endpoint_explicit_overrides(verify):
    endpoint = TokenEndpoint(
        token_url="http://localhost:8000/token?realm=test",
        client_id="service-account",
        verify=verify,
        timeout=1.5,
        trust_env=False,
        proxies={"http": "http://localhost:3128"},
    )
    assert endpoint.client_id == "service-account"
    assert endpoint.verify == verify
    assert endpoint.timeout == 1.5
    assert endpoint.trust_env is False
    assert endpoint.proxies == {"http": "http://localhost:3128"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_url", value)
        for value in (
            1,
            "",
            "sso.invalid/token",
            "ftp://sso.invalid/token",
            "https:///token",
            "https://user:credential-sentinel@sso.invalid/token",
            "https://sso.invalid/token#credential-sentinel",
            "https://sso.invalid:invalid/token",
            "https://sso.invalid:0/token",
            "https://[broken/token",
            "https://sso.invalid/ token",
            "https://sso.invalid/token\n",
        )
    ]
    + [("client_id", value) for value in (1, " \t")]
    + [("verify", value) for value in (1, " ")]
    + [
        ("proxies", value)
        for value in ("credential-sentinel", [], {1: "http://proxy.invalid"}, {"https": 1})
    ]
    + [("trust_env", 1)]
    + [("timeout", value) for value in (True, 0, float("nan"), float("inf"), "30")],
)
def test_token_endpoint_rejects_invalid_settings_without_credentials(field, value):
    settings = {"token_url": "https://sso.invalid/token", field: value}
    with pytest.raises(ValueError) as error:
        TokenEndpoint(**settings)
    assert field in str(error.value)
    assert "credential-sentinel" not in str(error.value)


@pytest.mark.parametrize("timeout", [10**1000, -(10**1000)], ids=["huge", "negative-huge"])
def test_token_endpoint_oversized_timeout_is_sanitized(timeout):
    with pytest.raises(ValueError, match="timeout must be a positive finite number") as error:
        TokenEndpoint(token_url="https://sso.invalid/token", timeout=timeout)
    assert str(timeout) not in str(error.value)
    assert error.value.__context__ is None
