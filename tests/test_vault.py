"""Offline contracts for standalone, lazy KV v2 secret fetching."""

import dataclasses
import traceback
from unittest.mock import Mock, call

import hvac
import pytest
import requests

from iqe_library.vault import (
    VaultAuthenticationError,
    VaultOptions,
    VaultReadError,
    VaultSecretFetcher,
    _client,
)


@pytest.fixture
def client():
    client = Mock()
    client.is_authenticated.return_value = True
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "username": "demo",
                "password": "secret-sentinel",
                "enabled": True,
                "count": 3,
            }
        }
    }
    return client


@pytest.fixture
def options():
    return VaultOptions(url="https://vault.invalid")


@pytest.fixture
def create_client(client, monkeypatch):
    factory = Mock(return_value=client)
    monkeypatch.setattr(_client, "_create_client", factory)
    return factory


@pytest.fixture
def authenticate(monkeypatch):
    login = Mock()
    monkeypatch.setattr(_client, "authenticate", login)
    return login


def test_lazy_client_and_path_cache(client, options, create_client, authenticate):
    fetcher = VaultSecretFetcher(options)
    create_client.assert_not_called()
    authenticate.assert_not_called()
    client.is_authenticated.assert_not_called()
    assert fetcher.get_value_from_vault("users/demo", "username") == "demo"
    create_client.assert_called_once_with(options)
    authenticate.assert_called_once_with(client, options)

    # All remaining accesses hit the cache, even after credentials expire.
    client.is_authenticated.reset_mock()
    client.is_authenticated.return_value = False
    assert fetcher.get_value_from_vault("users/demo", "password") == "secret-sentinel"
    assert fetcher.get("users/demo")["enabled"] is True
    assert fetcher.get("users/demo")["count"] == 3
    client.is_authenticated.assert_not_called()
    authenticate.assert_called_once_with(client, options)
    client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="users/demo", mount_point="insights", raise_on_deleted_version=True
    )


def test_distinct_paths_reuse_client(client, options, create_client, authenticate):
    fetcher = VaultSecretFetcher(dataclasses.replace(options, mount_point="custom"))
    assert fetcher.get("users/demo")["username"] == "demo"
    assert fetcher.get("users/other")["username"] == "demo"
    assert create_client.call_count == 1
    assert authenticate.call_count == 1
    assert client.is_authenticated.call_count == 2
    assert client.secrets.kv.v2.read_secret_version.call_args_list == [
        call(path="users/demo", mount_point="custom", raise_on_deleted_version=True),
        call(path="users/other", mount_point="custom", raise_on_deleted_version=True),
    ]
    client.adapter.close.assert_not_called()


def test_instances_are_independent(client, options, create_client, authenticate):
    other = Mock()
    other.is_authenticated.return_value = True
    other.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"username": "other"}}}
    create_client.side_effect = [client, other]
    first, second = VaultSecretFetcher(options), VaultSecretFetcher(options)
    assert first.get_value_from_vault("users/demo", "username") == "demo"
    assert second.get_value_from_vault("users/demo", "username") == "other"
    assert first.get_value_from_vault("users/demo", "username") == "demo"
    assert client.secrets.kv.v2.read_secret_version.call_count == 1
    assert other.secrets.kv.v2.read_secret_version.call_count == 1
    assert authenticate.call_args_list == [call(client, options), call(other, options)]


def test_read_failure_not_cached(client, options, create_client, authenticate):
    read = client.secrets.kv.v2.read_secret_version
    read.side_effect = [requests.Timeout("secret-sentinel"), read.return_value]
    fetcher = VaultSecretFetcher(options)
    with pytest.raises(VaultReadError):
        fetcher.get("users/demo")
    assert fetcher.get_value_from_vault("users/demo", "username") == "demo"
    assert read.call_count == 2


def test_empty_secret_is_cached(client, options, create_client, authenticate):
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}
    fetcher = VaultSecretFetcher(options)
    assert fetcher.get("users/demo") == {}
    assert fetcher.get("users/demo") == {}
    assert client.secrets.kv.v2.read_secret_version.call_count == 1


def test_missing_key(client, options, create_client, authenticate, caplog):
    fetcher = VaultSecretFetcher(options)
    with pytest.raises(LookupError) as error:
        fetcher.get_value_from_vault("users/demo", "absent")
    assert "absent" in str(error.value)
    assert "users/demo" in str(error.value)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text
    assert fetcher.get_value_from_vault("users/demo", "username") == "demo"
    assert client.secrets.kv.v2.read_secret_version.call_count == 1


@pytest.mark.parametrize(
    "response",
    [
        hvac.exceptions.Forbidden("secret-sentinel"),
        hvac.exceptions.InvalidPath("secret-sentinel"),
        requests.ConnectionError("secret-sentinel"),
        None,
        "secret-sentinel",
        {"unexpected": "secret-sentinel"},
        {"data": None},
        {"data": {"unexpected": "secret-sentinel"}},
        {"data": {"data": None}},
        {"data": {"data": ["secret-sentinel"]}},
    ],
)
def test_read_error_context(client, options, create_client, authenticate, response, caplog):
    read = client.secrets.kv.v2.read_secret_version
    if isinstance(response, Exception):
        read.side_effect = response
    else:
        read.return_value = response
    fetcher = VaultSecretFetcher(options)
    with pytest.raises(VaultReadError) as error:
        fetcher.get("users/demo")
    assert "users/demo" in str(error.value)
    assert "insights" in str(error.value)
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text
    assert read.call_count == 1
    assert authenticate.call_count == 1


@pytest.mark.parametrize("recovered", [True, False])
def test_expired_auth_retries_once(client, options, create_client, authenticate, recovered):
    fetcher = VaultSecretFetcher(options)
    assert fetcher.get("users/demo")["username"] == "demo"
    client.is_authenticated.side_effect = [False, recovered]
    if recovered:
        assert fetcher.get("users/other")["username"] == "demo"
    else:
        with pytest.raises(VaultAuthenticationError):
            fetcher.get("users/other")
    assert authenticate.call_args_list == [call(client, options), call(client, options)]
    assert client.is_authenticated.call_count == 3
    assert client.secrets.kv.v2.read_secret_version.call_count == (2 if recovered else 1)


def test_auth_check_error_is_sanitized(client, options, create_client, authenticate, caplog):
    client.is_authenticated.side_effect = requests.ConnectionError("secret-sentinel")
    with pytest.raises(VaultAuthenticationError) as error:
        VaultSecretFetcher(options).get("users/demo")
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text
    client.secrets.kv.v2.read_secret_version.assert_not_called()
    assert authenticate.call_count == 1


@pytest.mark.parametrize("failure", [VaultAuthenticationError("rejected"), ImportError("kerberos")])
def test_failed_initial_auth_releases_client_and_can_retry(
    client, options, create_client, authenticate, failure
):
    authenticate.side_effect = [failure, None]
    fetcher = VaultSecretFetcher(options)
    with pytest.raises(type(failure)) as error:
        fetcher.get("users/demo")
    assert error.value is failure
    client.adapter.close.assert_called_once_with()
    client.secrets.kv.v2.read_secret_version.assert_not_called()
    assert fetcher.get_value_from_vault("users/demo", "username") == "demo"
    assert create_client.call_count == 2
    assert authenticate.call_count == 2


@pytest.mark.parametrize(
    "verify,token", [(True, None), (False, ""), ("/custom/ca.pem", "selected-token")]
)
def test_client_options_are_explicit(options, monkeypatch, verify, token):
    monkeypatch.setenv("VAULT_TOKEN", "ambient-token")
    monkeypatch.setenv("VAULT_ADDR", "https://other.invalid")
    options = dataclasses.replace(options, verify=verify, timeout=7, token=token)
    session = _client.create_session(verify)
    factory = Mock(return_value=session)
    monkeypatch.setattr(_client, "create_session", factory)
    try:
        client = _client._create_client(options)
        assert isinstance(client, hvac.Client)
        assert client.url == "https://vault.invalid"
        assert client.token == (token if token is not None else "")
        assert client.adapter.session is session
        assert session.verify == verify
        assert client.adapter._kwargs["verify"] == verify
        assert client.adapter._kwargs["timeout"] == 7
        factory.assert_called_once_with(verify, timeout=7)
    finally:
        session.close()


def test_client_setup_failure_closes_session(options, monkeypatch, caplog):
    session = Mock(spec=requests.Session)
    monkeypatch.setattr(_client, "create_session", Mock(return_value=session))
    monkeypatch.setattr(_client.hvac, "Client", Mock(side_effect=RuntimeError("secret-sentinel")))
    with pytest.raises(VaultAuthenticationError) as error:
        _client._create_client(options)
    session.close.assert_called_once_with()
    assert "secret-sentinel" not in "".join(traceback.format_exception(error.value))
    assert "secret-sentinel" not in caplog.text
