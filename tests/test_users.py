import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakPostError

from iqe_library.users import UserProvider, UserProvisioningError, _provider, create_user_provider


@pytest.fixture
def spec():
    return {
        "username": "demo",
        "password": "private-password",
        "attributes": {
            "type": "User",
            "account_number": "012345",
            "org_id": "12345",
            "user_id": "123451",
            "email": "demo@example.com",
            "first_name": "Demo",
            "last_name": "User",
            "is_active": True,
            "is_org_admin": True,
            "is_internal": False,
            "locale": "en_US",
        },
        "entitlements": {"insights": {"is_entitled": True}, "settings": {"is_entitled": False}},
    }


@pytest.fixture
def admin():
    client = Mock(spec=KeycloakAdmin)
    client.get_users.return_value = []
    client.create_user.return_value = "keycloak-uuid"
    return client


def test_create_payload_and_inputs_are_preserved(admin, spec, caplog):
    before = deepcopy(spec)
    provider = UserProvider(admin)
    assert admin.mock_calls == []
    with caplog.at_level("INFO"):
        assert provider.ensure_user(**spec) == "keycloak-uuid"
    admin.get_users.assert_called_once_with({"username": "demo", "exact": True})
    payload = admin.create_user.call_args.args[0]
    assert "id" not in payload
    assert "credentials" not in payload
    assert payload["email"] == "demo@example.com"
    assert payload["enabled"] is True
    assert payload["attributes"]["user_id"] == ["123451"]
    assert payload["attributes"]["account_id"] == ["123451"]
    assert payload["attributes"]["is_org_admin"] == ["true"]
    assert payload["attributes"]["is_internal"] == ["false"]
    assert payload["attributes"]["entitlements"] == payload["attributes"]["newEntitlements"]
    decoded = json.loads("{" + ",".join(payload["attributes"]["newEntitlements"]) + "}")
    assert decoded == {
        "insights": {"is_entitled": True, "is_trial": False},
        "settings": {"is_entitled": False, "is_trial": False},
    }
    admin.set_user_password.assert_called_once_with(
        "keycloak-uuid", "private-password", temporary=False
    )
    admin.delete_user.assert_not_called()
    assert "private-password" not in caplog.text
    assert spec == before


def test_reuse_keeps_keycloak_id_and_unrelated_attributes(admin, spec):
    admin.get_users.return_value = [
        {
            "id": "existing-uuid",
            "username": "demo",
            "attributes": {"user_id": ["123451"], "custom": ["preserved"]},
        }
    ]
    assert UserProvider(admin).ensure_user(**spec) == "existing-uuid"
    admin.create_user.assert_not_called()
    admin.delete_user.assert_not_called()
    user_id, payload = admin.update_user.call_args.args
    assert user_id == "existing-uuid"
    assert payload["attributes"]["custom"] == ["preserved"]
    admin.set_user_password.assert_called_once_with(
        "existing-uuid", "private-password", temporary=False
    )


def test_recreate_deletes_exact_match_and_allows_explicit_new_user_id(admin, spec):
    admin.get_users.return_value = [
        {"id": "old-uuid", "username": "demo", "attributes": {"user_id": ["old-id"]}}
    ]
    assert UserProvider(admin).ensure_user(**spec, recreate=True) == "keycloak-uuid"
    admin.delete_user.assert_called_once_with("old-uuid")
    admin.create_user.assert_called_once()
    admin.update_user.assert_not_called()
    operations = [call[0] for call in admin.mock_calls]
    assert operations == ["get_users", "delete_user", "create_user", "set_user_password"]


@pytest.mark.parametrize("recreate", [False, True])
def test_never_modifies_substring_match(admin, spec, recreate):
    admin.get_users.return_value = [{"id": "other", "username": "demo-extra"}]
    assert UserProvider(admin).ensure_user(**spec, recreate=recreate) == "keycloak-uuid"
    admin.delete_user.assert_not_called()
    admin.update_user.assert_not_called()


def test_conflicting_insights_id_fails_before_mutation(admin, spec):
    admin.get_users.return_value = [
        {"id": "old-uuid", "username": "demo", "attributes": {"user_id": ["different"]}}
    ]
    with pytest.raises(ValueError, match="different Insights user_id"):
        UserProvider(admin).ensure_user(**spec)
    admin.create_user.assert_not_called()
    admin.delete_user.assert_not_called()
    admin.update_user.assert_not_called()
    admin.set_user_password.assert_not_called()


@pytest.mark.parametrize(
    "field,value", [("type", "System"), ("user_id", None), ("is_org_admin", "true"), ("locale", "")]
)
def test_invalid_attributes_fail_before_discovery_or_deletion(admin, spec, field, value):
    spec["attributes"][field] = value
    with pytest.raises(ValueError):
        UserProvider(admin).ensure_user(**spec, recreate=True)
    assert admin.mock_calls == []


def test_errors_omit_upstream_body_and_password(admin, spec):
    admin.create_user.side_effect = KeycloakPostError(
        "private-password upstream error", response_body=b"private-password"
    )
    with pytest.raises(UserProvisioningError) as error:
        UserProvider(admin).ensure_user(**spec)
    assert "demo" in str(error.value)
    assert "private-password" not in str(error.value)
    assert error.value.__cause__ is None


def test_injected_client_remains_owned_by_caller(admin):
    with UserProvider(admin) as provider:
        pass
    provider.close()
    assert admin.mock_calls == []


def test_factory_options_lazy_transport_and_cleanup(monkeypatch):
    admin = Mock()
    constructor = Mock(return_value=admin)
    monkeypatch.setattr(_provider, "KeycloakAdmin", constructor)
    with create_user_provider(
        server_url="https://sso.example/auth",
        username="admin",
        password="private-password",
        verify="/ca.pem",
        timeout=7,
    ) as provider:
        assert provider.keycloak_admin is admin
        assert admin.mock_calls == []
    constructor.assert_called_once_with(
        server_url="https://sso.example/auth/",
        username="admin",
        password="private-password",
        realm_name="redhat-external",
        user_realm_name="master",
        verify="/ca.pem",
        timeout=7,
        max_retries=0,
    )
    admin.connection._s.close.assert_called_once()
    admin.connection._keycloak_openid.connection._s.close.assert_called_once()
    provider.close()
    admin.connection._s.close.assert_called_once()


def test_close_does_not_create_token_transport(monkeypatch):
    admin = Mock()
    admin.connection._keycloak_openid = None
    monkeypatch.setattr(_provider, "KeycloakAdmin", Mock(return_value=admin))
    with create_user_provider(
        server_url="https://sso.example", username="admin", password="private-password"
    ):
        pass
    admin.connection._s.close.assert_called_once()


def test_closed_provider_cannot_be_reused(admin, spec):
    provider = UserProvider(admin)
    provider.close()
    with pytest.raises(RuntimeError, match="closed"):
        provider.ensure_user(**spec)
    assert admin.mock_calls == []
