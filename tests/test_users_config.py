from copy import deepcopy
from unittest.mock import Mock

import pytest

from iqe_library.config import load_config
from iqe_library.ephemeral import _discovery
from iqe_library.users import (
    UserProvider,
    _config,
    create_user_provider_from_config,
    provision_users_from_config,
)


@pytest.fixture
def config():
    first = {
        "auth": {"basic": {"username": "one", "password": "private-password"}},
        "attributes": {
            "account_number": "012345",
            "org_id": "12345",
            "user_id": "123451",
            "email": "one@example.com",
            "first_name": "One",
            "last_name": "User",
            "is_org_admin": True,
        },
        "entitlements": {"insights": {"is_entitled": True}},
    }
    second = deepcopy(first)
    second["auth"]["basic"]["username"] = "two"
    second["attributes"]["user_id"] = "123452"
    second["attributes"]["is_org_admin"] = False
    return {"users": {"first": first, "second": second}}


@pytest.fixture
def provider():
    provider = Mock(spec=UserProvider)
    provider.ensure_user.side_effect = lambda **spec: f"uuid-{spec['username']}"
    return provider


def test_multiple_users_plain_mapping_and_default_reuse(config, provider):
    before = deepcopy(config)
    assert provision_users_from_config(config, provider=provider) == {
        "first": "uuid-one",
        "second": "uuid-two",
    }
    assert provider.ensure_user.call_count == 2
    assert all(call.kwargs["recreate"] is False for call in provider.ensure_user.call_args_list)
    provider.close.assert_not_called()
    assert config == before


def test_explicit_selection_and_recreate(config, provider):
    assert provision_users_from_config(
        config, provider=provider, users=["second"], recreate=True
    ) == {"second": "uuid-two"}
    provider.ensure_user.assert_called_once()
    assert provider.ensure_user.call_args.kwargs["recreate"] is True


def test_flat_auth_is_not_supported(config, provider):
    user = config["users"]["first"]
    user["auth"] = {
        "username": "one",
        "password": "private-password",
        "user_id": user["attributes"].pop("user_id"),
    }
    with pytest.raises(ValueError, match=r"users.first.auth.basic must be a mapping"):
        provision_users_from_config(config, provider=provider, users=["first"])
    provider.ensure_user.assert_not_called()


def test_user_id_is_required_in_attributes(config, provider):
    user = config["users"]["first"]
    user["auth"]["user_id"] = user["attributes"].pop("user_id")
    with pytest.raises(ValueError, match=r"attributes.user_id"):
        provision_users_from_config(config, provider=provider)
    provider.ensure_user.assert_not_called()


def test_invalid_second_user_causes_no_mutations(config, provider):
    config["users"]["second"]["auth"]["basic"]["password"] = None
    with pytest.raises(ValueError, match="password"):
        provision_users_from_config(config, provider=provider, recreate=True)
    provider.ensure_user.assert_not_called()


def test_empty_selection_does_not_create_admin_client(monkeypatch):
    factory = Mock(side_effect=AssertionError("should not construct"))
    monkeypatch.setattr(_config, "create_user_provider_from_config", factory)
    assert provision_users_from_config({}) == {}
    factory.assert_not_called()


def test_loaded_config_keeps_other_auth_blocks_lazy(config, provider, config_file, monkeypatch):
    import yaml

    from iqe_library.vault import VaultSecretFetcher

    user = config["users"]["first"]
    user["auth"]["jwt"] = {"refresh_token": "VAULT_PLACEHOLDER"}
    user["auth"]["cert"] = {"cert": "@jinja {{ missing_secret }}"}
    text = yaml.safe_dump({"ephemeral": {"users": {"first": user}}})
    path = config_file(text.replace("VAULT_PLACEHOLDER", "!from_vault {path: never-read}"))
    settings = load_config(path, environment="ephemeral")
    command = Mock(side_effect=AssertionError("must not discover with an injected provider"))
    vault = Mock(side_effect=AssertionError("must not fetch unselected credentials"))
    monkeypatch.setattr(_discovery, "_oc", command)
    monkeypatch.setattr(VaultSecretFetcher, "get", vault)
    assert provision_users_from_config(settings, provider=provider) == {"first": "uuid-one"}
    command.assert_not_called()
    vault.assert_not_called()


def test_config_factory_uses_only_keycloak_options(monkeypatch):
    factory = Mock()
    monkeypatch.setattr(_config, "create_user_provider", factory)
    options = {
        "server_url": "https://sso.example/auth/",
        "username": "admin",
        "password": "private-password",
    }
    assert create_user_provider_from_config({"keycloak_admin": options}) is factory.return_value
    factory.assert_called_once_with(
        **options, realm_name="redhat-external", user_realm_name="master", verify=True, timeout=30
    )
