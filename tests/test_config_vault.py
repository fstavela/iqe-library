"""Public loading with real Vault fetching and offline client/auth boundaries."""

from dataclasses import asdict
from unittest.mock import Mock, call

import pytest

from iqe_library.config import _loader, load_config
from iqe_library.vault import VaultOptions, _client


@pytest.fixture
def vault_boundary(monkeypatch):
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
    create_client = Mock(return_value=client)
    authenticate = Mock()
    monkeypatch.setattr(_client, "_create_client", create_client)
    monkeypatch.setattr(_client, "authenticate", authenticate)
    return client, create_client, authenticate


def test_lazy_access_and_whole_secret(config_file, vault_boundary):
    client, create_client, authenticate = vault_boundary
    path = config_file("""
default:
  username: !from_vault {path: users/demo, key: username}
  account: !from_vault {path: users/demo}
  sequence:
    - !from_vault {path: users/demo, key: count}
  unused:
    password: !from_vault {path: inaccessible, key: password}
""")
    settings = load_config(path)
    create_client.assert_not_called()
    authenticate.assert_not_called()
    assert settings.base_url == "https://console.stage.redhat.com"
    create_client.assert_not_called()
    assert settings.username == "demo"
    assert settings.account["enabled"] is True
    assert settings.sequence == [3]
    assert settings["username"] == settings.get("username") == "demo"
    client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="users/demo", mount_point="insights", raise_on_deleted_version=True
    )
    assert create_client.call_count == authenticate.call_count == 1


@pytest.mark.parametrize("nested", [False, True])
def test_overridden_reference_never_fetches(config_file, monkeypatch, vault_boundary, nested):
    _, create_client, authenticate = vault_boundary
    shared = "password: !from_vault {path: inaccessible, key: password}"
    consumer = "password: local-value"
    if nested:
        shared, consumer = f"account: {{{shared}}}", f"account: {{{consumer}}}"
    shared_path = config_file(f"default: {{{shared}}}", "config.yaml")
    monkeypatch.setattr(_loader, "files", lambda _: shared_path.parent)
    settings = load_config(config_file(f"default: {{{consumer}}}"))
    assert (settings.account.password if nested else settings.password) == "local-value"
    create_client.assert_not_called()
    authenticate.assert_not_called()


def test_list_and_dict_overlays_defer_references(config_file, vault_boundary, monkeypatch):
    client, create_client, _ = vault_boundary
    path = config_file("""
default:
  sequence: [!from_vault {path: users/demo, key: count}]
  account:
    username: !from_vault {path: users/demo, key: username}
    password: !from_vault {path: inaccessible, key: password}
stage:
  sequence: [4]
  account: {password: stage-value}
""")
    config_file("default: {sequence: [5], account: {enabled: true}}", "consumer.local.yaml")
    monkeypatch.setenv("DYNACONF_ACCOUNT__PASSWORD", "local-value")
    monkeypatch.setenv("DYNACONF_SEQUENCE", "@merge [6]")
    settings = load_config(path)
    create_client.assert_not_called()
    # Native Dynaconf applies top-level @merge and MERGE_ENABLED together.
    assert settings.sequence == [3, 4, 5, 3, 4, 5, 6]
    assert settings.account.username == "demo"
    assert settings.account.password == "local-value"
    assert settings.account.enabled is True
    assert client.secrets.kv.v2.read_secret_version.call_count == 1


def test_consumers_have_independent_final_vault_options(config_file, vault_boundary):
    client, create_client, authenticate = vault_boundary
    first_path = config_file(
        """
default:
  vault: {url: 'https://first.invalid', token: first-default}
  username: !from_vault {path: users/demo, key: username}
stage:
  vault: {token: first-final}
""",
        "first.yaml",
    )
    second_path = config_file(
        """
default:
  vault: {url: 'https://second.invalid', token: second-default}
  username: !from_vault {path: users/demo, key: username}
""",
        "second.yaml",
    )
    config_file("default: {vault: {token: second-final}}", "second.local.yaml")
    other = Mock()
    other.is_authenticated.return_value = True
    other.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"username": "other"}}}
    create_client.side_effect = [client, other]
    first, second = load_config(first_path), load_config(second_path)
    create_client.assert_not_called()
    assert first.username == "demo"
    first_options = VaultOptions(url="https://first.invalid", token="first-final")
    create_client.assert_called_once_with(first_options)
    assert second.username == "other"
    second_options = VaultOptions(url="https://second.invalid", token="second-final")
    assert create_client.call_args_list == [call(first_options), call(second_options)]
    assert authenticate.call_args_list == [call(client, first_options), call(other, second_options)]
    assert first.username == "demo"
    assert second.username == "other"
    assert client.secrets.kv.v2.read_secret_version.call_count == 1
    assert other.secrets.kv.v2.read_secret_version.call_count == 1


def test_all_vault_options_use_dynaconf(config_file, monkeypatch, vault_boundary):
    client, create_client, authenticate = vault_boundary
    expected = VaultOptions(
        url="https://override.invalid",
        mount_point="custom",
        verify=False,
        token="selected-token",
        role_id="selected-role",
        secret_id="selected-secret",
        oidc_token="selected-oidc",
        oidc_role="Custom",
        oidc_redirect_uri="http://127.0.0.1:9000/callback",
        timeout=7.5,
    )
    for field, value in asdict(expected).items():
        raw = str(value).lower() if isinstance(value, bool) else str(value)
        monkeypatch.setenv(f"DYNACONF_VAULT__{field.upper()}", raw)
    settings = load_config(
        config_file("default: {username: !from_vault {path: users/demo, key: username}}")
    )
    create_client.assert_not_called()
    assert settings.username == "demo"
    create_client.assert_called_once_with(expected)
    authenticate.assert_called_once_with(client, expected)


def test_vault_options_are_validated_only_on_access(config_file, vault_boundary):
    _, create_client, _ = vault_boundary
    settings = load_config(
        config_file("""
default:
  vault: {timeout: -1}
  username: !from_vault {path: users/demo, key: username}
""")
    )
    assert settings.base_url == "https://console.stage.redhat.com"
    with pytest.raises(ValueError, match="timeout"):
        _ = settings.username
    create_client.assert_not_called()


def test_vault_and_templates_share_final_settings(config_file, monkeypatch, vault_boundary):
    client, create_client, _ = vault_boundary
    path = config_file("""
default:
  vault: {url: '@jinja {{ main.vault_url }}', token: '@format {this.selected_token}'}
  vault_url: https://original.invalid
  selected_token: original-token
  username: !from_vault {path: users/demo, key: username}
  rendered: '@jinja {{ this.username }}'
""")
    monkeypatch.setenv("DYNACONF_VAULT_URL", "https://final.invalid")
    monkeypatch.setenv("DYNACONF_SELECTED_TOKEN", "final-token")
    settings = load_config(path)
    create_client.assert_not_called()
    assert settings.rendered == "demo"
    create_client.assert_called_once_with(
        VaultOptions(url="https://final.invalid", token="final-token")
    )
    assert settings.username == "demo"
    assert client.secrets.kv.v2.read_secret_version.call_count == 1
