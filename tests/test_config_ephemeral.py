import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from iqe_library.config import load_config
from iqe_library.ephemeral import _discovery


@pytest.fixture
def oc(monkeypatch):
    command = Mock(
        return_value=json.dumps(
            {"spec": {"hostname": "gateway.example", "sso": "https://sso.example/auth/"}}
        )
    )
    monkeypatch.setattr(_discovery, "_oc", command)
    monkeypatch.delenv("NAMESPACE", raising=False)
    return command


def test_shared_templates_are_lazy_and_share_one_resource_read(oc, monkeypatch):
    monkeypatch.setenv("NAMESPACE", "selected")
    settings = load_config(environment="ephemeral")
    oc.assert_not_called()
    assert settings.http.default_auth_type == "basic"
    assert settings.base_url == "https://gateway.example"
    assert settings.keycloak_admin.server_url == "https://sso.example/auth/"
    assert settings.base_url == "https://gateway.example"
    oc.assert_called_once_with(
        "get", "frontendenvironment", "env-selected", "-o", "json", "--request-timeout=30s"
    )


@pytest.mark.parametrize("environment", ["stage", "prod"])
def test_other_environments_do_not_discover(oc, environment):
    settings = load_config(environment=environment)
    assert settings.base_url.startswith("https://console.")
    assert settings.get("keycloak_admin") is None
    oc.assert_not_called()


def test_base_url_override_does_not_evaluate_discarded_template(oc, monkeypatch):
    monkeypatch.setenv("DYNACONF_BASE_URL", "https://override.example")
    settings = load_config(environment="ephemeral")
    assert settings.base_url == "https://override.example"
    oc.assert_not_called()


def test_consumer_overlay_and_final_namespace_override(oc, monkeypatch, config_file):
    path = config_file("ephemeral: {ephemeral: {namespace: from-file}}")
    monkeypatch.setenv("NAMESPACE", "ambient")
    monkeypatch.setenv("DYNACONF_EPHEMERAL__NAMESPACE", "override")
    assert load_config(path, environment="ephemeral").base_url == "https://gateway.example"
    assert oc.call_args.args[2] == "env-override"


def test_settings_instances_snapshot_namespace_even_before_first_read(oc, monkeypatch):
    monkeypatch.setenv("NAMESPACE", "one")
    first = load_config(environment="ephemeral")
    monkeypatch.setenv("NAMESPACE", "two")
    second = load_config(environment="ephemeral")
    assert first.base_url == second.base_url == "https://gateway.example"
    assert [call.args[2] for call in oc.call_args_list] == ["env-one", "env-two"]


def test_absent_namespace_snapshot_keeps_current_project_fallback(oc, monkeypatch):
    first = load_config(environment="ephemeral")
    monkeypatch.setenv("NAMESPACE", "later")
    oc.side_effect = ["current\n", json.dumps({"spec": {"hostname": "current.example"}})]
    assert first.base_url == "https://current.example"
    assert oc.call_args.args[2] == "env-current"


def test_custom_template_context_can_replace_parser(oc):
    settings = load_config(
        environment="ephemeral",
        template_context={"env_parser": SimpleNamespace(env_hostname="custom.example")},
    )
    assert settings.base_url == "https://custom.example"
    oc.assert_not_called()


def test_namespace_validation_is_lazy(oc, config_file):
    settings = load_config(
        config_file("ephemeral: {ephemeral: {namespace: ''}}"), environment="ephemeral"
    )
    oc.assert_not_called()
    with pytest.raises(ValueError, match="namespace"):
        _ = settings.base_url
    oc.assert_not_called()
