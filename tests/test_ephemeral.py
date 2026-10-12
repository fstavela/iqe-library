import base64
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from iqe_library.ephemeral import EphemeralDiscoveryError, EphemeralEnvParser, _discovery


@pytest.fixture
def oc(monkeypatch):
    command = Mock()
    monkeypatch.setattr(_discovery, "_oc", command)
    monkeypatch.delenv("NAMESPACE", raising=False)
    return command


def frontend(namespace):
    return json.dumps(
        {"spec": {"hostname": f"{namespace}.example", "sso": f"https://{namespace}.sso/auth/"}}
    )


def test_import_and_construction_do_not_discover(oc):
    parser = EphemeralEnvParser("custom")
    oc.assert_not_called()
    assert parser.namespace == "custom"
    oc.assert_not_called()


def test_explicit_namespace_wins_and_isolated_instances(oc, monkeypatch):
    monkeypatch.setenv("NAMESPACE", "ambient")
    oc.side_effect = [frontend("one"), frontend("two")]
    first = EphemeralEnvParser("one")
    second = EphemeralEnvParser("two")
    assert first.env_hostname == "one.example"
    assert second.env_hostname == "two.example"
    assert first.sso_url == "https://one.sso/auth/"
    assert first.env_hostname == "one.example"
    assert oc.call_count == 2
    assert [call.args[2] for call in oc.call_args_list] == ["env-one", "env-two"]
    assert all("project" not in call.args for call in oc.call_args_list)


def test_namespace_environment_is_snapshotted(oc, monkeypatch):
    monkeypatch.setenv("NAMESPACE", "selected")
    parser = EphemeralEnvParser()
    monkeypatch.setenv("NAMESPACE", "changed")
    assert parser.namespace == "selected"
    oc.assert_not_called()


def test_current_project_fallback_is_lazy_and_cached(oc):
    oc.side_effect = ["current\n", frontend("current")]
    parser = EphemeralEnvParser()
    oc.assert_not_called()
    assert parser.env_hostname == "current.example"
    assert parser.namespace == "current"
    assert parser.env_hostname == "current.example"
    assert oc.call_count == 2
    assert oc.call_args_list[0].args == ("project", "--short")


def test_secret_is_read_only_when_needed_and_targeted(oc):
    data = {
        key: base64.b64encode(value.encode()).decode()
        for key, value in {"username": "admin", "password": "secret"}.items()
    }
    oc.side_effect = [frontend("selected"), json.dumps({"data": data})]
    parser = EphemeralEnvParser("selected")
    assert parser.env_hostname == "selected.example"
    assert oc.call_count == 1
    assert parser.sso_admin_username == "admin"
    assert parser.sso_admin_password == "secret"
    assert parser.sso_admin_password == "secret"
    assert oc.call_count == 2
    assert oc.call_args.args == (
        "get",
        "secret",
        "env-selected-keycloak",
        "-o",
        "json",
        "--request-timeout=30s",
        "--namespace",
        "selected",
    )


@pytest.mark.parametrize("output", ["not-json", "[]", "{}", '{"spec":null}'])
def test_missing_or_malformed_frontend_has_context(oc, output):
    oc.return_value = output
    with pytest.raises(EphemeralDiscoveryError, match="env-selected"):
        _ = EphemeralEnvParser("selected").env_hostname


@pytest.mark.parametrize("field", ["hostname", "sso"])
def test_missing_frontend_field(oc, field):
    oc.return_value = '{"spec":{}}'
    with pytest.raises(EphemeralDiscoveryError, match=f"spec.{field}"):
        parser = EphemeralEnvParser("selected")
        _ = parser.env_hostname if field == "hostname" else parser.sso_url


def test_sso_path_and_trailing_slash_preserved(oc):
    oc.return_value = '{"spec":{"sso":"https://sso.example/custom/auth"}}'
    assert EphemeralEnvParser("selected").sso_url == "https://sso.example/custom/auth/"


@pytest.mark.parametrize(
    "encoded", [None, "private-invalid-base64", "", base64.b64encode(b"\xff").decode()]
)
def test_secret_errors_do_not_expose_values(oc, encoded):
    oc.return_value = json.dumps({"data": {"password": encoded}})
    with pytest.raises(EphemeralDiscoveryError, match="password") as error:
        _ = EphemeralEnvParser("selected").sso_admin_password
    assert "private-invalid-base64" not in str(error.value)


def test_failed_reads_are_not_cached(oc):
    oc.side_effect = [EphemeralDiscoveryError("upstream sensitive output"), frontend("selected")]
    parser = EphemeralEnvParser("selected")
    with pytest.raises(EphemeralDiscoveryError) as error:
        _ = parser.env_hostname
    assert "upstream sensitive" not in str(error.value)
    assert error.value.__cause__ is None
    assert parser.env_hostname == "selected.example"


def test_command_is_bounded_quiet_and_sanitized(monkeypatch):
    command = Mock(side_effect=RuntimeError("secret resource contents"))
    monkeypatch.setitem(sys.modules, "ocviapy", SimpleNamespace(oc=command))
    with pytest.raises(EphemeralDiscoveryError) as error:
        _discovery._oc("get", "secret")
    assert "secret resource contents" not in str(error.value)
    command.assert_called_once_with("get", "secret", _silent=True, _timeout=30)


@pytest.mark.parametrize("namespace", ["", " ", 123])
def test_invalid_explicit_namespace(namespace):
    with pytest.raises(ValueError, match="namespace"):
        EphemeralEnvParser(namespace)
