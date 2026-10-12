"""Optional session selection, with real auth and offline external boundaries."""

import base64
import copy
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import requests
from requests.auth import HTTPBasicAuth

from iqe_library.auth import NoAuth, OIDCAuth
from iqe_library.config import load_config
from iqe_library.http import create_session_from_config, log_response
from iqe_library.vault import VaultSecretFetcher


def basic_config():
    return {
        "default_user": "shared",
        "http": {"default_auth_type": "basic"},
        "users": {
            "shared": {"auth": {"basic": {"username": "u", "password": "p"}}},
            "viewer": {"auth": {"basic": {"username": "v", "password": "q"}}},
        },
    }


def test_config_adapter_defaults_and_explicit_selection():
    config = basic_config()
    config["http"]["default_user"] = "wrong"  # Selection is top-level, not HTTP-scoped.
    before = copy.deepcopy(config)
    with (
        create_session_from_config(config) as first,
        create_session_from_config(config) as second,
        create_session_from_config(config, user="viewer", auth_type="basic") as viewer,
    ):
        assert isinstance(first.auth, HTTPBasicAuth)
        assert first.auth.username == second.auth.username == "u"
        assert viewer.auth.username == "v"
        assert first is not second and first.auth is not second.auth
        prepared = first.prepare_request(requests.Request("GET", "https://api.invalid"))
        assert prepared.headers["Authorization"] == "Basic dTpw"
        assert first.hooks["response"] == [log_response]
    assert config == before


@pytest.mark.parametrize(
    ("loaded", "username", "password", "header"),
    [
        (False, "token", "", "Basic dG9rZW46"),
        (True, "", "p", "Basic OnA="),
        (True, "", "", "Basic Og=="),
    ],
)
def test_basic_accepts_empty_strings(config_file, loaded, username, password, header):
    config = basic_config()
    config["users"]["shared"]["auth"]["basic"] = {"username": username, "password": password}
    if loaded:
        config = load_config(config_file(f"default:\n  {json.dumps(config)}\n"))
    with create_session_from_config(config) as session:
        prepared = session.prepare_request(requests.Request("GET", "https://api.invalid"))
        assert prepared.headers["Authorization"] == header


@pytest.mark.parametrize("field,value", [("username", None), ("password", False)])
def test_basic_rejects_non_string_credentials(field, value):
    config = basic_config()
    config["users"]["shared"]["auth"]["basic"][field] = value
    with pytest.raises(ValueError, match=field):
        create_session_from_config(config)


@pytest.mark.parametrize(
    ("grant", "field"),
    [
        ("refresh_token", "refresh_token"),
        ("client_credentials", "client_secret"),
        ("client_credentials", "client_id"),
        ("password", "username"),
        ("password", "password"),
        ("password", "client_id"),
        ("refresh_token", "grant_type"),
    ],
)
def test_jwt_fields_remain_nonempty(grant, field):
    block = {
        "grant_type": grant,
        "refresh_token": "offline",
        "client_secret": "secret",
        "client_id": "service",
        "username": "test-user",
        "password": "secret",
        field: " \t",
    }
    config = {
        "default_user": "u",
        "http": {"token_url": "https://sso.invalid/token"},
        "users": {"u": {"auth": {"jwt": block}}},
    }
    with pytest.raises(ValueError, match=field):
        create_session_from_config(config, auth_type="jwt")


def test_none_needs_no_user():
    with create_session_from_config({"http": {"default_auth_type": "none"}}) as session:
        assert isinstance(session.auth, NoAuth)
        assert session.cert is None
    with create_session_from_config({}, auth_type="none", user="missing") as session:
        assert isinstance(session.auth, NoAuth)


@pytest.fixture
def token_boundary(monkeypatch):
    exchanges = []

    def send(session, request, **kwargs):
        exchanges.append((session, request, kwargs))
        response = requests.Response()
        response.status_code = 200
        response.request = request
        response._content = b'{"access_token":"access","token_type":"Bearer","expires_in":300}'
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return exchanges


@pytest.mark.parametrize(
    ("block", "expected"),
    [
        (
            {"refresh_token": "offline"},
            {
                "refresh_token": ["offline"],
                "grant_type": ["refresh_token"],
                "client_id": ["rhsm-api"],
            },
        ),
        (
            {"grant_type": "client_credentials", "client_secret": "secret", "client_id": "service"},
            {
                "client_secret": ["secret"],
                "grant_type": ["client_credentials"],
                "client_id": ["service"],
            },
        ),
        (
            {
                "grant_type": "password",
                "username": "test-user",
                "password": "secret",
                "client_id": "cloud-services",
            },
            {
                "grant_type": ["password"],
                "username": ["test-user"],
                "password": ["secret"],
                "client_id": ["cloud-services"],
            },
        ),
    ],
)
def test_jwt_grants_are_lazy_and_use_isolated_transport(block, expected, token_boundary):
    config = {
        "default_user": "selected",
        "http": {
            "default_auth_type": "jwt",
            "token_url": "https://sso.invalid/token",
            "headers": {"X-API": "api-only"},
            "cookies": {"api-cookie": "api-only"},
            "proxy": "http://shorthand.invalid",
            "proxies": {"https": "http://explicit.invalid"},
            "verify": "/ca.pem",
            "timeout": 7,
            "trust_env": False,
        },
        "users": {"selected": {"auth": {"jwt": block}}},
    }
    with create_session_from_config(config) as session:
        assert isinstance(session.auth, OIDCAuth)
        assert token_boundary == []
        assert session.headers["X-API"] == "api-only"
        assert session.cookies["api-cookie"] == "api-only"
        assert session.proxies == {
            "http": "http://shorthand.invalid",
            "https": "http://explicit.invalid",
        }
        assert session.verify == "/ca.pem" and session.trust_env is False
        prepared = session.prepare_request(requests.Request("GET", "https://api.invalid"))
        assert prepared.headers["Authorization"] == "Bearer access"
        token_session, request, kwargs = token_boundary[0]
        data = parse_qs(request.body)
        assert data == expected
        assert request.url == "https://sso.invalid/token"
        assert "X-API" not in request.headers and "Cookie" not in request.headers
        assert token_session.hooks["response"] == []
        assert token_session.cert is None and isinstance(token_session.auth, NoAuth)
        assert token_session is not session
        assert kwargs["verify"] == "/ca.pem" and kwargs["timeout"] == 7
        assert kwargs["proxies"] == session.proxies and kwargs["allow_redirects"] is False


@pytest.mark.parametrize("scope,per_user", [(None, False), ("", True), ("read write", True)])
def test_jwt_endpoint_client_and_scope_precedence(scope, per_user, token_boundary):
    block = {"refresh_token": "offline", "scope": scope}
    if per_user:
        block.update(token_url="https://user.invalid/token", client_id="user-client")
    config = {
        "default_user": "u",
        "http": {"token_url": "https://shared.invalid/token", "client_id": "shared-client"},
        "users": {"u": {"auth": {"jwt": block}}},
    }
    with create_session_from_config(config, auth_type="jwt") as session:
        assert session.auth.get_token() == "access"
    _, request, _ = token_boundary[0]
    assert request.url == (
        "https://user.invalid/token" if per_user else "https://shared.invalid/token"
    )
    data = parse_qs(request.body)
    assert data["client_id"] == ["user-client" if per_user else "shared-client"]
    assert data.get("scope") == (["read write"] if scope else None)


def test_password_grant_requires_explicit_client_id():
    config = {
        "default_user": "selected",
        "http": {"token_url": "https://sso.invalid/token"},
        "users": {
            "selected": {
                "auth": {
                    "jwt": {"grant_type": "password", "username": "user", "password": "password"}
                }
            }
        },
    }
    with pytest.raises(ValueError, match="client_id"):
        create_session_from_config(config, auth_type="jwt")


@pytest.mark.parametrize("mode", ["split", "combined", "pem"])
def test_certificate_modes_and_lifecycle(mode, tmp_path):
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_text("certificate")
    key_path.write_text("private key")
    block = {"cert": "certificate", "key": "private key"}
    if mode != "pem":
        block["cert_path"] = str(cert_path)
        if mode == "split":
            block["key_path"] = str(key_path)
    config = {"default_user": "u", "users": {"u": {"auth": {"cert": block}}}}
    session = create_session_from_config(config, auth_type="cert")
    assert isinstance(session.auth, NoAuth)
    paths = (
        [Path(p) for p in session.cert] if isinstance(session.cert, tuple) else [Path(session.cert)]
    )
    assert paths[0].read_text() == "certificate"
    session.close()
    assert all(not p.exists() for p in paths) if mode == "pem" else all(p.exists() for p in paths)
    assert cert_path.exists() and key_path.exists()


def test_identity_payload_and_explicit_type_override():
    config = basic_config()
    config["users"]["shared"]["auth"]["identity"] = {
        "identity": {"type": "User", "account_number": "123"},
        "entitlements": {"inventory": {"is_entitled": True}},
    }
    with create_session_from_config(config, auth_type="identity") as session:
        request = session.prepare_request(requests.Request("GET", "https://api.invalid"))
        assert json.loads(base64.b64decode(request.headers["x-rh-identity"])) == {
            "identity": {"type": "User", "account_number": "123"},
            "entitlements": {"inventory": {"is_entitled": True}},
        }
        assert "Authorization" not in request.headers


@pytest.mark.parametrize(
    ("auth_type", "block", "field"),
    [
        ("basic", {"password": "secret-sentinel"}, "username"),
        ("basic", {"username": "secret-sentinel"}, "password"),
        ("basic", {"username": [], "password": "secret-sentinel"}, "username"),
        ("jwt", {"grant_type": "secret-sentinel"}, "grant_type"),
        ("jwt", {}, "token_url"),
        ("jwt", {"token_url": "https://sso.invalid/token"}, "refresh_token"),
        (
            "jwt",
            {
                "grant_type": "client_credentials",
                "client_secret": "secret-sentinel",
                "token_url": "https://sso.invalid/token",
            },
            "client_id",
        ),
        (
            "jwt",
            {
                "grant_type": "client_credentials",
                "client_id": "service",
                "token_url": "https://sso.invalid/token",
            },
            "client_secret",
        ),
        ("cert", {"key_path": "secret-sentinel"}, "cert_path"),
        ("cert", {"cert": "secret-sentinel"}, "key"),
        ("identity", {"entitlements": {"value": "secret-sentinel"}}, "identity"),
        ("identity", {"identity": "secret-sentinel"}, "identity"),
    ],
)
def test_bad_selection_errors_hide_values(auth_type, block, field):
    config = {"default_user": "u", "users": {"u": {"auth": {auth_type: block}}}}
    with pytest.raises(ValueError, match=field) as error:
        create_session_from_config(config, auth_type=auth_type)
    assert "secret-sentinel" not in str(error.value)


@pytest.mark.parametrize(
    ("config", "kwargs", "field"),
    [
        ({}, {"auth_type": "secret-sentinel"}, "auth_type"),
        ({}, {}, "default_user"),
        (basic_config(), {"user": "secret-sentinel"}, "user"),
        ({"default_user": "u", "users": {"u": {}}}, {}, "auth"),
    ],
)
def test_unknown_selection_is_safe(config, kwargs, field):
    with pytest.raises(ValueError, match=field) as error:
        create_session_from_config(config, **kwargs)
    assert "secret-sentinel" not in str(error.value)


@pytest.fixture
def vault_resolver(monkeypatch):
    reads = []
    values = {
        "username": "vault-user",
        "password": "vault-password",
        "refresh_token": "vault-offline",
        "client_id": "vault-service",
        "client_secret": "vault-secret",
        "cert": "vault-certificate",
        "key": "vault-private-key",
        "identity": {"type": "User", "account_number": "vault-account"},
    }

    def resolve(self, path, key=None):
        assert path == "selected", "unselected Vault reference accessed"
        reads.append((path, key))
        return values[key]

    monkeypatch.setattr(VaultSecretFetcher, "get_value_from_vault", resolve)
    return reads


@pytest.mark.parametrize(
    ("auth_type", "block", "keys"),
    [
        (
            "basic",
            "username: !from_vault {path: selected, key: username}\n"
            "password: !from_vault {path: selected, key: password}",
            ["username", "password"],
        ),
        (
            "jwt",
            "refresh_token: !from_vault {path: selected, key: refresh_token}",
            ["refresh_token"],
        ),
        (
            "jwt",
            "grant_type: client_credentials\n"
            "client_id: !from_vault {path: selected, key: client_id}\n"
            "client_secret: !from_vault {path: selected, key: client_secret}",
            ["client_id", "client_secret"],
        ),
        (
            "cert",
            "cert: !from_vault {path: selected, key: cert}\n"
            "key: !from_vault {path: selected, key: key}",
            ["cert", "key"],
        ),
        ("identity", "identity: !from_vault {path: selected, key: identity}", ["identity"]),
        ("none", "unneeded: !from_vault {path: forbidden}", []),
    ],
)
def test_real_loader_reads_only_selected_credential_keys(
    config_file, vault_resolver, token_boundary, auth_type, block, keys
):
    selected_block = "\n".join(f"          {line}" for line in block.splitlines())
    settings = load_config(
        config_file(f"""
default:
  default_user: selected
  http:
    default_auth_type: {auth_type}
    token_url: https://sso.invalid/token
  users:
    forbidden: !from_vault {{path: forbidden}}
    selected:
      unrelated: !from_vault {{path: forbidden}}
      auth:
        unrelated: !from_vault {{path: forbidden}}
        {auth_type}:
{selected_block}
          unused: !from_vault {{path: forbidden}}
""")
    )
    assert vault_resolver == []
    with create_session_from_config(settings) as session:
        if auth_type == "basic":
            assert session.auth.username == "vault-user"
            assert session.auth.password == "vault-password"
        elif auth_type == "jwt":
            assert session.auth.get_token() == "access"
        elif auth_type == "cert":
            paths = [Path(p) for p in session.cert]
            assert [p.read_text() for p in paths] == ["vault-certificate", "vault-private-key"]
        elif auth_type == "identity":
            prepared = session.prepare_request(requests.Request("GET", "https://api.invalid"))
            assert json.loads(base64.b64decode(prepared.headers["x-rh-identity"])) == {
                "identity": {"type": "User", "account_number": "vault-account"},
                "entitlements": {},
            }
        else:
            assert isinstance(session.auth, NoAuth)
    if auth_type == "cert":
        assert all(not p.exists() for p in paths)
    assert vault_resolver == [("selected", key) for key in keys]


def test_basic_never_resolves_token_settings_or_jwt_secrets(config_file, vault_resolver):
    settings = load_config(
        config_file("""
default:
  default_user: selected
  http:
    token_url: !from_vault {path: forbidden}
    client_id: !from_vault {path: forbidden}
  users:
    selected:
      auth:
        basic: {username: local, password: local}
        jwt:
          refresh_token: !from_vault {path: forbidden}
""")
    )
    with create_session_from_config(settings) as session:
        assert session.auth.username == "local"
    assert vault_resolver == []


def test_loaded_environment_overrides_and_explicit_selection(
    config_file, monkeypatch, vault_resolver
):
    monkeypatch.setenv("DYNACONF_DEFAULT_USER", "viewer")
    monkeypatch.setenv("DYNACONF_HTTP__DEFAULT_AUTH_TYPE", "identity")
    settings = load_config(
        config_file("""
default:
  default_user: selected
  http: {default_auth_type: basic}
  users:
    selected:
      auth:
        basic: {username: chosen, password: chosen}
        identity: !from_vault {path: forbidden}
    viewer:
      auth:
        identity: {identity: {type: User, account_number: viewer}}
        basic: !from_vault {path: forbidden}
""")
    )
    with create_session_from_config(settings) as viewer:
        request = viewer.prepare_request(requests.Request("GET", "https://api.invalid"))
        assert (
            json.loads(base64.b64decode(request.headers["x-rh-identity"]))["identity"][
                "account_number"
            ]
            == "viewer"
        )
    with create_session_from_config(settings, user="selected", auth_type="basic") as selected:
        assert selected.auth.username == "chosen"
    assert settings.default_user == "viewer" and settings.http.default_auth_type == "identity"
    assert vault_resolver == []


def test_explicit_arguments_do_not_resolve_configured_selection(config_file, vault_resolver):
    settings = load_config(
        config_file("""
default:
  default_user: !from_vault {path: forbidden}
  http: {default_auth_type: !from_vault {path: forbidden}}
  users: {selected: {auth: {basic: {username: explicit, password: explicit}}}}
""")
    )
    with create_session_from_config(settings, user="selected", auth_type="basic") as session:
        assert session.auth.username == "explicit"
    with create_session_from_config(settings, auth_type="none") as session:
        assert isinstance(session.auth, NoAuth)
    assert vault_resolver == []


def test_jwt_per_user_settings_do_not_resolve_shared_defaults(
    config_file, vault_resolver, token_boundary
):
    settings = load_config(
        config_file("""
default:
  default_user: selected
  http:
    token_url: !from_vault {path: forbidden}
    client_id: !from_vault {path: forbidden}
  users:
    selected:
      auth:
        jwt:
          token_url: https://user.invalid/token
          client_id: user-client
          refresh_token: !from_vault {path: selected, key: refresh_token}
          client_secret: !from_vault {path: forbidden}
""")
    )
    with create_session_from_config(settings, auth_type="jwt") as session:
        assert session.auth.get_token() == "access"
    _, request, _ = token_boundary[0]
    assert request.url == "https://user.invalid/token"
    assert parse_qs(request.body)["client_id"] == ["user-client"]
    assert vault_resolver == [("selected", "refresh_token")]


@pytest.mark.parametrize("split", [False, True])
def test_certificate_paths_take_precedence_over_lazy_pem(
    config_file, tmp_path, vault_resolver, split
):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    settings = load_config(
        config_file(f"""
default:
  default_user: selected
  users:
    selected:
      auth:
        cert:
          cert_path: {cert}
          key_path: {key if split else "null"}
          cert: !from_vault {{path: forbidden}}
          key: !from_vault {{path: forbidden}}
""")
    )
    with create_session_from_config(settings, auth_type="cert") as session:
        assert session.cert == ((str(cert), str(key)) if split else str(cert))
    assert cert.exists() and key.exists()
    assert vault_resolver == []


def test_http_environment_transport_overrides(config_file, monkeypatch, token_boundary):
    monkeypatch.setenv("DYNACONF_HTTP__VERIFY", "false")
    monkeypatch.setenv("DYNACONF_HTTP__TIMEOUT", "8.5")
    monkeypatch.setenv("DYNACONF_HTTP__TRUST_ENV", "false")
    monkeypatch.setenv("DYNACONF_HTTP__PROXY", "http://env.invalid")
    monkeypatch.setenv("DYNACONF_HTTP__TOKEN_URL", "https://env.invalid/token")
    monkeypatch.setenv("DYNACONF_HTTP__CLIENT_ID", "env-service")
    settings = load_config(
        config_file("""
default:
  default_user: selected
  users:
    selected:
      auth:
        jwt: {grant_type: client_credentials, client_secret: secret}
""")
    )
    with create_session_from_config(settings, auth_type="jwt") as session:
        assert session.verify is False and session.trust_env is False
        assert session.proxies == {"http": "http://env.invalid", "https": "http://env.invalid"}
        assert session.auth.get_token() == "access"
    _, request, kwargs = token_boundary[0]
    assert request.url == "https://env.invalid/token"
    assert parse_qs(request.body)["client_id"] == ["env-service"]
    assert kwargs["timeout"] == 8.5 and kwargs["verify"] is False


@pytest.mark.parametrize(
    ("environment", "proxy", "token_url"),
    [
        (
            "stage",
            "http://squid.corp.redhat.com:3128",
            "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        ),
        (
            "prod",
            None,
            "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        ),
        ("absent", None, None),
    ],
)
def test_shared_http_defaults_and_environment_urls(environment, proxy, token_url, token_boundary):
    settings = load_config(environment=environment)
    assert settings.get("default_user") is None and settings.get("users") is None
    assert settings.http.default_auth_type == "basic"
    assert settings.http.proxy == proxy
    assert settings.http.verify is True
    assert settings.http.timeout == 30 and settings.http.trust_env is True
    assert settings.http.get("token_url") == token_url
    with create_session_from_config(settings, auth_type="none") as session:
        assert session.verify is True and session.trust_env is True
        assert session.proxies == ({"http": proxy, "https": proxy} if proxy else {})
        session.get("https://api.invalid")
    assert token_boundary[0][2]["timeout"] == 30
