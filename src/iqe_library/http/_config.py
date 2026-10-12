"""Optional, structural configuration adapter; no configuration-stack imports."""

from collections.abc import Mapping
from typing import Any, Protocol, cast

import requests
from requests.auth import AuthBase, HTTPBasicAuth

from iqe_library.auth import CertificateAuth, IdentityAuth, NoAuth, OIDCAuth, TokenEndpoint

from ._session import create_session


class ConfigLookup(Protocol):
    """The small lookup interface shared by plain mappings and loaded settings."""

    def get(self, key: str, default: Any = None) -> Any: ...


def _lookup(value: object, field: str) -> ConfigLookup:
    if not callable(getattr(value, "get", None)):
        raise ValueError(f"{field} must support configuration lookup")
    return cast(ConfigLookup, value)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _basic_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    return value


def _proxies(http: ConfigLookup) -> dict[str, str] | None:
    proxy = http.get("proxy")
    proxies = {} if proxy is None else dict.fromkeys(("http", "https"), _string(proxy, "proxy"))
    explicit = http.get("proxies")
    if explicit is not None:
        for key, value in _mapping(explicit, "proxies").items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("proxies must be a mapping of strings to strings")
            proxies[key] = value
    return proxies if proxy is not None or explicit is not None else None


def _jwt(block: ConfigLookup, http: ConfigLookup, transport: dict[str, Any]) -> OIDCAuth:
    grant = block.get("grant_type", "refresh_token")
    if grant not in ("refresh_token", "client_credentials"):
        raise ValueError("grant_type must be refresh_token or client_credentials")
    token_url = block.get("token_url")
    if token_url is None:
        token_url = http.get("token_url")
    endpoint_options = {"token_url": _string(token_url, "token_url"), **transport}
    client_id = block.get("client_id")
    if client_id is None:
        client_id = http.get("client_id")
    if client_id is not None or grant == "client_credentials":
        endpoint_options["client_id"] = _string(client_id, "client_id")
    endpoint = TokenEndpoint(**endpoint_options)
    scope = block.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise ValueError("scope must be a string or None")
    if grant == "refresh_token":
        return OIDCAuth.from_refresh_token(
            _string(block.get("refresh_token"), "refresh_token"), endpoint, scope=scope
        )
    return OIDCAuth.from_client_credentials(
        _string(block.get("client_secret"), "client_secret"), endpoint, scope=scope
    )


def _certificate(block: ConfigLookup) -> CertificateAuth:
    cert_path = block.get("cert_path")
    key_path = block.get("key_path")
    if cert_path is not None:
        return CertificateAuth.from_files(cert_path, key_path)
    if key_path is not None:
        raise ValueError("cert_path is required with key_path")
    return CertificateAuth.from_pem(
        _string(block.get("cert"), "cert"), _string(block.get("key"), "key")
    )


def _auth(
    config: ConfigLookup,
    http: ConfigLookup,
    auth_type: str,
    user: str | None,
    transport: dict[str, Any],
) -> AuthBase | CertificateAuth:
    if auth_type == "none":
        return NoAuth()
    if user is None:
        user = _string(config.get("default_user"), "default_user")
    else:
        user = _string(user, "user")
    users = _lookup(config.get("users", {}), "users")
    selected = _lookup(users.get(user), "selected user")
    auth = _lookup(selected.get("auth"), "selected user auth")
    block = _lookup(auth.get(auth_type), "selected auth block")
    if auth_type == "basic":
        return HTTPBasicAuth(
            _basic_string(block.get("username"), "username"),
            _basic_string(block.get("password"), "password"),
        )
    if auth_type == "jwt":
        return _jwt(block, http, transport)
    if auth_type == "cert":
        return _certificate(block)
    identity = _mapping(block.get("identity"), "identity")
    entitlements = block.get("entitlements")
    if entitlements is not None:
        entitlements = _mapping(entitlements, "entitlements")
    try:
        return IdentityAuth(identity, entitlements)
    except (TypeError, ValueError):
        raise ValueError("identity and entitlements must contain JSON values") from None


def create_session_from_config(
    config: ConfigLookup, *, auth_type: str | None = None, user: str | None = None
) -> requests.Session:
    """Select only the requested credentials and delegate transport/cleanup.

    Explicit selection wins over top-level ``default_user`` and
    ``http.default_auth_type``. No files or environment variables are loaded;
    unselected credential blocks and non-JWT token settings remain untouched.
    """
    http = _lookup(config.get("http", {}), "http")
    if auth_type is None:
        auth_type = http.get("default_auth_type", "basic")
    if auth_type not in ("basic", "jwt", "cert", "identity", "none"):
        raise ValueError("auth_type must be basic, jwt, cert, identity or none")
    assert auth_type is not None
    transport = {
        "verify": http.get("verify", True),
        "timeout": http.get("timeout", 30),
        "trust_env": http.get("trust_env", True),
        "proxies": _proxies(http),
    }
    auth = _auth(config, http, auth_type, user, transport)
    return create_session(
        auth=auth, headers=http.get("headers"), cookies=http.get("cookies"), **transport
    )
