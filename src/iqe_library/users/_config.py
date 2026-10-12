"""Structural config helpers: mappings and Settings work without loading files."""

from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from typing import Any, Protocol

from ._payload import _string, user_payload
from ._provider import UserProvider, create_user_provider


class _ConfigLookup(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    return value


def create_user_provider_from_config(config: _ConfigLookup) -> UserProvider:
    """Read keycloak_admin options only; no files, env selection, or config imports."""
    options = _mapping(config.get("keycloak_admin"), "keycloak_admin")
    return create_user_provider(
        server_url=_string(options.get("server_url"), "keycloak_admin.server_url"),
        username=_string(options.get("username"), "keycloak_admin.username"),
        password=_string(options.get("password"), "keycloak_admin.password"),
        realm_name=options.get("realm_name", "redhat-external"),
        user_realm_name=options.get("user_realm_name", "master"),
        verify=options.get("verify", True),
        timeout=options.get("timeout", 30),
    )


def provision_users_from_config(
    config: _ConfigLookup,
    *,
    provider: UserProvider | None = None,
    users: Sequence[str] | None = None,
    recreate: bool = False,
) -> dict[str, str]:
    """Provision all configured users, or an explicit selection; return name -> UUID.

    Read credentials from auth.basic and metadata from attributes and entitlements.
    Only password credentials are accessed; JWT/certificate/identity blocks and
    Vault references in them remain untouched.
    No RBAC mutations or environment checks: the consumer decides when to call.
    """
    configured = _mapping(config.get("users", {}), "users")
    if isinstance(users, str):
        raise ValueError("users must be a sequence of user names, not a string")
    names = list(configured) if users is None else list(users)
    if not names:
        return {}
    # Validate the entire selection before making changes to any user.
    specs = {}
    for name in names:
        selected = _mapping(configured.get(name), f"users.{name}")
        auth = _mapping(selected.get("auth"), f"users.{name}.auth")
        credentials = _mapping(auth.get("basic"), f"users.{name}.auth.basic")
        attributes = dict(_mapping(selected.get("attributes"), f"users.{name}.attributes"))
        entitlements = _mapping(selected.get("entitlements", {}), f"users.{name}.entitlements")
        spec: dict[str, Any] = {
            "username": credentials.get("username"),
            "password": credentials.get("password"),
            "attributes": attributes,
            "entitlements": entitlements,
        }
        # The payload validator never includes values in its error messages.
        _string(spec["password"], f"users.{name}.password")
        user_payload(spec["username"], attributes, entitlements)
        specs[name] = spec
    context = (
        nullcontext(provider) if provider is not None else create_user_provider_from_config(config)
    )
    with context as active_provider:
        return {
            name: active_provider.ensure_user(**spec, recreate=recreate)
            for name, spec in specs.items()
        }
