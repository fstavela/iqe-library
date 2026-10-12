"""Translate explicit Insights attributes into Keycloak's small user representation."""

import json
from collections.abc import Mapping
from typing import Any


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _attribute(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        try:
            return json.dumps(value, allow_nan=False)
        except ValueError:
            pass
    raise ValueError("user attributes must contain strings, booleans, numbers, or lists of them")


def user_payload(
    username: str, attributes: Mapping[str, Any], entitlements: Mapping[str, Any]
) -> dict[str, Any]:
    """No random defaults, credential fields, or Keycloak UUID in the payload."""
    _string(username, "username")
    if not isinstance(attributes, Mapping) or not isinstance(entitlements, Mapping):
        raise ValueError("attributes and entitlements must be mappings")
    if attributes.get("type", "User") != "User":
        raise ValueError("Keycloak provisioning supports only type User")
    attrs = dict(attributes)
    attrs.pop("type", None)
    for name in ("account_number", "org_id", "user_id", "email", "first_name", "last_name"):
        _string(attrs.get(name), f"attributes.{name}")
    for name, default in (("is_active", True), ("is_org_admin", False), ("is_internal", False)):
        value = attrs.setdefault(name, default)
        if not isinstance(value, bool):
            raise ValueError(f"attributes.{name} must be a boolean")
    attrs.setdefault("locale", "en_US")
    _string(attrs["locale"], "attributes.locale")
    # account_id is the Insights user_id, not the Keycloak UUID.
    attrs["account_id"] = attrs["user_id"]
    encoded = {
        name: [_attribute(item) for item in value]
        if isinstance(value, list)
        else [_attribute(value)]
        for name, value in attrs.items()
    }
    entries = []
    for service, flags in entitlements.items():
        _string(service, "entitlement service")
        if not isinstance(flags, Mapping):
            raise ValueError("each entitlement must be a mapping")
        flags = {"is_entitled": True, "is_trial": False, **flags}
        if any(not isinstance(value, bool) for value in flags.values()):
            raise ValueError("entitlement flags must be booleans")
        entries.append(f"{json.dumps(service)}:{json.dumps(flags, separators=(',', ':'))}")
    # Current mocktitlements validates entitlements but reads newEntitlements.
    # Split by service to avoid Keycloak's per-attribute-value length limit.
    encoded["entitlements"] = entries
    encoded["newEntitlements"] = entries.copy()
    encoded["permissions"] = [""]
    return {
        "username": username,
        "email": attrs["email"],
        "firstName": attrs["first_name"],
        "lastName": attrs["last_name"],
        "enabled": attrs["is_active"],
        "emailVerified": True,
        "attributes": encoded,
    }
