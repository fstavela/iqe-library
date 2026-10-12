"""Validated connection options and public Vault errors."""

import math
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit


class VaultAuthenticationError(RuntimeError):
    """Vault authentication could not be completed."""


class VaultReadError(RuntimeError):
    """A Vault secret could not be read."""


@dataclass(frozen=True, kw_only=True)
class VaultOptions:
    """Explicit Vault settings, without environment reads or value coercion."""

    url: str
    mount_point: str = "insights"
    verify: bool | str = True
    token: str | None = field(default=None, repr=False)
    role_id: str | None = field(default=None, repr=False)
    secret_id: str | None = field(default=None, repr=False)
    oidc_token: str | None = field(default=None, repr=False)
    oidc_role: str = "Default"
    oidc_redirect_uri: str = "http://localhost:8250/oidc/callback"
    timeout: float = 60

    def __post_init__(self) -> None:
        for name in ("url", "mount_point", "oidc_role", "oidc_redirect_uri"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a nonempty string")
        for name in ("token", "role_id", "secret_id", "oidc_token"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or None")
        if not isinstance(self.verify, (bool, str)) or (
            isinstance(self.verify, str) and not self.verify.strip()
        ):
            raise ValueError("verify must be a boolean or a nonempty CA path")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        self._validate_redirect_uri()

    def _validate_redirect_uri(self) -> None:
        try:
            uri = urlsplit(self.oidc_redirect_uri)
            host = uri.hostname
            loopback = host == "localhost" or (host is not None and ip_address(host).is_loopback)
            if (
                uri.scheme != "http"
                or not loopback
                or uri.username is not None
                or uri.password is not None
                or not uri.path.startswith("/")
                or uri.query
                or uri.fragment
                or (uri.port is not None and uri.port == 0)
            ):
                raise ValueError
        except ValueError:
            raise ValueError("oidc_redirect_uri must be an HTTP loopback callback URI") from None

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "VaultOptions":
        """Read only documented option keys, retaining native values."""
        if "url" not in values:
            raise ValueError("url is required")
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})
