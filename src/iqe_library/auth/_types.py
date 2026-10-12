"""Structural request typing, token endpoint settings, and public auth errors."""

import math
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit


class RequestWithHeaders(Protocol):
    """The header-only request interface used by authentication callbacks."""

    @property
    def headers(self) -> MutableMapping[str, str]: ...


class TokenAuthenticationError(RuntimeError):
    """An OAuth token exchange could not be completed."""


def _validate_verify(verify: object) -> None:
    if not isinstance(verify, (bool, str)) or (isinstance(verify, str) and not verify.strip()):
        raise ValueError("verify must be a boolean or a nonempty CA path")


def _validate_proxies(proxies: object) -> dict[str, str] | None:
    if proxies is None:
        return None
    if not isinstance(proxies, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in proxies.items()
    ):
        raise ValueError("proxies must be a mapping of strings to strings or None")
    return dict(proxies)


def _validate_timeout(timeout: object) -> None:
    try:
        valid = (
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and math.isfinite(timeout)
            and timeout > 0
        )
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("timeout must be a positive finite number")


def _validate_trust_env(trust_env: object) -> None:
    if not isinstance(trust_env, bool):
        raise ValueError("trust_env must be a boolean")


@dataclass(frozen=True, kw_only=True)
class TokenEndpoint:
    """Explicit token-exchange settings, independent of API transport settings."""

    token_url: str
    client_id: str = "rhsm-api"
    verify: bool | str = True
    proxies: Mapping[str, str] | None = None
    timeout: float = 30
    trust_env: bool = True

    def __post_init__(self) -> None:
        self._validate_token_url()
        if not isinstance(self.client_id, str) or not self.client_id.strip():
            raise ValueError("client_id must be a nonempty string")
        _validate_verify(self.verify)
        object.__setattr__(self, "proxies", _validate_proxies(self.proxies))
        _validate_timeout(self.timeout)
        _validate_trust_env(self.trust_env)

    def _validate_token_url(self) -> None:
        try:
            if (
                not isinstance(self.token_url, str)
                or not self.token_url
                or any(char.isspace() for char in self.token_url)
                or "#" in self.token_url
            ):
                raise ValueError
            url = urlsplit(self.token_url)
            if (
                url.scheme not in {"http", "https"}
                or not url.hostname
                or url.username is not None
                or url.password is not None
                or url.port == 0
            ):
                raise ValueError
        except ValueError:
            raise ValueError(
                "token_url must be an HTTP(S) URL without credentials or fragment"
            ) from None
