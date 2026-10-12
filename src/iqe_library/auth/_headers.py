"""Requests-compatible authentication callbacks for mutable request headers."""

import base64
import json
from collections.abc import Mapping
from typing import Any, TypeVar, overload

from requests import PreparedRequest
from requests.auth import AuthBase

from ._types import RequestWithHeaders

_RequestT = TypeVar("_RequestT", bound=RequestWithHeaders)


class NoAuth(AuthBase):
    """Keep explicit headers intact without selecting ambient credentials."""

    @overload
    def __call__(self, request: PreparedRequest) -> PreparedRequest: ...

    @overload
    def __call__(self, request: _RequestT) -> _RequestT: ...

    def __call__(self, request: PreparedRequest | _RequestT) -> PreparedRequest | _RequestT:
        return request


class IdentityAuth(AuthBase):
    """Set an x-rh-identity header from a snapshot of arbitrary identity JSON."""

    def __init__(
        self, identity: Mapping[str, Any], entitlements: Mapping[str, Any] | None = None
    ) -> None:
        payload = {"identity": dict(identity), "entitlements": dict(entitlements or {})}
        self._header = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    @overload
    def __call__(self, request: PreparedRequest) -> PreparedRequest: ...

    @overload
    def __call__(self, request: _RequestT) -> _RequestT: ...

    def __call__(self, request: PreparedRequest | _RequestT) -> PreparedRequest | _RequestT:
        request.headers["x-rh-identity"] = self._header
        return request
