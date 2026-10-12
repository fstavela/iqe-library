"""Lazy OAuth access-token acquisition, independent of API transports."""

import math
from threading import Lock
from time import monotonic
from typing import Literal, TypeVar, overload

import requests
from requests.auth import AuthBase

from iqe_library._transport import _SystemTrustAdapter

from ._headers import NoAuth
from ._types import RequestWithHeaders, TokenAuthenticationError, TokenEndpoint

_RequestT = TypeVar("_RequestT", bound=RequestWithHeaders)
_Grant = Literal["refresh_token", "client_credentials", "password"]


class OIDCAuth(AuthBase):
    """Exchange credentials only when access is needed; keep tokens per instance."""

    def __init__(
        self,
        credential: str,
        endpoint: TokenEndpoint,
        *,
        grant_type: _Grant,
        scope: str | None,
        username: str | None = None,
    ) -> None:
        if grant_type not in ("refresh_token", "client_credentials", "password"):
            raise ValueError("grant_type must be refresh_token, client_credentials or password")
        if not isinstance(credential, str) or not credential.strip():
            raise ValueError("credential must be a nonempty string")
        if scope is not None and not isinstance(scope, str):
            raise ValueError("scope must be a string or None")
        if grant_type == "password" and (not isinstance(username, str) or not username.strip()):
            raise ValueError("username must be a nonempty string")
        self._credential = credential
        self._username = username
        self._endpoint = endpoint
        self._grant_type = grant_type
        self._scope = scope
        self._access_token: str | None = None
        self._renew_at = 0.0
        self._lock = Lock()

    @classmethod
    def from_refresh_token(
        cls, refresh_token: str, endpoint: TokenEndpoint, *, scope: str | None = None
    ) -> "OIDCAuth":
        """Use a caller-provided offline/refresh token, not an API bearer token."""
        return cls(refresh_token, endpoint, grant_type="refresh_token", scope=scope)

    @classmethod
    def from_client_credentials(
        cls, client_secret: str, endpoint: TokenEndpoint, *, scope: str | None = None
    ) -> "OIDCAuth":
        """Use the client-credentials grant with the endpoint's client ID."""
        return cls(client_secret, endpoint, grant_type="client_credentials", scope=scope)

    @classmethod
    def from_password(
        cls,
        username: str,
        password: str,
        endpoint: TokenEndpoint,
        *,
        scope: str | None = None,
    ) -> "OIDCAuth":
        """Password grant for test Keycloak realms that explicitly allow direct grants.

        Prefer refresh tokens for Stage/prod. When Keycloak returns a refresh
        token, subsequent renewals use it rather than sending the password again.
        """
        return cls(password, endpoint, grant_type="password", scope=scope, username=username)

    def get_token(self) -> str:
        """Return a current access token, acquiring or renewing under a lock."""
        with self._lock:
            started = monotonic()
            if self._access_token is not None and started < self._renew_at:
                return self._access_token
            access_token, expires_in, refresh_token = self._exchange()
            expires_at = started + expires_in
            if not math.isfinite(expires_at) or monotonic() >= expires_at:
                raise TokenAuthenticationError("Token exchange returned an expired access token")
            renew_at = expires_at - min(30.0, expires_in / 2)
            credential = self._credential
            grant = self._grant_type
            if grant in ("refresh_token", "password") and refresh_token is not None:
                credential = refresh_token
                grant = "refresh_token"
            # Publish only after the entire response and its lifetime are valid.
            # All cache reads and rotation are protected by this instance's lock.
            self._access_token, self._renew_at, self._credential, self._grant_type = (
                access_token,
                renew_at,
                credential,
                grant,
            )
            return access_token

    @overload
    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest: ...

    @overload
    def __call__(self, request: _RequestT) -> _RequestT: ...

    def __call__(
        self, request: requests.PreparedRequest | _RequestT
    ) -> requests.PreparedRequest | _RequestT:
        request.headers["Authorization"] = f"Bearer {self.get_token()}"
        return request

    def _exchange(self) -> tuple[str, float, str | None]:
        endpoint = self._endpoint
        data = {"grant_type": self._grant_type, "client_id": endpoint.client_id}
        credential_field = {
            "refresh_token": "refresh_token",
            "client_credentials": "client_secret",
            "password": "password",
        }[self._grant_type]
        data[credential_field] = self._credential
        if self._grant_type == "password":
            assert self._username is not None  # Validated at construction.
            data["username"] = self._username
        if self._scope:
            data["scope"] = self._scope
        # Never use the public API factory: token traffic has no API hooks,
        # cookies, certificate identity, or bearer authentication.
        try:
            with requests.Session() as session:
                session.mount("https://", _SystemTrustAdapter())
                session.auth = NoAuth()
                session.trust_env = endpoint.trust_env
                response = session.post(
                    endpoint.token_url,
                    data=data,
                    verify=endpoint.verify,
                    proxies=dict(endpoint.proxies) if endpoint.proxies is not None else None,
                    timeout=endpoint.timeout,
                    allow_redirects=False,
                )
                if not 200 <= response.status_code < 300:
                    raise TokenAuthenticationError(
                        f"Token exchange failed (HTTP {response.status_code})"
                    )
                try:
                    body = response.json()
                except ValueError:
                    raise TokenAuthenticationError("Token exchange returned invalid JSON") from None
                return self._validate_response(body)
        except (requests.RequestException, OSError, ValueError):
            # Requests parses redirect metadata even with allow_redirects=False;
            # malformed Location URLs can raise ValueError before post returns.
            raise TokenAuthenticationError("Token exchange transport failed") from None

    @staticmethod
    def _validate_response(body: object) -> tuple[str, float, str | None]:
        if not isinstance(body, dict):
            raise TokenAuthenticationError("Token exchange returned an invalid payload")
        access_token = body.get("access_token")
        token_type = body.get("token_type")
        expires_in = body.get("expires_in")
        refresh_token = body.get("refresh_token")
        # Keep tokens opaque, but ensure HTTP serialization cannot raise an
        # exception containing the bearer value after cache/rotation publication.
        if (
            not isinstance(access_token, str)
            or not access_token.strip()
            or any(not 32 <= ord(char) <= 126 for char in access_token)
        ):
            raise TokenAuthenticationError("Token exchange returned an invalid access token")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise TokenAuthenticationError("Token exchange returned an invalid token type")
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            raise TokenAuthenticationError("Token exchange returned an invalid lifetime")
        try:
            lifetime = float(expires_in)
        except OverflowError:
            raise TokenAuthenticationError("Token exchange returned an invalid lifetime") from None
        if not math.isfinite(lifetime) or lifetime <= 0:
            raise TokenAuthenticationError("Token exchange returned an invalid lifetime")
        if "refresh_token" in body and (
            not isinstance(refresh_token, str) or not refresh_token.strip()
        ):
            raise TokenAuthenticationError("Token exchange returned an invalid refresh token")
        return access_token, lifetime, refresh_token
