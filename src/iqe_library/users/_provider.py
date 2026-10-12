"""Ensure users in Keycloak without touching RBAC groups or roles."""

import logging
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Self

from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError

from ._payload import _string, user_payload

logger = logging.getLogger(__name__)


class UserProvisioningError(RuntimeError):
    """Keycloak provisioning failed, without exposing credentials or upstream bodies."""


class UserProvider:
    """Use an existing KeycloakAdmin client, owned and configured by the caller.

    No discovery, environment selection, or requests occur during construction.
    Closing this provider does not close an injected client's connections.
    """

    def __init__(self, keycloak_admin: KeycloakAdmin) -> None:
        self.keycloak_admin = keycloak_admin
        self._owns_client = False
        self._closed = False

    def _existing_user(self, username: str) -> dict[str, Any] | None:
        # Even if a client ignores exact=True, never modify a substring match.
        matches = [
            user
            for user in self.keycloak_admin.get_users({"username": username, "exact": True})
            if user.get("username", "").casefold() == username.casefold()
        ]
        if len(matches) > 1:
            raise UserProvisioningError(f"Multiple exact matches for Keycloak user {username!r}")
        return matches[0] if matches else None

    def ensure_user(
        self,
        *,
        username: str,
        password: str,
        attributes: Mapping[str, Any],
        entitlements: Mapping[str, Any],
        recreate: bool = False,
    ) -> str:
        """Create a missing user or update one in place; return the Keycloak UUID.

        With recreate=True, delete the exact-match user and create it again.
        Coordinating other runs using that user is the consumer's responsibility.
        All inputs are validated before any deletion. No config is mutated.
        """
        if self._closed:
            raise RuntimeError("UserProvider is closed")
        if not isinstance(recreate, bool):
            raise ValueError("recreate must be a boolean")
        _string(password, "password")
        payload = user_payload(username, attributes, entitlements)
        try:
            existing = self._existing_user(username)
            if existing is not None and not recreate:
                previous = existing.get("attributes", {}).get("user_id")
                previous = previous[0] if isinstance(previous, list) and previous else previous
                if previous and previous != attributes["user_id"]:
                    raise ValueError(
                        f"User {username!r} already has a different Insights user_id; "
                        "reuse that user_id, select another username, or explicitly recreate"
                    )
                user_id = _string(existing.get("id"), "existing Keycloak id")
                # Preserve unrelated consumer-owned attributes on reuse.
                payload["attributes"] = {
                    **existing.get("attributes", {}),
                    **payload["attributes"],
                }
                self.keycloak_admin.update_user(user_id, payload)
            else:
                if existing is not None:
                    self.keycloak_admin.delete_user(
                        _string(existing.get("id"), "existing Keycloak id")
                    )
                user_id = self.keycloak_admin.create_user(payload)
            # Passwords are write-only; set explicitly on both creation and reuse.
            self.keycloak_admin.set_user_password(user_id, password, temporary=False)
        except KeycloakError:
            raise UserProvisioningError(f"Could not provision Keycloak user {username!r}") from None
        logger.info("Provisioned Keycloak user %s (recreate=%s)", username, recreate)
        return _string(user_id, "Keycloak id")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_client:
            connection = self.keycloak_admin.connection
            # python-keycloak 5 has no public synchronous close method. Its
            # destructor closes _s too; also close the lazily created token session.
            connection._s.close()
            if connection._keycloak_openid is not None:
                connection._keycloak_openid.connection._s.close()

    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("UserProvider is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def create_user_provider(
    *,
    server_url: str,
    username: str,
    password: str,
    realm_name: str = "redhat-external",
    user_realm_name: str = "master",
    verify: bool | str = True,
    timeout: int = 30,
) -> UserProvider:
    """Create an owned, lazy Keycloak client; use the provider as a context manager.

    These are admin login credentials, not the credentials of a user to provision.
    TLS and HTTP behavior use python-keycloak's transport, without API logging hooks.
    """
    for name, value in (
        ("server_url", server_url),
        ("username", username),
        ("password", password),
        ("realm_name", realm_name),
        ("user_realm_name", user_realm_name),
    ):
        _string(value, name)
    if not isinstance(verify, (bool, str)) or (isinstance(verify, str) and not verify.strip()):
        raise ValueError("verify must be a boolean or a nonempty CA path")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("timeout must be a positive integer")
    try:
        admin = KeycloakAdmin(
            server_url=server_url.rstrip("/") + "/",
            username=username,
            password=password,
            realm_name=realm_name,
            user_realm_name=user_realm_name,
            verify=verify,
            timeout=timeout,
            max_retries=0,
        )
    except Exception:
        raise UserProvisioningError("Could not initialize Keycloak admin client") from None
    provider = UserProvider(admin)
    provider._owns_client = True
    return provider
