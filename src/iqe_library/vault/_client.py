"""Lazy, instance-cached Vault KV v2 reads."""

from collections.abc import Mapping
from contextlib import suppress
from typing import Any

import hvac

from ._auth import authenticate
from ._http import create_session
from ._types import VaultAuthenticationError, VaultOptions, VaultReadError


def _create_client(options: VaultOptions) -> hvac.Client:
    session = create_session(options.verify, timeout=options.timeout)
    try:
        return hvac.Client(
            url=options.url,
            # None makes hvac consult VAULT_TOKEN and ~/.vault-token.
            token=options.token if options.token is not None else "",
            session=session,
            verify=options.verify,
            timeout=options.timeout,
        )
    except Exception:
        with suppress(Exception):
            session.close()
        raise VaultAuthenticationError("Vault client setup failed") from None


class VaultSecretFetcher:
    """Fetch native secret mappings, caching successful reads per instance/path."""

    def __init__(self, options: VaultOptions) -> None:
        self._options = options
        self._client: hvac.Client | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    def _authenticated_client(self) -> hvac.Client:
        if self._client is None:
            client = _create_client(self._options)
            try:
                authenticate(client, self._options)
            except BaseException:
                with suppress(Exception):
                    client.adapter.close()
                raise
            self._client = client

        client = self._client
        try:
            if not client.is_authenticated():
                authenticate(client, self._options)
                if not client.is_authenticated():
                    raise VaultAuthenticationError("Vault authentication rejected before read")
        except (VaultAuthenticationError, ImportError):
            raise
        except Exception:
            raise VaultAuthenticationError(
                "Vault authentication check failed before read"
            ) from None
        return client

    def get(self, path: str) -> dict[str, Any]:
        """Read a KV v2 path, or return its cached mapping without network access."""
        if path in self._cache:
            return self._cache[path]

        client = self._authenticated_client()
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._options.mount_point,
                raise_on_deleted_version=True,
            )
            data = response["data"]["data"]
            if not isinstance(data, Mapping):
                raise ValueError("Vault secret is not a mapping")
            secret = dict(data)
        except Exception:
            raise VaultReadError(
                f"Vault KV v2 read failed for path {path!r} at mount {self._options.mount_point!r}"
            ) from None
        self._cache[path] = secret
        return secret

    def get_value_from_vault(self, path: str, key: str) -> Any:
        """Return one native value, raising LookupError for an absent key."""
        secret = self.get(path)
        try:
            return secret[key]
        except KeyError:
            raise LookupError(f"Vault secret at path {path!r} has no key {key!r}") from None
