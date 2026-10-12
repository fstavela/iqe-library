"""Standalone Vault utilities; configuration-framework dependencies are not required."""

from ._client import VaultSecretFetcher
from ._types import VaultAuthenticationError, VaultOptions, VaultReadError

__all__ = ["VaultAuthenticationError", "VaultOptions", "VaultReadError", "VaultSecretFetcher"]
