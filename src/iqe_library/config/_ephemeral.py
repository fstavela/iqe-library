"""Bind a lazy template object to the final settings without importing OpenShift tools."""

from collections.abc import Mapping
from functools import cached_property
from typing import TYPE_CHECKING

from dynaconf.base import Settings

if TYPE_CHECKING:
    from iqe_library.ephemeral import EphemeralEnvParser


class ConfigEnvParser:
    def __init__(self, settings: Settings) -> None:
        from iqe_library.ephemeral import EphemeralEnvParser

        self._settings = settings
        self._fallback = EphemeralEnvParser()

    @cached_property
    def _parser(self) -> "EphemeralEnvParser":
        from iqe_library.ephemeral import EphemeralEnvParser

        options = self._settings.get("ephemeral", {})
        if not isinstance(options, Mapping):
            raise ValueError("ephemeral must be a mapping")
        # Final config (including DYNACONF_EPHEMERAL__NAMESPACE) wins over the
        # NAMESPACE snapshot. Neither loading nor unrelated templates call oc.
        namespace = options.get("namespace")
        return self._fallback if namespace is None else EphemeralEnvParser(namespace=namespace)

    @property
    def namespace(self) -> str:
        return self._parser.namespace

    @property
    def env_hostname(self) -> str:
        return self._parser.env_hostname

    @property
    def sso_url(self) -> str:
        return self._parser.sso_url

    @property
    def sso_admin_username(self) -> str:
        return self._parser.sso_admin_username

    @property
    def sso_admin_password(self) -> str:
        return self._parser.sso_admin_password
