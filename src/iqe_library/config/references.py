"""References parsed from configuration without fetching secrets."""

from dataclasses import dataclass
from typing import Any, ClassVar

from dynaconf.base import Settings

from iqe_library.config._runtime import get_runtime


@dataclass(frozen=True)
class VaultReference:
    """A Vault secret path and, optionally, a key within that secret."""

    path: str
    key: str | None = None
    _dynaconf_lazy_format: ClassVar[bool] = True

    def __call__(self, settings: Settings) -> Any:
        runtime = get_runtime(settings)
        if runtime.loading:
            return self
        fetcher = runtime.get_fetcher(settings)
        if self.key is None:
            return fetcher.get(self.path)
        return fetcher.get_value_from_vault(self.path, self.key)
