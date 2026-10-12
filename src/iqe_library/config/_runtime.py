"""Per-settings lazy evaluation, without changing Dynaconf's global converters."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Self, cast

from dynaconf.base import Settings
from dynaconf.utils.boxing import DynaBox
from dynaconf.utils.parse_conf import Lazy, MetaValue, parse_conf_data
from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

from iqe_library.vault import VaultOptions, VaultSecretFetcher


def _template_environment() -> SandboxedEnvironment:
    environment = SandboxedEnvironment(undefined=StrictUndefined)
    # Match Dynaconf's documented path filters, on our own environment only.
    for name in ("abspath", "realpath", "relpath", "dirname", "basename"):
        environment.filters[name] = getattr(os.path, name)
    return environment


@dataclass
class ConfigRuntime:
    """State owned by one loaded Settings object, outside its configuration keys."""

    template_context: Mapping[str, object]
    loading: bool = True
    _fetcher: VaultSecretFetcher | None = None
    jinja: SandboxedEnvironment = field(default_factory=_template_environment)

    def __post_init__(self) -> None:
        self.template_context = dict(self.template_context)

    def get_fetcher(self, settings: Settings) -> VaultSecretFetcher:
        if self._fetcher is None:
            self._fetcher = VaultSecretFetcher(VaultOptions.from_mapping(settings.vault))
        return self._fetcher


def get_runtime(settings: Settings) -> ConfigRuntime:
    # Bypass Settings' routing of attribute access through configuration keys.
    return cast(ConfigRuntime, object.__getattribute__(settings, "_config_runtime"))


@dataclass(frozen=True)
class _JinjaValue:
    value: str
    _dynaconf_lazy_format: ClassVar[bool] = True

    def __call__(self, settings: Settings) -> str | Self:
        runtime = get_runtime(settings)
        if runtime.loading:
            return self
        context = {"env": os.environ, "this": settings, "main": settings}
        context.update(runtime.template_context)
        return runtime.jinja.from_string(self.value).render(context)


@dataclass(frozen=True)
class _DeferredValue:
    """Keep native dynamic values/casts lazy even during Dynaconf comparisons."""

    value: Lazy
    _dynaconf_lazy_format: ClassVar[bool] = True

    def __call__(self, settings: Settings) -> Any:
        if get_runtime(settings).loading:
            return self
        if self.value.formatter.token == "jinja":
            result = _JinjaValue(self.value.value)(settings)
            return self.value.casting(result) if self.value.casting is not None else result
        return self.value(settings)


def normalize_lazy_values(value: Any, *, settings: Settings | None = None) -> Any:
    """Normalize YAML strings and parsed env values before native merging."""
    if isinstance(value, str):
        if settings is not None:
            # Parse each string before descending: @json can expose more dynamic
            # strings in a new container that Dynaconf's parser doesn't revisit.
            parsed = parse_conf_data(value, box_settings=settings)
            if isinstance(parsed, str):
                # Settings.set still parses scalars. Keep the original syntax so
                # a converter's literal result (e.g. @str @int 3) isn't reparsed.
                return value
            value = parsed
        elif value.startswith("@jinja "):
            return _JinjaValue(value.removeprefix("@jinja "))
        elif value.startswith("@format ") or value.partition(" ")[2].startswith(
            ("@jinja ", "@format ")
        ):
            # Only deferred expressions need guarding in already-parsed marker
            # payloads. Leave their literal scalar results alone.
            value = parse_conf_data(value)
    if isinstance(value, Lazy):
        if value.formatter.token == "jinja" and value.casting is None:
            return _JinjaValue(value.value)
        return _DeferredValue(value)
    if isinstance(value, MetaValue):
        # Preserve @merge/@reset/@insert themselves and let Dynaconf apply them.
        value.value = normalize_lazy_values(value.value)
    elif isinstance(value, dict):
        items = value.items(bypass_eval=True) if isinstance(value, DynaBox) else value.items()
        for key, item in items:
            value[key] = normalize_lazy_values(item, settings=settings)
    elif isinstance(value, list):
        return [normalize_lazy_values(item, settings=settings) for item in value]
    return value
