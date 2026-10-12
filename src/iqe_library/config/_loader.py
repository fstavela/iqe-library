"""Apply explicitly selected YAML sources using Dynaconf's native merge rules."""

import os
from collections.abc import Mapping
from copy import deepcopy
from importlib.resources import files
from pathlib import Path
from typing import Any, TextIO, cast

from dynaconf import default_settings
from dynaconf.base import Settings
from dynaconf.loaders import env_loader
from dynaconf.loaders.base import BaseLoader
from dynaconf.utils.files import get_local_filename

from iqe_library.config._ephemeral import ConfigEnvParser
from iqe_library.config._runtime import ConfigRuntime, normalize_lazy_values
from iqe_library.config.yaml import yaml_reader


def _read_shared_sources() -> list[tuple[str, dict[str, Any]]]:
    root = files("iqe_library.config")
    sources = []
    for name in ("config.yaml", "config.local.yaml"):
        resource = root.joinpath(name)
        if name == "config.local.yaml" and not resource.is_file():
            continue
        with resource.open("r", encoding="utf-8") as stream:
            sources.append((str(resource), yaml_reader(cast(TextIO, stream))))
    return sources


def _read_consumer_sources(path: Path) -> list[tuple[str, dict[str, Any]]]:
    paths = [path]
    if ".local." not in path.name:
        companion = Path(get_local_filename(str(path)))
        if companion.is_file():
            paths.append(companion)
    sources = []
    for source in paths:
        with source.open(encoding="utf-8") as stream:
            sources.append((str(source), yaml_reader(stream)))
    return sources


def load_config(
    local_config: str | Path | None = None,
    *,
    environment: str | None = None,
    template_context: Mapping[str, object] | None = None,
) -> Settings:
    """Load shared defaults, consumer YAML and local overlays, then env overrides.

    Environment selection is explicit argument, nonempty ``ENV_FOR_DYNACONF``,
    then ``stage``. No dotenv files or unrelated settings files are discovered.
    Vault and template values are evaluated only on access, after all sources.
    """
    if environment == "":
        raise ValueError("environment must not be empty")
    if template_context is not None and "this" in template_context:
        raise ValueError("template_context key 'this' is reserved for the settings instance")
    selected_env = (
        environment if environment is not None else os.getenv("ENV_FOR_DYNACONF") or "stage"
    )

    # Settings(skip_loaders=True) skips default initialization too. Seed the
    # defaults deliberately, without default_loader's dotenv/env discovery.
    defaults = {
        name: deepcopy(value) for name, value in vars(default_settings).items() if name.isupper()
    }
    defaults.update(
        ENVIRONMENTS_FOR_DYNACONF=True,
        ENV_FOR_DYNACONF=selected_env,
        FORCE_ENV_FOR_DYNACONF=selected_env,
        DEFAULT_ENV_FOR_DYNACONF="DEFAULT",
        ENVVAR_PREFIX_FOR_DYNACONF="DYNACONF",
        MERGE_ENABLED_FOR_DYNACONF=True,
        SETTINGS_FILE_FOR_DYNACONF=[],
        LOADERS_FOR_DYNACONF=[],
        CORE_LOADERS_FOR_DYNACONF=[],
        PRELOAD_FOR_DYNACONF=[],
        INCLUDES_FOR_DYNACONF=[],
        LOAD_DOTENV_FOR_DYNACONF=False,
    )
    settings = Settings(dynaconf_skip_loaders=True)
    runtime = ConfigRuntime(dict(template_context or {}))
    object.__setattr__(settings, "_config_runtime", runtime)
    object.__setattr__(settings, "_template_context", runtime.template_context)

    def prepare_values(data: dict[str, Any]) -> dict[str, Any]:
        # The native filter hook runs before source/env updates and their merge
        # comparisons. Parse while normalizing so decoded descendants are guarded
        # too, with native casts and merge markers retained.
        return cast(dict[str, Any], normalize_lazy_values(data, settings=settings))

    # BaseLoader reads the native attribute; env_loader reads the settings key.
    settings.filter_strategy = prepare_values
    defaults["FILTER_STRATEGY"] = prepare_values
    settings.update(defaults, loader_identifier="default_settings", validate=False)

    sources = _read_shared_sources()
    if local_config is not None:
        sources.extend(_read_consumer_sources(Path(local_config)))

    loader = BaseLoader(
        obj=settings,
        env=selected_env,
        identifier="config_yaml",
        extensions=(".yaml", ".yml"),
        file_reader=yaml_reader,
        string_reader=None,
    )
    for name, data in sources:
        # Dynaconf 3.2.13's private adapter preserves per-file default/dynaconf/
        # selected/global ordering and native directives, without file discovery.
        loader._load_all_envs({name: data}, silent=True)
        settings._loaded_files.append(name)
    env_loader.load(settings, silent=False)
    runtime.template_context.setdefault("env_parser", ConfigEnvParser(settings))
    runtime.loading = False
    return settings
