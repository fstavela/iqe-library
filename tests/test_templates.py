import json
from types import SimpleNamespace

import jinja2
import pytest
import yaml
from dynaconf import Dynaconf

from iqe_library.config import _loader, load_config


def test_jinja_uses_final_settings(config_file, monkeypatch):
    path = config_file(
        "default: {label: original, rendered: '@jinja {{ this.label }} / {{ main.label }}'}"
    )
    monkeypatch.setenv("DYNACONF_LABEL", "final")
    assert load_config(path).rendered == "final / final"


def test_explicit_template_context(config_file):
    path = config_file("default: {rendered: '@jinja {{ env_parser.hostname }} / {{ main.label }}'}")
    context = {
        "env_parser": SimpleNamespace(hostname="provided.invalid"),
        "main": {"label": "external"},
    }
    settings = load_config(path, template_context=context)
    context["main"] = {"label": "changed"}
    assert settings.rendered == "provided.invalid / external"


@pytest.mark.parametrize(
    "nested,template",
    [
        (False, "@jinja {{ env_parser.hostname }}"),
        (True, "@int @jinja {{ absent }}"),
        (True, "@format {this.absent}"),
    ],
)
def test_jinja_override_does_not_render_discarded_template(
    config_file, monkeypatch, nested, template
):
    shared = f"rendered: '{template}'"
    consumer = "rendered: local-value"
    if nested:
        shared, consumer = f"account: {{{shared}}}", f"account: {{{consumer}}}"
    shared_path = config_file(f"default: {{{shared}}}", "config.yaml")
    monkeypatch.setattr(_loader, "files", lambda _: shared_path.parent)
    settings = load_config(config_file(f"default: {{{consumer}}}"))
    assert (settings.account.rendered if nested else settings.rendered) == "local-value"


def test_context_isolation(config_file):
    path = config_file("default: {rendered: '@jinja {{ env_parser.hostname }}'}")
    first = load_config(path, template_context={"env_parser": SimpleNamespace(hostname="first")})
    second = load_config(path, template_context={"env_parser": SimpleNamespace(hostname="second")})
    assert first.rendered == "first"
    assert second.rendered == "second"
    assert first.rendered == "first"


@pytest.mark.parametrize("variable", ["DYNACONF_RENDERED", "DYNACONF_ACCOUNT__RENDERED"])
def test_jinja_env_override_uses_context(config_file, monkeypatch, variable):
    monkeypatch.setenv(variable, "@jinja {{ env_parser.hostname }}")
    path = config_file("default: {rendered: original, account: {rendered: original}}")
    settings = load_config(
        path, template_context={"env_parser": SimpleNamespace(hostname="provided.invalid")}
    )
    rendered = settings.account.rendered if "__" in variable else settings.rendered
    assert rendered == "provided.invalid"


def test_native_dynamic_values(config_file, monkeypatch):
    monkeypatch.setenv("DYNACONF_LABEL", "final")
    monkeypatch.setenv("DYNACONF_ENV_CASTED", "@int @jinja {{ extra.count }}")
    path = config_file("""
default:
  label: original
  formatted: '@format {this.label}'
  count: '@int 3'
  casted: '@int @jinja {{ this.count + 1 }}'
  contextual: '@int @jinja {{ extra.count }}'
""")
    settings = load_config(path, template_context={"extra": {"count": 7}})
    assert settings.formatted == "final"
    assert settings.count == 3
    assert settings.casted == 4
    assert type(settings.casted) is int
    assert settings.contextual == settings.env_casted == 7
    assert type(settings.contextual) is type(settings.env_casted) is int


@pytest.mark.parametrize(
    ("location", "raw", "expected"),
    [
        ("scalar", "@str @int 3", "@int 3"),
        ("mapping", '@str @json {"a": 1}', '@json {"a": 1}'),
        ("list", '@json "@int 3"', "@int 3"),
        ("list", "@str @merge [3]", "@merge [3]"),
        ("scalar", "@str 123", "123"),
        ("mapping", "@str @format {this.label}", "@int 3"),
    ],
)
def test_literal_converter_results_match_native(config_file, location, raw, expected):
    value = {"nested": raw} if location == "mapping" else [raw] if location == "list" else raw
    path = config_file(yaml.safe_dump({"default": {"value": value, "label": "@str @int 3"}}))
    native = Dynaconf(settings_files=[path], environments=True, env="stage", merge_enabled=True)
    settings = load_config(path)
    for loaded in (native, settings):
        result = loaded.value
        if location == "mapping":
            result = result.nested
        elif location == "list":
            result = result[0]
        assert result == expected
        assert type(result) is str


@pytest.mark.parametrize("directive", ["@insert 0", "@merge"])
def test_merge_marker_literal_results_match_native(config_file, directive):
    path = config_file(yaml.safe_dump({"default": {"value": f"{directive} @str @int 3"}}))
    native = Dynaconf(settings_files=[path], environments=True, env="stage", merge_enabled=True)
    assert native.value == ["@int 3"]
    assert load_config(path).value == native.value


def test_merge_marker_casted_jinja_uses_context(config_file):
    path = config_file("default: {value: '@merge [\"@int @jinja {{ main.count }}\"]'}")
    assert load_config(path, template_context={"main": {"count": 7}}).value == [7]


@pytest.mark.parametrize("source", ["yaml", "env"])
def test_decoded_container_jinja_uses_context(config_file, monkeypatch, source):
    encoded = "@json " + json.dumps(
        {
            "literal": "@str @int 3",
            "rendered": "@int @jinja {{ main.count }}",
            "nested": '@json {"sequence": ["@int @jinja {{ main.count }}"]}',
        }
    )
    if source == "env":
        monkeypatch.setenv("DYNACONF_ACCOUNT", encoded)
        path = config_file("default: {}")
    else:
        path = config_file(yaml.safe_dump({"default": {"account": encoded}}))
    settings = load_config(path, template_context={"main": {"count": 7}})
    assert settings.account.rendered == 7
    assert settings.account.literal == "@int 3"
    assert type(settings.account.literal) is str
    assert type(settings.account.rendered) is int
    assert settings.account.nested.sequence == [7]
    assert type(settings.account.nested.sequence[0]) is int


def test_decoded_container_jinja_preserves_merge_markers(config_file):
    path = config_file("""
default:
  account: {sequence: [1], retained: original}
stage:
  account: '@json {"rendered": "@int @jinja {{ main.count }}", "sequence": "@merge [2]"}'
""")
    settings = load_config(path, template_context={"main": {"count": 7}})
    assert settings.account.rendered == 7
    assert type(settings.account.rendered) is int
    assert settings.account.sequence == [1, 2]
    assert settings.account.retained == "original"


def test_jinja_nested_lists_and_env_merge(config_file, monkeypatch):
    path = config_file("""
default:
  sequence: ['@jinja {{ env_parser.hostname }}']
  account: {rendered: '@jinja {{ main.label }}'}
  label: original
stage:
  sequence: [literal]
""")
    monkeypatch.setenv("DYNACONF_SEQUENCE", '@merge ["@jinja {{ main.label }}"]')
    monkeypatch.setenv("DYNACONF_LABEL", "final")
    settings = load_config(
        path, template_context={"env_parser": SimpleNamespace(hostname="provided.invalid")}
    )
    # Keep Dynaconf's double top-level merge with MERGE_ENABLED enabled.
    assert settings.sequence == [
        "provided.invalid",
        "literal",
        "provided.invalid",
        "literal",
        "final",
    ]
    assert settings.account.rendered == "final"


def test_jinja_env_and_strict_missing_values(config_file, monkeypatch):
    monkeypatch.setenv("TEMPLATE_TEST_LABEL", "from-env")
    path = config_file("""
default:
  rendered: '@jinja {{ env.TEMPLATE_TEST_LABEL }}'
  missing: '@jinja {{ absent }}'
""")
    settings = load_config(path)
    assert settings.base_url == "https://console.stage.redhat.com"  # Missing names are lazy.
    assert settings.rendered == "from-env"
    with pytest.raises(jinja2.UndefinedError):
        _ = settings.missing


def test_native_dynaconf_is_unmodified(config_file):
    def native_behavior():
        native = Dynaconf(settings_files=[], rendered="@jinja {{ absent }}")
        assert native.rendered == ""
        with pytest.raises(yaml.constructor.ConstructorError, match="!from_vault"):
            yaml.safe_load("value: !from_vault {path: users/demo}")

    native_behavior()
    settings = load_config(
        config_file("default: {rendered: '@jinja {{ main.label }}'}"),
        template_context={"main": {"label": "provided"}},
    )
    assert settings.rendered == "provided"
    native_behavior()
