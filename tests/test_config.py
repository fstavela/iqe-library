import os
from contextlib import nullcontext

import pytest
import yaml
from dynaconf.base import Settings

from iqe_library.config import _loader, load_config
from iqe_library.config.references import VaultReference


def test_shared_defaults_and_environment():
    settings = load_config()
    assert isinstance(settings, Settings)
    assert settings.current_env.lower() == "stage"
    assert settings.base_url == "https://console.stage.redhat.com"
    assert settings.http.proxy == "http://squid.corp.redhat.com:3128"
    assert settings.get("proxy") is None
    assert settings.vault.mount_point == "insights"


def test_consumer_default_overrides_shared_environment(config_file):
    path = config_file("default: {base_url: 'https://consumer.invalid', vault: {verify: false}}")
    settings = load_config(path, environment="stage")
    assert settings.base_url == "https://consumer.invalid"
    assert settings.vault.verify is False
    assert settings.vault.mount_point == "insights"


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ("stage", "https://cert.console.stage.redhat.com"),
        ("prod", "https://cert.console.redhat.com"),
    ],
)
def test_certificate_base_url_defaults(environment, expected):
    assert load_config(environment=environment).cert_base_url == expected


def test_consumer_certificate_base_url_override(config_file, monkeypatch):
    path = config_file("default: {cert_base_url: 'https://client-cert.invalid'}")
    settings = load_config(path, environment="stage")
    assert settings.cert_base_url == "https://client-cert.invalid"
    assert settings.base_url == "https://console.stage.redhat.com"
    monkeypatch.setenv("DYNACONF_CERT_BASE_URL", "https://override-cert.invalid")
    assert load_config(path, environment="stage").cert_base_url == "https://override-cert.invalid"


def test_environment_argument_and_nested_override(monkeypatch):
    monkeypatch.setenv("ENV_FOR_DYNACONF", "prod")
    monkeypatch.setenv("DYNACONF_VAULT__TIMEOUT", "7")
    assert load_config().base_url == "https://console.redhat.com"
    settings = load_config(environment="stage")
    assert settings.base_url == "https://console.stage.redhat.com"
    assert settings.vault.timeout == 7
    assert os.environ["ENV_FOR_DYNACONF"] == "prod"


def test_consumer_environment_wins(config_file, monkeypatch):
    path = config_file(
        "default: {base_url: 'https://default.invalid'}\nstage: {base_url: 'https://stage.invalid'}"
    )
    assert load_config(path).base_url == "https://stage.invalid"
    monkeypatch.setenv("DYNACONF_BASE_URL", "https://override.invalid")
    assert load_config(path).base_url == "https://override.invalid"


def test_global_order(config_file, monkeypatch):
    monkeypatch.setattr(
        _loader, "_read_shared_sources", lambda: [("shared.yaml", {"global": {"value": 1}})]
    )
    path = config_file("default: {value: 2}\nglobal: {value: 3}")
    assert load_config(path).value == 3
    path = config_file("default: {value: 2}")
    assert load_config(path).value == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("default: {value: 1}\ndynaconf: {value: 2}", 2),
        ("default: {value: 1}\ndynaconf: {value: 2}\nstage: {value: 3}", 3),
        ("dynaconf: {value: 2}\nstage: {value: 3}\nglobal: {value: 4}", 4),
    ],
)
def test_native_section_order(config_file, text, expected):
    assert load_config(config_file(text)).value == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "default: {value: {numbers: [1, 2]}}\nstage: {value: {numbers: [3]}}",
            {"numbers": [1, 2, 3]},
        ),
        (
            'default: {value: {numbers: [1, 2]}}\nstage: {value: {numbers: "@reset [3]"}}',
            {"numbers": [3]},
        ),
        ('default: {value: {keep: 1, remove: 2}}\nstage: {value: {remove: "@del"}}', {"keep": 1}),
        (
            "default: {value: {old: 1, nested: {keep: 2}}}\n"
            "stage: {value: {dynaconf_merge: false, new: 3}}",
            {"new": 3},
        ),
    ],
)
def test_native_merge_directives(config_file, text, expected):
    warning = (
        pytest.warns(UserWarning, match="does not need `@reset` anymore")
        if "@reset" in text
        else nullcontext()
    )
    with warning:
        assert load_config(config_file(text)).value == expected


def test_local_companions(config_file, monkeypatch):
    path = config_file("default: {value: 1}\nstage: {value: 2}")
    assert load_config(path).value == 2  # Missing companion is optional.
    local = config_file("default: {value: 3}", "consumer.local.yaml")
    assert load_config(path).value == 3
    config_file("default: {value: 3}\nstage: {value: 4}", "consumer.local.yaml")
    assert load_config(path).value == 4
    config_file("stage: {value: 5}", "consumer.local.local.yaml")
    assert load_config(local).value == 4
    monkeypatch.setenv("DYNACONF_VALUE", "6")
    assert load_config(path).value == 6


def test_shared_local_precedes_consumer(config_file, monkeypatch):
    def shared_sources():
        return [
            ("shared.yaml", {"stage": {"value": {"base": 1, "base_only": 2}}}),
            ("shared.local.yaml", {"default": {"value": {"overlay": 3, "local_only": 4}}}),
        ]

    monkeypatch.setattr(_loader, "_read_shared_sources", shared_sources)
    path = config_file("default: {value: {base: 5, overlay: 6}}")
    assert load_config(path).value == {"base": 5, "base_only": 2, "overlay": 6, "local_only": 4}


def test_source_isolation(config_file, monkeypatch):
    path = config_file("stage: {value: selected}")
    config_file("stage: {value: unrelated}", "settings.yaml")
    config_file("stage: {value: secret}", ".secrets.yaml")
    config_file("DYNACONF_VALUE=dotenv\nDOTENV_TEST_SENTINEL=changed\n", ".env")
    monkeypatch.delenv("DOTENV_TEST_SENTINEL", raising=False)
    monkeypatch.chdir(path.parent)
    before = dict(os.environ)
    assert load_config(path.name).value == "selected"
    assert dict(os.environ) == before
    assert load_config().get("value") is None


def test_configured_includes_are_not_discovered(config_file, monkeypatch):
    included = config_file("stage: {value: included}", "included.yaml")
    path = config_file(f"default: {{dynaconf_include: ['{included}']}}\nstage: {{value: selected}}")
    monkeypatch.setenv("SETTINGS_FILE_FOR_DYNACONF", str(included))
    monkeypatch.setenv("INCLUDES_FOR_DYNACONF", f'["{included}"]')
    monkeypatch.setenv("LOAD_DOTENV_FOR_DYNACONF", "true")
    assert load_config(path).value == "selected"


def test_environment_per_call(config_file):
    path = config_file("stage: {stage_only: 1}\nprod: {prod_only: 2}")
    stage = load_config(path, environment="stage")
    prod = load_config(path, environment="prod")
    assert stage.current_env.lower() == "stage"
    assert stage.base_url == "https://console.stage.redhat.com"
    assert stage.get("prod_only") is None
    assert prod.current_env.lower() == "prod"
    assert prod.base_url == "https://console.redhat.com"
    assert prod.get("stage_only") is None
    assert load_config(path, environment="StAgE").stage_only == 1
    both = load_config(path, environment="StAgE,PrOd")
    assert both.base_url == "https://console.redhat.com"
    assert both.stage_only == 1
    assert both.prod_only == 2


def test_empty_environment_variable_falls_back(monkeypatch):
    monkeypatch.setenv("ENV_FOR_DYNACONF", "")
    assert load_config().current_env.lower() == "stage"


def test_defaults_only_and_consumer_environment(config_file):
    path = config_file("default: {value: 1}\nconsumer: {value: 2}")
    assert load_config(path, environment="consumer").value == 2
    assert load_config(path, environment="absent").value == 1
    path = config_file("default: {value: 3}")
    assert load_config(path).value == 3


def test_invalid_inputs(config_file, tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")
    with pytest.raises(yaml.YAMLError):
        load_config(config_file("stage: ["))
    with pytest.raises(ValueError, match="environment"):
        load_config(environment="")
    with pytest.raises(ValueError, match="this"):
        load_config(template_context={"this": object()})


def test_vault_reference_survives_loading(config_file):
    settings = load_config(
        config_file("stage: {password: !from_vault {path: users/demo, key: password}}")
    )
    reference = settings.store.get("PASSWORD", bypass_eval=True)
    assert isinstance(reference, VaultReference)
    assert (reference.path, reference.key) == ("users/demo", "password")
