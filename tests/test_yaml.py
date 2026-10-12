from io import StringIO

import pytest
import yaml
from yaml.constructor import ConstructorError

from iqe_library.config.references import VaultReference
from iqe_library.config.yaml import yaml_reader


def test_vault_reference_fields():
    data = yaml_reader(StringIO("stage: {password: !from_vault {path: users/demo, key: password}}"))
    ref = data["stage"]["password"]
    assert isinstance(ref, VaultReference)
    assert (ref.path, ref.key) == ("users/demo", "password")


def test_whole_secret_reference():
    data = yaml_reader(StringIO("stage: {account: !from_vault {path: users/demo}}"))
    assert data["stage"]["account"].key is None


def test_ordinary_values_and_anchors():
    data = yaml_reader(
        StringIO("default: &base {enabled: true, count: 2, empty: null}\nstage: *base")
    )
    assert data["stage"] == {"enabled": True, "count": 2, "empty": None}


def test_yaml_merge_keys_and_lists():
    data = yaml_reader(
        StringIO(
            "default: &base {enabled: true, names: [alice, bob]}\n"
            "stage: {<<: *base, enabled: false}"
        )
    )
    assert data["stage"] == {"enabled": False, "names": ["alice", "bob"]}


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ("{}", "path"),
        ("{path: ''}", "path"),
        ("{path: null}", "path"),
        ("{path: 3}", "path"),
        ("{path: [users/demo]}", "path"),
        ("{path: users/demo, key: ''}", "key"),
        ("{path: users/demo, key: 3}", "key"),
        ("{path: users/demo, key: null}", "key"),
        ("users/demo", "scalar"),
        ("[users/demo]", "sequence"),
        ("{path: users/demo, other: password}", "other"),
    ],
)
def test_invalid_reference(body, field):
    stream = StringIO(f"stage: {{password: !from_vault {body}}}")
    stream.name = "invalid-reference.yaml"
    with pytest.raises((ValueError, ConstructorError), match=field) as error:
        yaml_reader(stream)
    assert "invalid-reference.yaml" in str(error.value)


@pytest.mark.parametrize("tag", ["!credential", "!template", "!from_template"])
def test_unknown_tag(tag):
    with pytest.raises(ConstructorError, match=tag):
        yaml_reader(StringIO(f"stage: {{value: {tag} {{name: demo}}}}"))


def test_legacy_forms_are_ordinary_data():
    data = yaml_reader(
        StringIO(
            "stage:\n"
            "  mapping: {from_vault: {path: users/demo, key: password}}\n"
            "  vault_mapping: {vault: {path: users/demo, key: password}}\n"
            "  string: vault:users/demo#password\n"
        )
    )
    assert data["stage"]["mapping"] == {"from_vault": {"path": "users/demo", "key": "password"}}
    assert data["stage"]["vault_mapping"] == {"vault": {"path": "users/demo", "key": "password"}}
    assert data["stage"]["string"] == "vault:users/demo#password"


def test_empty_document():
    assert yaml_reader(StringIO("")) == {}


@pytest.mark.parametrize("text", ["[one, two]", "scalar", "false", "3", "null"])
def test_nonmapping_document(text):
    stream = StringIO(text)
    stream.name = "nonmapping.yaml"
    with pytest.raises(ValueError, match=r"nonmapping\.yaml"):
        yaml_reader(stream)


def test_safe_loader_is_not_modified():
    yaml_reader(StringIO("stage: {account: !from_vault {path: users/demo}}"))
    with pytest.raises(ConstructorError, match="!from_vault"):
        yaml.safe_load("stage: {account: !from_vault {path: users/demo}}")
