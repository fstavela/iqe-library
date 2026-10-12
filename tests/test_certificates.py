"""Offline certificate ownership, privacy, and file-permission contracts."""

import os
import stat
import tempfile
import traceback
from pathlib import Path

import pytest

from iqe_library.auth import CertificateAuth, certificate_files

CERT_PEM = "-----BEGIN CERTIFICATE-----\ncert-pem-sentinel\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nkey-pem-sentinel\n-----END PRIVATE KEY-----\n"


def test_pem_context_permissions_and_exit_cleanup():
    with certificate_files(CERT_PEM, KEY_PEM) as (cert_path, key_path):
        assert isinstance(cert_path, str)
        assert isinstance(key_path, str)
        cert, key = Path(cert_path), Path(key_path)
        directory = cert.parent
        assert directory.name.startswith("test-cert-")
        assert key.parent == directory
        assert cert != key
        assert cert.read_text(encoding="utf-8") == CERT_PEM
        assert key.read_text(encoding="utf-8") == KEY_PEM
        if os.name == "posix":
            assert stat.S_IMODE(cert.stat().st_mode) == 0o600
            assert stat.S_IMODE(key.stat().st_mode) == 0o600
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert not cert.exists()
    assert not key.exists()
    assert not directory.exists()


def test_pem_context_cleans_up_when_caller_raises():
    error = RuntimeError("caller failure")
    with (
        pytest.raises(RuntimeError) as caught,
        certificate_files(CERT_PEM, KEY_PEM) as (cert_path, key_path),
    ):
        raise error
    assert caught.value is error
    assert not Path(cert_path).parent.exists()
    assert not Path(key_path).exists()


def test_pem_partial_write_cleanup(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    write_text = Path.write_text
    written = []

    def fail_second_write(path, contents, *args, **kwargs):
        written.append(path)
        write_text(path, contents, *args, **kwargs)
        if len(written) == 2:
            raise OSError("cert-pem-sentinel key-pem-sentinel")

    monkeypatch.setattr(Path, "write_text", fail_second_write)
    with pytest.raises(RuntimeError) as error, certificate_files(CERT_PEM, KEY_PEM):
        pytest.fail("a failed write must not yield certificate paths")
    assert len(written) == 2
    assert not list(tmp_path.iterdir())
    assert all(not path.exists() for path in written)
    message = "".join(traceback.format_exception(error.value)) + caplog.text
    assert "cert-pem-sentinel" not in message
    assert "key-pem-sentinel" not in message


def test_certificate_descriptions_are_lazy_and_private(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    cert = tmp_path / "caller-cert.pem"
    cert.write_text(CERT_PEM)
    before = set(tmp_path.iterdir())
    descriptions = [CertificateAuth.from_pem(CERT_PEM, KEY_PEM), CertificateAuth.from_files(cert)]
    assert set(tmp_path.iterdir()) == before
    for description in descriptions:
        assert "cert-pem-sentinel" not in repr(description)
        assert "key-pem-sentinel" not in repr(description)


@pytest.mark.parametrize(
    "field,value", [("cert_pem", None), ("cert_pem", ""), ("key_pem", 1), ("key_pem", " \n")]
)
@pytest.mark.parametrize("description", [False, True])
def test_pem_inputs_are_validated_locally(field, value, description):
    values = {"cert_pem": CERT_PEM, "key_pem": KEY_PEM, field: value}
    factory = CertificateAuth.from_pem if description else certificate_files
    with pytest.raises(ValueError) as error:
        result = factory(**values)
        if not description:
            with result:
                pytest.fail("invalid PEM inputs must not yield paths")
    assert field in str(error.value)
    assert "pem-sentinel" not in str(error.value)


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("cert_path", "missing"),
        ("key_path", "empty"),
        ("cert_path", "directory"),
        ("cert_path", "blank"),
        ("key_path", "wrong-type"),
    ],
)
def test_file_inputs_are_validated_locally(tmp_path, field, invalid):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text(CERT_PEM)
    key.write_text(KEY_PEM)
    empty = tmp_path / "empty.pem"
    empty.touch()
    value = {
        "missing": tmp_path / "missing.pem",
        "empty": empty,
        "directory": tmp_path,
        "blank": " ",
        "wrong-type": 1,
    }[invalid]
    with pytest.raises(ValueError) as error:
        CertificateAuth.from_files(**{"cert_path": cert, "key_path": key, field: value})
    assert field in str(error.value)
    assert "pem-sentinel" not in str(error.value)


def test_key_only_input_is_rejected(tmp_path):
    key = tmp_path / "key.pem"
    key.write_text(KEY_PEM)
    with pytest.raises(ValueError, match="cert_path"):
        CertificateAuth.from_files(cert_path=None, key_path=key)
