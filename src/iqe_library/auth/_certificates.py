"""Lazy certificate descriptions and explicitly owned temporary PEM files."""

import os
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory


def _validate_pem(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty PEM string")


def _validate_path(value: object, name: str) -> str:
    if not isinstance(value, (str, Path)) or (isinstance(value, str) and not value.strip()):
        raise ValueError(f"{name} must name an existing nonempty file")
    path = Path(value)
    try:
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError(f"{name} must name an existing nonempty file") from None
    return str(path)


@contextmanager
def certificate_files(cert_pem: str, key_pem: str) -> Iterator[tuple[str, str]]:
    """Yield private PEM paths, deleting them on exit or partial creation failure.

    Keep this context open until all connections using the paths are closed.
    PEM contents are not parsed or included in materialization errors.
    """
    _validate_pem(cert_pem, "cert_pem")
    _validate_pem(key_pem, "key_pem")
    with ExitStack() as stack:
        try:
            directory = Path(stack.enter_context(TemporaryDirectory(prefix="test-cert-")))
            if os.name == "posix":
                directory.chmod(0o700)
            cert_path, key_path = directory / "cert.pem", directory / "key.pem"
            for path, pem in ((cert_path, cert_pem), (key_path, key_pem)):
                path.touch(mode=0o600, exist_ok=False)
                if os.name == "posix":
                    path.chmod(0o600)
                path.write_text(pem, encoding="utf-8")
        except OSError:
            raise RuntimeError("Could not create temporary certificate files") from None
        yield str(cert_path), str(key_path)


@dataclass(frozen=True, kw_only=True)
class CertificateAuth:
    """Describe caller-owned paths or PEM contents without creating resources."""

    _files: str | tuple[str, str] | None = field(repr=False)
    _pem: tuple[str, str] | None = field(repr=False)

    @classmethod
    def from_files(
        cls, cert_path: str | Path, key_path: str | Path | None = None
    ) -> "CertificateAuth":
        """Use existing split or combined files, which remain caller-owned."""
        cert = _validate_path(cert_path, "cert_path")
        files = cert if key_path is None else (cert, _validate_path(key_path, "key_path"))
        return cls(_files=files, _pem=None)

    @classmethod
    def from_pem(cls, cert_pem: str, key_pem: str) -> "CertificateAuth":
        """Snapshot nonempty PEM strings; materialize only when a consumer asks."""
        _validate_pem(cert_pem, "cert_pem")
        _validate_pem(key_pem, "key_pem")
        return cls(_files=None, _pem=(cert_pem, key_pem))

    def _materialize(self, stack: ExitStack) -> str | tuple[str, str]:
        """Register owned PEM files with the consumer's resource stack."""
        if self._files is not None:
            return self._files
        if self._pem is not None:
            return stack.enter_context(certificate_files(*self._pem))
        raise ValueError("certificate inputs are required")
