"""Prepare modern Insights archives without service or framework dependencies."""

import re
import tarfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from shutil import rmtree
from tempfile import TemporaryDirectory, mkdtemp
from uuid import uuid4

DEFAULT_ARCHIVE = "rhel94.tar.gz"

__all__ = ["DEFAULT_ARCHIVE", "HostArchiveData", "prepare_archive"]


@dataclass
class HostArchiveData:
    insights_id: str
    subscription_manager_id: str
    fqdn: str

    @classmethod
    def random(
        cls,
        fqdn_prefix: str = "test",
        *,
        insights_id: str | None = None,
        subscription_manager_id: str | None = None,
    ) -> "HostArchiveData":
        """Generate matching IDs unless both are explicitly supplied."""
        if insights_id is None:
            insights_id = (
                subscription_manager_id if subscription_manager_id is not None else str(uuid4())
            )
        if subscription_manager_id is None:
            subscription_manager_id = insights_id
        return cls(insights_id, subscription_manager_id, f"{fqdn_prefix}.{insights_id}")


def prepare_archive(
    host_data: HostArchiveData,
    source_archive: str | Path = DEFAULT_ARCHIVE,
) -> Path:
    """Copy a modern archive and replace its IDs and hostnames.

    A bare string selects a bundled archive; a Path or string with directory
    components selects a filesystem archive. The source is never modified.
    Only one enclosing directory containing data/ is supported.

    The result is archive.tar.gz in its own temporary directory. The caller
    owns deletion of that directory; extraction files are always cleaned up.
    System temporary-directory cleanup is a fallback, subject to OS policy.
    """
    source = (
        files("iqe_library").joinpath("data", "archives", source_archive)
        if isinstance(source_archive, str) and Path(source_archive).name == source_archive
        else Path(source_archive)
    )
    with source.open("rb") as source_file:
        work_dir = Path(mkdtemp())
        try:
            with TemporaryDirectory(dir=work_dir) as extraction_dir:
                with tarfile.open(fileobj=source_file, mode="r:gz") as archive:
                    archive.extractall(extraction_dir, filter="data")

                roots = list(Path(extraction_dir).iterdir())
                if len(roots) != 1 or not (roots[0] / "data").is_dir():
                    raise ValueError("Expected one enclosing archive directory containing data/")
                archive_dir = roots[0]
                data_dir = archive_dir / "data"

                identity_file = data_dir / "insights_commands/subscription-manager_identity"
                machine_id_file = data_dir / "etc/insights-client/machine-id"
                hostname_files = [
                    data_dir / "insights_commands" / name for name in ("hostname", "hostname_-f")
                ]
                for path in (identity_file, machine_id_file, *hostname_files):
                    linked_path = any(
                        part.is_symlink()
                        for part in (path, *path.parents)
                        if part.is_relative_to(archive_dir)
                    )
                    if linked_path or (path.is_file() and path.stat().st_nlink > 1):
                        raise ValueError(
                            f"Linked rewrite path is not supported: {path.relative_to(archive_dir)}"
                        )

                content = identity_file.read_text(encoding="utf-8")
                content, count = re.subn(
                    r"^system identity:.*$",
                    lambda match: f"system identity: {host_data.subscription_manager_id}",
                    content,
                    flags=re.MULTILINE,
                )
                if not count:
                    raise ValueError("subscription-manager_identity is missing system identity")
                content, count = re.subn(
                    r"^name:.*$",
                    lambda match: f"name: {host_data.fqdn}",
                    content,
                    flags=re.MULTILINE,
                )
                if not count:
                    content += (
                        "" if content.endswith("\n") else "\n"
                    ) + f"name: {host_data.fqdn}\n"
                identity_file.write_text(content, encoding="utf-8")

                machine_id_file.write_text(host_data.insights_id, encoding="utf-8")
                for hostname_file in hostname_files:
                    hostname_file.write_text(host_data.fqdn, encoding="utf-8")

                result = work_dir / "archive.tar.gz"
                with tarfile.open(result, "w:gz") as archive:
                    archive.add(archive_dir, arcname=archive_dir.name)
            return result
        except BaseException:
            rmtree(work_dir)
            raise
