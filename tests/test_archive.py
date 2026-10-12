"""Offline contracts for the minimal modern Insights archive builder."""

import io
import posixpath
import tarfile
import tempfile
from pathlib import Path
from uuid import UUID

import pytest

from iqe_library import archive as archive_module

_SOURCE_FILES = {
    "collected/data/etc/insights-client/machine-id": b"original-insights-id\n",
    "collected/data/etc/machine-id": b"original-os-machine-id\n",
    "collected/data/insights_commands/hostname": b"original-host\n",
    "collected/data/insights_commands/hostname_-f": b"original-host.example\n",
    "collected/data/insights_commands/subscription-manager_identity": (
        b"system identity: original-subscription-id\n"
        b"name: original-host.example\norg name: Example\norg ID: 123\n"
    ),
    "collected/data/sys/class/net/eth0/address": b"aa:bb:cc:dd:ee:ff\n",
    "collected/meta_data/example.json": b'{"unchanged": true}\n',
    "collected/data/binary": b"\x00\xff\xfebinary",
}


def _write_archive(path, contents, links=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for name, value in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        for member in links:
            archive.addfile(member)
    return path


def _read_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        return {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile()
        }


@pytest.fixture
def work_root(tmp_path, monkeypatch):
    root = tmp_path / "work"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def source_archive(tmp_path):
    return _write_archive(tmp_path / "inputs" / "custom.tar.gz", _SOURCE_FILES)


@pytest.fixture
def host_data():
    return archive_module.HostArchiveData("new-insights-id", "new-subscription-id", "new.example")


def test_random_host_data_uses_one_unique_id():
    from iqe_library.archive import HostArchiveData

    first = HostArchiveData.random()
    second = HostArchiveData.random()

    assert str(UUID(first.insights_id)) == first.insights_id
    assert first.subscription_manager_id == first.insights_id
    assert first.fqdn == f"test.{first.insights_id}"
    assert second.insights_id != first.insights_id


@pytest.mark.parametrize(
    "insights_id,subscription_manager_id,expected_insights,expected_subscription",
    [
        ("insights-id", None, "insights-id", "insights-id"),
        (None, "subscription-id", "subscription-id", "subscription-id"),
        ("insights-id", "subscription-id", "insights-id", "subscription-id"),
        ("", "subscription-id", "", "subscription-id"),
    ],
)
def test_random_host_data_preserves_explicit_ids(
    insights_id, subscription_manager_id, expected_insights, expected_subscription
):
    from iqe_library.archive import HostArchiveData

    data = HostArchiveData.random(
        "consumer", insights_id=insights_id, subscription_manager_id=subscription_manager_id
    )

    assert data.insights_id == expected_insights
    assert data.subscription_manager_id == expected_subscription
    assert data.fqdn == f"consumer.{expected_insights}"


def test_prepare_default_archive(host_data, work_root):
    result = archive_module.prepare_archive(host_data)
    assert isinstance(result, Path)
    contents = _read_archive(result)

    def value(relative_path):
        matches = [value for name, value in contents.items() if name.endswith(relative_path)]
        assert len(matches) == 1
        return matches[0]

    assert value("/data/etc/insights-client/machine-id") == b"new-insights-id"
    assert value("/data/insights_commands/hostname") == b"new.example"
    assert value("/data/insights_commands/hostname_-f") == b"new.example"
    identity = value("/data/insights_commands/subscription-manager_identity")
    assert b"system identity: new-subscription-id\n" in identity
    assert b"name: new.example\n" in identity
    assert b"org name: 17401227\norg ID: 17401227" in identity


@pytest.mark.parametrize("kind", ["path", "absolute-string", "relative-string"])
def test_prepare_external_archive(
    kind, source_archive, host_data, work_root, tmp_path, monkeypatch
):
    source = source_archive
    if kind == "absolute-string":
        source = str(source_archive)
    elif kind == "relative-string":
        monkeypatch.chdir(tmp_path)
        source = "inputs/custom.tar.gz"

    original = source_archive.read_bytes()
    result = archive_module.prepare_archive(host_data, source)
    contents = _read_archive(result)
    assert source_archive.read_bytes() == original
    assert result.parent.parent == work_root
    assert list(result.parent.iterdir()) == [result]
    second = archive_module.prepare_archive(host_data, source)
    assert second.parent != result.parent
    assert result.is_file() and second.is_file()

    expected = dict(_SOURCE_FILES)
    expected.update(
        {
            "collected/data/etc/insights-client/machine-id": b"new-insights-id",
            "collected/data/insights_commands/hostname": b"new.example",
            "collected/data/insights_commands/hostname_-f": b"new.example",
            "collected/data/insights_commands/subscription-manager_identity": (
                b"system identity: new-subscription-id\n"
                b"name: new.example\norg name: Example\norg ID: 123\n"
            ),
        }
    )
    assert contents == expected


def test_prepare_alternate_bundled_archive(host_data, work_root, tmp_path, monkeypatch):
    _write_archive(tmp_path / "data" / "archives" / "alternate.tar.gz", _SOURCE_FILES)
    monkeypatch.setattr(archive_module, "files", lambda package: tmp_path, raising=False)

    result = archive_module.prepare_archive(host_data, "alternate.tar.gz")

    assert _read_archive(result)["collected/data/binary"] == b"\x00\xff\xfebinary"


def test_external_path_takes_precedence_over_bundled_name(host_data, work_root, tmp_path):
    source = _write_archive(tmp_path / "rhel94.tar.gz", _SOURCE_FILES)

    result = archive_module.prepare_archive(host_data, source)

    assert "collected/data/binary" in _read_archive(result)


def test_fqdn_is_data_not_an_output_path(source_archive, work_root):
    data = archive_module.HostArchiveData("insights-id", "subscription-id", "../../escaped")

    result = archive_module.prepare_archive(data, source_archive)

    assert result.parent.parent == work_root
    assert result.is_file()
    assert _read_archive(result)["collected/data/insights_commands/hostname"] == b"../../escaped"


def test_missing_plain_hostname_is_created(host_data, work_root, tmp_path):
    contents = dict(_SOURCE_FILES)
    del contents["collected/data/insights_commands/hostname"]
    contents["collected/data/insights_commands/subscription-manager_identity"] = (
        b"system identity: original-subscription-id\norg ID: 123"
    )
    source = _write_archive(tmp_path / "source.tar.gz", contents)

    result = archive_module.prepare_archive(host_data, source)

    assert _read_archive(result)["collected/data/insights_commands/hostname"] == b"new.example"
    identity = _read_archive(result)[
        "collected/data/insights_commands/subscription-manager_identity"
    ]
    assert identity.splitlines() == [
        b"system identity: new-subscription-id",
        b"org ID: 123",
        b"name: new.example",
    ]


@pytest.mark.parametrize(
    "contents",
    [
        {},
        {"collected/etc/insights-client/machine-id": b"legacy-id"},
        {**_SOURCE_FILES, "other/data/example": b"ambiguous root"},
    ],
    ids=["empty", "legacy", "multiple-roots"],
)
def test_unsupported_layout_is_rejected(contents, host_data, work_root, tmp_path):
    source = _write_archive(tmp_path / "source.tar.gz", contents)

    with pytest.raises(ValueError, match="data/"):
        archive_module.prepare_archive(host_data, source)

    assert list(work_root.iterdir()) == []


@pytest.mark.parametrize("identity", [None, b"not registered\norg ID: 123\n"])
def test_missing_or_malformed_subscription_identity_is_rejected(
    identity, host_data, work_root, tmp_path
):
    contents = dict(_SOURCE_FILES)
    key = "collected/data/insights_commands/subscription-manager_identity"
    if identity is None:
        del contents[key]
    else:
        contents[key] = identity
    source = _write_archive(tmp_path / "source.tar.gz", contents)

    with pytest.raises(
        (ValueError, FileNotFoundError), match=r"system identity|subscription-manager_identity"
    ):
        archive_module.prepare_archive(host_data, source)

    assert list(work_root.iterdir()) == []


def test_unsafe_extraction_is_rejected(host_data, work_root, tmp_path):
    source = _write_archive(
        tmp_path / "source.tar.gz", {**_SOURCE_FILES, "../../escaped": b"unsafe"}
    )

    with pytest.raises(tarfile.FilterError):
        archive_module.prepare_archive(host_data, source)

    assert list(work_root.iterdir()) == []
    assert not (tmp_path / "escaped").exists()


@pytest.mark.parametrize("source", ["missing.tar.gz", Path("missing.tar.gz")])
def test_missing_source_leaves_no_temporary_directory(source, host_data, work_root):
    with pytest.raises(FileNotFoundError):
        archive_module.prepare_archive(host_data, source)

    assert list(work_root.iterdir()) == []


def test_repack_failure_cleans_the_temporary_directory(
    source_archive, host_data, work_root, monkeypatch
):
    def fail_add(*args, **kwargs):
        raise OSError("cannot write archive")

    monkeypatch.setattr(tarfile.TarFile, "add", fail_add)

    with pytest.raises(OSError, match="cannot write archive"):
        archive_module.prepare_archive(host_data, source_archive)

    assert list(work_root.iterdir()) == []


@pytest.mark.parametrize(
    "target,link_type",
    [
        ("collected/data/etc/insights-client/machine-id", tarfile.SYMTYPE),
        ("collected/data/insights_commands/hostname", tarfile.LNKTYPE),
        ("collected/data/insights_commands/hostname_-f", tarfile.SYMTYPE),
        ("collected/data/insights_commands/subscription-manager_identity", tarfile.LNKTYPE),
    ],
)
def test_linked_rewrite_target_is_rejected(target, link_type, host_data, work_root, tmp_path):
    contents = dict(_SOURCE_FILES)
    backup = "collected/data/unchanged-copy"
    contents[backup] = contents.pop(target)
    link = tarfile.TarInfo(target)
    link.type = link_type
    link.linkname = (
        posixpath.relpath(backup, posixpath.dirname(target))
        if link_type == tarfile.SYMTYPE
        else backup
    )
    source = _write_archive(tmp_path / "linked.tar.gz", contents, [link])
    original = source.read_bytes()

    with pytest.raises(ValueError, match="Linked rewrite path"):
        archive_module.prepare_archive(host_data, source)

    assert source.read_bytes() == original
    assert list(work_root.iterdir()) == []


@pytest.mark.parametrize(
    "directory",
    ["collected/data", "collected/data/etc/insights-client", "collected/data/insights_commands"],
)
def test_symlinked_rewrite_ancestor_is_rejected(directory, host_data, work_root, tmp_path):
    backup = "collected/original-directory"
    contents = {
        name.replace(directory + "/", backup + "/", 1): value
        for name, value in _SOURCE_FILES.items()
    }
    link = tarfile.TarInfo(directory)
    link.type = tarfile.SYMTYPE
    link.linkname = posixpath.relpath(backup, posixpath.dirname(directory))
    source = _write_archive(tmp_path / "linked.tar.gz", contents, [link])
    original = source.read_bytes()

    with pytest.raises(ValueError, match="Linked rewrite path"):
        archive_module.prepare_archive(host_data, source)

    assert source.read_bytes() == original
    assert list(work_root.iterdir()) == []


def test_unrelated_internal_links_are_preserved(host_data, work_root, tmp_path):
    symlink = tarfile.TarInfo("collected/data/os-machine-id-copy")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "etc/machine-id"
    hardlink = tarfile.TarInfo("collected/data/mac-copy")
    hardlink.type = tarfile.LNKTYPE
    hardlink.linkname = "collected/data/sys/class/net/eth0/address"
    source = _write_archive(tmp_path / "linked.tar.gz", _SOURCE_FILES, [symlink, hardlink])

    result = archive_module.prepare_archive(host_data, source)

    with tarfile.open(result) as archive:
        assert archive.getmember("collected/data/os-machine-id-copy").issym()
        assert (
            archive.extractfile("collected/data/os-machine-id-copy").read()
            == b"original-os-machine-id\n"
        )
        assert archive.extractfile("collected/data/mac-copy").read() == b"aa:bb:cc:dd:ee:ff\n"
    assert (
        _read_archive(result)["collected/data/etc/insights-client/machine-id"] == b"new-insights-id"
    )
