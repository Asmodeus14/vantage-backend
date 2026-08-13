"""Regression tests for archive extraction safety.

v2 of this service shipped an exploitable Zip Slip: it computed a sanitised
filename and then extracted using the original untrusted path. These tests
exist so that specific bug, and its neighbours, cannot come back.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.errors import ArchiveTooLargeError, InvalidArchiveError, UnsafeArchiveError
from app.ingest.archive import (
    ExtractionLimits,
    RejectionReason,
    extract_tar_gz,
    extract_zip,
    resolve_member_path,
)

LIMITS = ExtractionLimits(
    max_extracted_bytes=10 * 1024 * 1024,
    max_file_bytes=1 * 1024 * 1024,
    max_file_count=1000,
    max_compression_ratio=100.0,
    max_path_depth=10,
)


def write_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


# --------------------------------------------------------------------------
# resolve_member_path — the single chokepoint for untrusted paths
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "member",
    [
        "../evil.txt",
        "../../evil.txt",
        "a/../../evil.txt",
        "a/b/../../../evil.txt",
        r"..\..\evil.txt",  # Windows separators
        "a/..\\../evil.txt",  # mixed separators
        "/etc/passwd",
        "//etc/passwd",
        r"C:\Windows\system32\evil.dll",
        "C:/Windows/evil.dll",
    ],
)
def test_traversal_and_absolute_paths_are_refused(tmp_path: Path, member: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    destination, reason = resolve_member_path(root, member, max_depth=10)
    assert destination is None, f"{member!r} should have been refused"
    assert reason in {RejectionReason.TRAVERSAL, RejectionReason.ABSOLUTE}


@pytest.mark.parametrize("member", ["src/index.js", "./a/b/c.ts", "a/b/../c.py"])
def test_benign_paths_resolve_inside_root(tmp_path: Path, member: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    destination, reason = resolve_member_path(root, member, max_depth=10)
    # "a/b/../c.py" contains ".." and is conservatively refused; everything else
    # must resolve to a path inside the root.
    if destination is None:
        assert reason == RejectionReason.TRAVERSAL
    else:
        assert root.resolve() in destination.resolve().parents


def test_path_depth_is_capped(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    deep = "/".join(["d"] * 30) + "/file.txt"
    destination, reason = resolve_member_path(root, deep, max_depth=10)
    assert destination is None
    assert reason == RejectionReason.TOO_DEEP


def test_strip_components_removes_wrapper_directory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    destination, reason = resolve_member_path(
        root, "owner-repo-abc123/src/main.py", max_depth=10, strip_components=1
    )
    assert reason is None
    assert destination == root / "src" / "main.py"


# --------------------------------------------------------------------------
# End-to-end extraction
# --------------------------------------------------------------------------

def test_zip_slip_writes_nothing_outside_root(tmp_path: Path) -> None:
    """The headline regression test: a traversal entry must not escape."""
    archive = write_zip(
        tmp_path / "evil.zip",
        {
            "../../evil.txt": b"pwned",
            "../escape.txt": b"pwned",
            "good/app.js": b"console.log(1)",
        },
    )
    root = tmp_path / "extract"

    result = extract_zip(archive, root, limits=LIMITS)

    assert (root / "good" / "app.js").read_bytes() == b"console.log(1)"
    assert result.file_count == 1
    assert result.rejected[RejectionReason.TRAVERSAL] == 2

    # Nothing may exist anywhere outside the extraction root.
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path.parent / "evil.txt").exists()
    escaped = list(tmp_path.rglob("evil.txt")) + list(tmp_path.rglob("escape.txt"))
    assert escaped == []


def test_zip_symlink_entries_are_refused(tmp_path: Path) -> None:
    """A symlink to /etc/passwd must not be recreated inside the tree."""
    archive_path = tmp_path / "link.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        info = zipfile.ZipInfo("link_to_passwd")
        # 0o120777: symlink + rwxrwxrwx, in the high 16 bits of external_attr.
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd")
        zf.writestr("real.txt", b"data")

    root = tmp_path / "extract"
    result = extract_zip(archive_path, root, limits=LIMITS)

    assert result.rejected[RejectionReason.SYMLINK] == 1
    assert not (root / "link_to_passwd").exists()
    assert (root / "real.txt").exists()


def test_tar_symlink_and_special_entries_are_refused(tmp_path: Path) -> None:
    archive_path = tmp_path / "src.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        payload = b"print('hi')"
        info = tarfile.TarInfo("pkg/main.py")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

        link = tarfile.TarInfo("pkg/evil_link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)

        fifo = tarfile.TarInfo("pkg/pipe")
        fifo.type = tarfile.FIFOTYPE
        tf.addfile(fifo)

    root = tmp_path / "extract"
    result = extract_tar_gz(archive_path, root, limits=LIMITS, strip_components=1)

    assert (root / "main.py").read_bytes() == b"print('hi')"
    assert result.rejected[RejectionReason.SYMLINK] == 1
    assert result.rejected[RejectionReason.SPECIAL] == 1
    assert not (root / "evil_link").exists()


def test_tar_traversal_is_refused(tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        payload = b"pwned"
        info = tarfile.TarInfo("../../evil.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    root = tmp_path / "extract"
    result = extract_tar_gz(archive_path, root, limits=LIMITS)

    assert result.file_count == 0
    assert result.rejected[RejectionReason.TRAVERSAL] == 1
    assert list(tmp_path.rglob("evil.txt")) == []


def test_zip_bomb_is_rejected_by_compression_ratio(tmp_path: Path) -> None:
    """A highly compressible payload must trip the ratio guard."""
    archive = write_zip(tmp_path / "bomb.zip", {"bomb.bin": b"\0" * (2 * 1024 * 1024)})
    limits = ExtractionLimits(
        max_extracted_bytes=64 * 1024 * 1024,
        max_file_bytes=64 * 1024 * 1024,
        max_file_count=1000,
        max_compression_ratio=10.0,
        max_path_depth=10,
    )
    with pytest.raises(UnsafeArchiveError) as exc:
        extract_zip(archive, tmp_path / "extract", limits=limits)
    assert "compression ratio" in str(exc.value).lower()


def test_oversized_single_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    archive = write_zip(
        tmp_path / "big.zip",
        {"huge.bin": b"x" * (2 * 1024 * 1024), "small.js": b"ok"},
    )
    limits = ExtractionLimits(
        max_extracted_bytes=100 * 1024 * 1024,
        max_file_bytes=1024 * 1024,  # 1MB cap → huge.bin is skipped
        max_file_count=1000,
        max_compression_ratio=10_000.0,
        max_path_depth=10,
    )
    result = extract_zip(archive, tmp_path / "extract", limits=limits)

    assert result.rejected[RejectionReason.FILE_TOO_LARGE] == 1
    assert (tmp_path / "extract" / "small.js").exists()
    assert not (tmp_path / "extract" / "huge.bin").exists()


def test_total_extracted_size_is_capped(tmp_path: Path) -> None:
    entries = {f"f{i}.bin": b"x" * (200 * 1024) for i in range(20)}  # ~4MB total
    archive = write_zip(tmp_path / "many.zip", entries)
    limits = ExtractionLimits(
        max_extracted_bytes=1024 * 1024,  # 1MB total cap
        max_file_bytes=1024 * 1024,
        max_file_count=1000,
        max_compression_ratio=10_000.0,
        max_path_depth=10,
    )
    with pytest.raises(ArchiveTooLargeError):
        extract_zip(archive, tmp_path / "extract", limits=limits)


def test_file_count_is_capped(tmp_path: Path) -> None:
    entries = {f"f{i}.js": b"//" for i in range(50)}
    archive = write_zip(tmp_path / "count.zip", entries)
    limits = ExtractionLimits(
        max_extracted_bytes=10 * 1024 * 1024,
        max_file_bytes=1024 * 1024,
        max_file_count=10,
        max_compression_ratio=10_000.0,
        max_path_depth=10,
    )
    with pytest.raises(ArchiveTooLargeError):
        extract_zip(archive, tmp_path / "extract", limits=limits)


def test_corrupt_archive_raises_invalid(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"this is definitely not a zip file")
    with pytest.raises(InvalidArchiveError):
        extract_zip(bad, tmp_path / "extract", limits=LIMITS)
