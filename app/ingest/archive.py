"""Safe archive extraction for ZIP and tar.gz sources.

Security notes
--------------
Threat model, verified against CPython 3.12 rather than assumed:

* ``zipfile.extract()`` already strips ``..`` components and leading separators,
  so the ZIP path is not traversable even with a naive implementation. v2 relied
  on this incidentally: it computed a sanitised name and then discarded it,
  extracting with the original. It happened to be safe, but nothing in the
  codebase was making it safe.
* ``tarfile.extractall()`` offers no such protection. On 3.12 the default filter
  is ``fully_trusted`` and a member named ``../../x`` **does** escape the
  destination (confirmed experimentally); only ``filter="data"`` refuses it.
  Since fetching GitHub tarballs makes tar the primary ingestion path, this is a
  live risk rather than a theoretical one.

Rather than depending on per-format stdlib behaviour, this module applies one
explicit policy to both formats:

* :func:`resolve_member_path` is the *only* way a destination path is produced,
  and it returns ``None`` for anything that escapes the extraction root.
* Symlinks, hardlinks and special files are refused outright, so the extracted
  tree contains only regular files and directories. That in turn means no
  later path resolution can be redirected out of the root.
* Every limit (file count, per-file size, total size, compression ratio) is
  enforced *while streaming*, so a zip bomb is aborted partway through rather
  than being fully written to disk and measured afterwards.

Refused entries are counted and reported rather than silently dropped — an
archive that trips these checks is itself a finding worth surfacing.
"""

from __future__ import annotations

import re
import shutil
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO

from app.errors import ArchiveTooLargeError, InvalidArchiveError, UnsafeArchiveError

_CHUNK = 64 * 1024
_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:$")

# Unix file-type mask and symlink type, as stored in a ZIP's external_attr.
_S_IFMT = 0o170000
_S_IFLNK = 0o120000


class RejectionReason:
    TRAVERSAL = "path_traversal"
    ABSOLUTE = "absolute_path"
    SYMLINK = "symlink"
    SPECIAL = "special_file"
    TOO_DEEP = "path_too_deep"
    FILE_TOO_LARGE = "file_too_large"


@dataclass
class ExtractionResult:
    root: Path
    file_count: int = 0
    total_bytes: int = 0
    compression_ratio: float = 0.0
    rejected: dict[str, int] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.rejected[reason] = self.rejected.get(reason, 0) + 1

    @property
    def rejected_count(self) -> int:
        return sum(self.rejected.values())


@dataclass(frozen=True)
class ExtractionLimits:
    max_extracted_bytes: int
    max_file_bytes: int
    max_file_count: int
    max_compression_ratio: float
    max_path_depth: int


def resolve_member_path(
    root: Path, member_name: str, *, max_depth: int, strip_components: int = 0
) -> tuple[Path | None, str | None]:
    """Map an archive member name to a safe absolute path under ``root``.

    Returns ``(path, None)`` when safe, or ``(None, reason)`` when the entry must
    be refused. This is the single chokepoint for untrusted paths.
    """
    if not member_name or "\x00" in member_name:
        return None, RejectionReason.TRAVERSAL

    # Archives may use either separator regardless of the producing platform.
    normalised = member_name.replace("\\", "/")
    pure = PurePosixPath(normalised)

    if pure.is_absolute():
        return None, RejectionReason.ABSOLUTE

    parts = [p for p in pure.parts if p not in ("", ".")]

    if any(p == ".." for p in parts):
        return None, RejectionReason.TRAVERSAL
    # "C:/Windows/..." arrives as a relative path on POSIX but is absolute on NT.
    if parts and _WINDOWS_DRIVE.match(parts[0]):
        return None, RejectionReason.ABSOLUTE

    if strip_components:
        parts = parts[strip_components:]
    if not parts:
        return None, None  # nothing left after stripping; skip silently

    if len(parts) > max_depth:
        return None, RejectionReason.TOO_DEEP

    destination = root.joinpath(*parts)

    # Belt and braces: even though the checks above should be sufficient,
    # verify containment against the resolved root before returning.
    root_resolved = root.resolve()
    try:
        resolved = destination.resolve()
    except (OSError, RuntimeError):
        return None, RejectionReason.TRAVERSAL

    if resolved != root_resolved and root_resolved not in resolved.parents:
        return None, RejectionReason.TRAVERSAL

    return destination, None


def _stream_to_disk(
    source: IO[bytes],
    destination: Path,
    *,
    declared_size: int,
    limits: ExtractionLimits,
    result: ExtractionResult,
) -> bool:
    """Copy one member to disk, aborting if it breaches a size limit.

    Returns True when the file was written in full.
    """
    if declared_size > limits.max_file_bytes:
        result.reject(RejectionReason.FILE_TOO_LARGE)
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with destination.open("wb") as out:
            while True:
                chunk = source.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)

                # Trust the stream, not the header: a lying declared size must
                # not let a member exceed the cap.
                if written > limits.max_file_bytes:
                    out.close()
                    destination.unlink(missing_ok=True)
                    result.reject(RejectionReason.FILE_TOO_LARGE)
                    return False

                if result.total_bytes + written > limits.max_extracted_bytes:
                    out.close()
                    destination.unlink(missing_ok=True)
                    raise ArchiveTooLargeError(
                        "Archive exceeds the maximum extracted size",
                        detail=(
                            f"Extraction stopped after "
                            f"{limits.max_extracted_bytes // (1024 * 1024)}MB."
                        ),
                    )
                out.write(chunk)
    except (OSError, EOFError) as exc:
        destination.unlink(missing_ok=True)
        raise InvalidArchiveError("Archive is corrupt or truncated", detail=str(exc)) from exc

    result.total_bytes += written
    result.file_count += 1
    return True


def _check_ratio(result: ExtractionResult, archive_bytes: int, limits: ExtractionLimits) -> None:
    if archive_bytes <= 0:
        return
    ratio = result.total_bytes / archive_bytes
    result.compression_ratio = round(ratio, 2)
    if ratio > limits.max_compression_ratio:
        raise UnsafeArchiveError(
            "Archive compression ratio exceeds the safety limit",
            detail=(
                f"Expanded {ratio:.1f}x (limit {limits.max_compression_ratio:.0f}x). "
                "This pattern is characteristic of a decompression bomb."
            ),
        )


def extract_zip(
    archive_path: Path, root: Path, *, limits: ExtractionLimits
) -> ExtractionResult:
    """Extract a ZIP archive into ``root``, enforcing all safety limits."""
    root.mkdir(parents=True, exist_ok=True)
    result = ExtractionResult(root=root)
    archive_bytes = archive_path.stat().st_size

    try:
        zf = zipfile.ZipFile(archive_path, "r")
    except zipfile.BadZipFile as exc:
        raise InvalidArchiveError("File is not a valid ZIP archive", detail=str(exc)) from exc

    with zf:
        for info in zf.infolist():
            if result.file_count >= limits.max_file_count:
                raise ArchiveTooLargeError(
                    "Archive contains too many files",
                    detail=f"Limit is {limits.max_file_count:,} files.",
                )

            if info.is_dir():
                continue

            # Symlinks are stored as regular entries whose payload is the target
            # path; the type lives in the high bits of external_attr.
            mode = info.external_attr >> 16
            if mode and (mode & _S_IFMT) == _S_IFLNK:
                result.reject(RejectionReason.SYMLINK)
                continue

            destination, reason = resolve_member_path(
                root, info.filename, max_depth=limits.max_path_depth
            )
            if destination is None:
                if reason:
                    result.reject(reason)
                continue

            with zf.open(info, "r") as member:
                _stream_to_disk(
                    member,
                    destination,
                    declared_size=info.file_size,
                    limits=limits,
                    result=result,
                )

            _check_ratio(result, archive_bytes, limits)

    _check_ratio(result, archive_bytes, limits)
    return result


def extract_tar_gz(
    archive_path: Path, root: Path, *, limits: ExtractionLimits, strip_components: int = 0
) -> ExtractionResult:
    """Extract a gzipped tarball into ``root``.

    ``strip_components=1`` drops the wrapper directory that GitHub adds to its
    tarballs (``owner-repo-<sha>/``).
    """
    root.mkdir(parents=True, exist_ok=True)
    result = ExtractionResult(root=root)
    archive_bytes = archive_path.stat().st_size

    try:

        # exists only to turn a bad archive into a domain error.
        tf = tarfile.open(archive_path, "r:gz")  # noqa: SIM115
    except (tarfile.TarError, OSError) as exc:
        raise InvalidArchiveError("File is not a valid tar.gz archive", detail=str(exc)) from exc

    with tf:
        for member in tf:
            if result.file_count >= limits.max_file_count:
                raise ArchiveTooLargeError(
                    "Archive contains too many files",
                    detail=f"Limit is {limits.max_file_count:,} files.",
                )

            if member.isdir():
                continue
            if member.issym() or member.islnk():
                result.reject(RejectionReason.SYMLINK)
                continue
            if not member.isreg():
                # Character/block devices, FIFOs — never legitimate in source.
                result.reject(RejectionReason.SPECIAL)
                continue

            destination, reason = resolve_member_path(
                root,
                member.name,
                max_depth=limits.max_path_depth,
                strip_components=strip_components,
            )
            if destination is None:
                if reason:
                    result.reject(reason)
                continue

            source = tf.extractfile(member)
            if source is None:
                result.reject(RejectionReason.SPECIAL)
                continue
            with source:
                _stream_to_disk(
                    source,
                    destination,
                    declared_size=member.size,
                    limits=limits,
                    result=result,
                )

            _check_ratio(result, archive_bytes, limits)

    _check_ratio(result, archive_bytes, limits)
    return result


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every regular file under ``root``, skipping any stray symlink."""
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file():
            yield path


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
