"""An indexed, read-only view of an extracted project.

Built once and shared by every rule, so the tree is walked and each file read
at most once. v2 re-walked the tree with ``rglob('*')`` several times per
analysis just to compute directory sizes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.ingest.filter import detect_language, should_analyse, should_read

logger = logging.getLogger(__name__)

# Files larger than this are indexed (size, path) but not read into memory.
MAX_READ_BYTES = 1_000_000
# Anything with a NUL byte in its first block is treated as binary.
_BINARY_SNIFF_BYTES = 8_000


@dataclass
class SourceFile:
    path: str  # repo-relative, POSIX separators
    absolute: Path
    size: int
    language: str | None
    analysable: bool
    _text: str | None = field(default=None, repr=False)
    _loaded: bool = field(default=False, repr=False)
    _line_offsets: list[int] | None = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    def text(self) -> str | None:
        """Decoded contents, or ``None`` for binary/oversized files."""
        if self._loaded:
            return self._text
        self._loaded = True
        if self.size > MAX_READ_BYTES:
            return None
        try:
            raw = self.absolute.read_bytes()
        except OSError:
            return None
        if b"\x00" in raw[:_BINARY_SNIFF_BYTES]:
            return None
        try:
            self._text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                self._text = raw.decode("utf-8", errors="replace")
            except Exception:
                self._text = None
        return self._text

    def lines(self) -> list[str]:
        text = self.text()
        return text.splitlines() if text else []

    def line_count(self) -> int:
        return len(self.lines())

    def snippet(self, line: int, *, context: int = 3) -> tuple[str, int] | None:
        """Source around a 1-indexed line.

        Returns ``(text, start_line)``. The start line is required for a viewer
        to number the gutter correctly — the snippet rarely begins at ``line``.
        """
        lines = self.lines()
        if not lines or line < 1:
            return None
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        return "\n".join(lines[start:end]), start + 1


@dataclass
class Snapshot:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    by_path: dict[str, SourceFile] = field(default_factory=dict)

    # -- construction --------------------------------------------------

    @classmethod
    def build(cls, root: Path) -> "Snapshot":
        snapshot = cls(root=root)
        for absolute in sorted(root.rglob("*")):
            if absolute.is_symlink() or not absolute.is_file():
                continue
            try:
                relative = PurePosixPath(absolute.relative_to(root).as_posix())
            except ValueError:  # pragma: no cover - defensive
                continue
            if not should_read(relative):
                continue
            try:
                size = absolute.stat().st_size
            except OSError:
                continue

            source = SourceFile(
                path=str(relative),
                absolute=absolute,
                size=size,
                language=detect_language(relative),
                analysable=should_analyse(relative),
            )
            snapshot.files.append(source)
            snapshot.by_path[source.path] = source
        return snapshot

    # -- queries -------------------------------------------------------

    def get(self, path: str) -> SourceFile | None:
        return self.by_path.get(path)

    def analysable(self) -> list[SourceFile]:
        return [f for f in self.files if f.analysable]

    def by_language(self, *languages: str) -> list[SourceFile]:
        wanted = set(languages)
        return [f for f in self.files if f.language in wanted and f.analysable]

    def by_name(self, *names: str) -> list[SourceFile]:
        wanted = {n.lower() for n in names}
        return [f for f in self.files if f.name.lower() in wanted]

    def find(self, pattern: str) -> list[SourceFile]:
        """Match files by glob against the repo-relative path."""
        return [f for f in self.files if PurePosixPath(f.path).match(pattern)]

    def exists(self, *names: str) -> bool:
        return bool(self.by_name(*names))

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def total_lines(self) -> int:
        return sum(f.line_count() for f in self.analysable())
