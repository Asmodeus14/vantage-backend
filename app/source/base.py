"""Reading a report's source, after the analysis that produced it.

Findings record a file and a line, and until now there was nothing behind that
coordinate — the analysed tree is deleted as soon as the run finishes. This is
the seam that gives it back, for the file viewer and for AI actions that need
more than the ±3 lines a finding carries.

**One interface, two implementations.** Repository source is re-fetched from
GitHub pinned to the analysed commit; upload source is stored, because there is
nothing to re-fetch it from. That split is real and unavoidable, so it is
confined to this package: everything above it asks a ``SourceProvider`` and
never learns which kind it has.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SourceEntry:
    """One file in a report's tree."""

    path: str  # repo-relative, POSIX separators
    size: int
    language: str | None = None
    analysable: bool = True


class SourceUnavailable(Exception):
    """Source cannot be read, with a reason fit to show someone.

    Deliberately an exception carrying prose rather than a bare ``None``. Every
    way this fails is a different sentence — the repository went private, the
    commit was force-pushed away, the upload predates blob storage — and
    "unavailable" tells nobody anything they can act on.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SourceProvider(Protocol):
    """Where a report's files come from."""

    async def tree(self) -> list[SourceEntry]:
        """Every file, for the viewer's sidebar.

        Raises :class:`SourceUnavailable` when the source is gone.
        """
        ...

    async def read(self, path: str) -> str:
        """One file's text, decoded.

        Raises :class:`SourceUnavailable` when the file or the source is gone.
        """
        ...
