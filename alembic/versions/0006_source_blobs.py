"""Stored source, for uploads.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-13

Only uploads are stored. A repository's source is re-fetched from GitHub pinned
to the analysed commit, which costs nothing to keep and cannot drift; an upload
is bytes someone sent once, with no URL that would produce them again.

One row per file rather than one archive per report, because the viewer opens a
single file at a time and decompressing a whole project to read a 40-line module
is a cost that only appears under load.

No foreign key to `reports`. The delete path removes blobs explicitly, and a
cascade would make it silently correct here while hiding that obligation from
anyone reading the router.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_blobs",
        sa.Column("report_id", sa.String(24), primary_key=True),
        sa.Column("path", sa.String(1024), primary_key=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("language", sa.String(40), nullable=True),
        sa.Column("analysable", sa.Integer(), nullable=False, server_default="1"),
        # gzip, not text. Source compresses 3-4x, which is the whole reason
        # keeping it is affordable on a small instance.
        sa.Column("content", sa.LargeBinary(), nullable=False),
    )
    # Every read is "this report's files"; the composite primary key already
    # leads with report_id, but the tree query and the delete both filter on it
    # alone and deserve their own index rather than a prefix scan.
    op.create_index("ix_source_blobs_report_id", "source_blobs", ["report_id"])


def downgrade() -> None:
    op.drop_index("ix_source_blobs_report_id", table_name="source_blobs")
    op.drop_table("source_blobs")
