"""Timestamp source blobs so the oldest can be pruned.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-13

Stored source is the one thing here that grows without bound: an upload keeps
up to 8 MB gzipped, so a few hundred would approach a small managed database's
whole storage allowance.

Pruning needs an ordering, and the blobs table had none — `report_id` is a
random token and carries no time. This adds the timestamp and the index the
prune query sorts on, so eviction is a pure blobs-table operation that still
works after the report row it belonged to has been deleted.

Existing rows get the migration's own timestamp. That makes them all equally
old, which is the correct answer: nothing recorded when they arrived, so the
only honest ordering among them is none.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_blobs",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    # The prune query orders by this to find the oldest upload.
    op.create_index("ix_source_blobs_created_at", "source_blobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_source_blobs_created_at", table_name="source_blobs")
    op.drop_column("source_blobs", "created_at")
