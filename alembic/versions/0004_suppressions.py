"""Accepted findings.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-13

The primary key is (owner_id, repository, fingerprint): accepting the same
problem twice is one suppression, not two, so `merge` updates the reason
instead of colliding.

No foreign key to `reports`. A suppression outlives the analysis that revealed
it — that is the entire point, since it has to apply to the *next* run — and
`ON DELETE CASCADE` from a report would silently revoke it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "suppressions",
        sa.Column("owner_id", sa.String(24), primary_key=True),
        sa.Column("repository", sa.String(255), primary_key=True),
        sa.Column("fingerprint", sa.String(64), primary_key=True),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("title", sa.String(500), nullable=False, server_default=""),
        sa.Column("rule_id", sa.String(120), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    # Every read is "the suppressions for this owner and this repository", which
    # the composite primary key already serves as a leading-column prefix. The
    # separate index exists for the eventual "everything this account has
    # accepted" management view, which has no repository to filter on.
    op.create_index("ix_suppressions_owner_id", "suppressions", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_suppressions_owner_id", table_name="suppressions")
    op.drop_table("suppressions")
