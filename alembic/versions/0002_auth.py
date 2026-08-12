"""Accounts, sessions, and report ownership.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-11

``reports.owner_id`` is nullable on purpose. Every row that exists when this
runs was created anonymously, and those reports must keep working: reachable by
their unguessable id, simply not listed. Backfilling them to some placeholder
owner would either hide them or hand them to the wrong person.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(24), primary_key=True),
        # GitHub ids are already past 2^31.
        sa.Column("github_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("login", sa.String(120), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.String(512), nullable=True),
        sa.Column("access_token_encrypted", sa.Text(), nullable=False),
        sa.Column("scopes", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(24),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    # Expiry sweeps scan on this.
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.add_column("reports", sa.Column("owner_id", sa.String(24), nullable=True))
    op.create_index("ix_reports_owner_id", "reports", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_reports_owner_id", table_name="reports")
    op.drop_column("reports", "owner_id")
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("users")
