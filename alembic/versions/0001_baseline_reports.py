"""Baseline: the reports table.

Revision ID: 0001
Revises:
Create Date: 2026-08-11

This exists to give Alembic a starting point for a schema that was created by
``Base.metadata.create_all`` before migrations existed. Every deployed database
already has ``reports``, so the upgrade inspects first and does nothing when it
is present. That makes ``alembic upgrade head`` safe to run against a live
database and against an empty one.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "reports" in inspector.get_table_names():
        # Created by create_all on an earlier deploy. Stamping is all that is
        # wanted here; recreating it would fail, and dropping it would be
        # catastrophic.
        return

    op.create_table(
        "reports",
        sa.Column("id", sa.String(24), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_kind", sa.String(20), nullable=False),
        sa.Column("repository", sa.String(255), nullable=True),
        sa.Column("ref", sa.String(255), nullable=True),
        sa.Column("commit", sa.String(64), nullable=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("grade", sa.String(2), nullable=False),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("payload", JSON_TYPE, nullable=False),
    )
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_repository", "reports", ["repository"])


def downgrade() -> None:
    op.drop_index("ix_reports_repository", table_name="reports")
    op.drop_index("ix_reports_created_at", table_name="reports")
    op.drop_table("reports")
