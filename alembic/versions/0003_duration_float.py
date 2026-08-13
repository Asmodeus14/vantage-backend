"""Store duration_seconds as a float.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-12

An `Integer` column truncated every sub-second analysis to 0, so the Postgres
and in-memory stores disagreed about the same report and the UI showed
"analysed in 0.0s" for anything fast.

The cast is widening and lossless — existing whole-second values survive
exactly. Only the truncated precision is unrecoverable, and it was never
written.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "reports",
        "duration_seconds",
        existing_type=sa.Integer(),
        type_=sa.Float(),
        existing_nullable=False,
        # Postgres will not implicitly cast integer → double precision in an
        # ALTER, so it is stated.
        postgresql_using="duration_seconds::double precision",
    )


def downgrade() -> None:
    op.alter_column(
        "reports",
        "duration_seconds",
        existing_type=sa.Float(),
        type_=sa.Integer(),
        existing_nullable=False,
        postgresql_using="duration_seconds::integer",
    )
