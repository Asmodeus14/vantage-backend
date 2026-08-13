"""Cache the suppression-adjusted score on the report row.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-13

A listing is built entirely from indexed columns and never deserialises
``payload`` — that is what keeps it cheap. Without these two columns, History
and the trend chart showed the score as analysed while the report page they
link to showed it adjusted, so the same report displayed two different numbers.

Both are nullable/defaulted rather than backfilled. Null means "nothing
accepted", which is true of every row that exists when this runs, since
suppressions were introduced one revision ago.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("effective_score", sa.Integer(), nullable=True))
    op.add_column(
        "reports",
        sa.Column(
            "suppressed_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )


def downgrade() -> None:
    op.drop_column("reports", "suppressed_count")
    op.drop_column("reports", "effective_score")
