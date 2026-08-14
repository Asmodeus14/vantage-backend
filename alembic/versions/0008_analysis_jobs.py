"""Durable job outcomes.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-14

Job state lived only in a module-level dict, so it did not survive a restart —
and a free-tier instance sleeps when idle. An analysis running at that moment
left the client holding a job id with nothing on the other end, and the SSE
endpoint told it the analysis no longer existed. That was frequently false: the
work had finished and the report was in the database with nobody holding its id.

This table records the *outcome*, not the progress log. The event stream stays
in memory, which is correct — replaying stages that finished twenty minutes ago
helps nobody, whereas the report id is the one thing a reconnecting client
cannot reconstruct.

No foreign key to `reports`. Records are swept after two days while a report is
kept indefinitely, so a constraint here would either block the sweep or, with
cascade, let report deletion rewrite history about a job that did succeed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("stage", sa.String(24), nullable=True),
        sa.Column("message", sa.String(500), nullable=True),
        sa.Column("report_id", sa.String(24), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("owner_id", sa.String(24), nullable=True),
    )
    # The sweep deletes by age on every job start, so that predicate is the one
    # index that earns its write cost.
    op.create_index(
        "ix_analysis_jobs_created_at", "analysis_jobs", ["created_at"]
    )
    op.create_index("ix_analysis_jobs_owner_id", "analysis_jobs", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_analysis_jobs_owner_id", table_name="analysis_jobs")
    op.drop_index("ix_analysis_jobs_created_at", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
