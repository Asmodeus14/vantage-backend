"""Account and session tables.

Sign-in exists for three concrete reasons, in order of value:

* Reports become owned, so ``GET /api/reports`` stops handing every user the
  full index of everyone's analyses.
* The user's own GitHub token raises the API budget from 60 requests an hour to
  5000, which is what makes commit-history enrichment affordable.
* Private repositories become analysable, if the user separately grants it.

Sessions are opaque ids stored here rather than JWTs: revocable, and the lookup
costs one indexed primary-key read.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    # GitHub ids are already past 2^31; Integer would overflow.
    github_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    login: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(512))
    # Fernet ciphertext, never the raw token.
    access_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # Space-separated OAuth scopes actually granted, which is not necessarily
    # what was asked for — the UI offers private-repo analysis based on this.
    scopes: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SessionRow(Base):
    __tablename__ = "sessions"

    # SHA-256 of the session token. Storing the token itself would turn a
    # database leak directly into account takeover.
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(24), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
