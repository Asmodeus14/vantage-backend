"""Sign-in, and the ownership rules it exists to enable.

Sessions themselves need a database, so the tests that would need one are
deliberately absent; everything here exercises logic that holds without it —
which is also the configuration most contributors run.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import current_user
from app.auth.store import AuthenticatedUser, hash_session_token
from app.auth.tokens import TokenCipherUnavailable, decrypt_token, encrypt_token
from app.config import Settings
from app.main import app
from app.store import InMemoryReportStore

from tests.test_api_flow import make_report

FERNET_KEY = "8ZQZ3xw1n0m6Q3kY0d0m2y7cQxq3d2XwqZ8b8dJc0mY="


def settings(**overrides) -> Settings:
    base = dict(database_url=None, gemini_api_key=None)
    base.update(overrides)
    return Settings(**base)


def user(user_id: str = "u1") -> AuthenticatedUser:
    return AuthenticatedUser(
        id=user_id,
        github_id=1,
        login="octocat",
        name="Octo",
        avatar_url=None,
        scopes=("read:user",),
        _token_ciphertext="",
    )


# --------------------------------------------------------------------------
# Honest degradation
# --------------------------------------------------------------------------

def test_sign_in_names_what_is_missing_rather_than_saying_unavailable():
    reason = settings().auth_unavailable_reason
    assert reason is not None
    # A database is the first requirement, so that is what it names.
    assert "database" in reason.lower()


def test_missing_oauth_settings_are_listed_by_name():
    reason = settings(database_url="postgresql+asyncpg://x/y").auth_unavailable_reason
    assert reason is not None
    for name in ("GITHUB_CLIENT_ID", "INTERNAL_API_SECRET", "TOKEN_ENCRYPTION_KEY"):
        assert name in reason


def test_auth_is_configured_only_when_everything_is_present():
    configured = settings(
        database_url="postgresql+asyncpg://x/y",
        github_client_id="id",
        internal_api_secret="s",
        token_encryption_key=FERNET_KEY,
    )
    assert configured.auth_configured is True
    assert configured.auth_unavailable_reason is None


def test_health_reports_auth_state(monkeypatch):
    with TestClient(app) as client:
        body = client.get("/api/health").json()
    assert body["auth"]["configured"] is False
    assert body["auth"]["reason"]


def test_auth_status_endpoint_matches_health():
    with TestClient(app) as client:
        status = client.get("/api/auth/status").json()
    assert status["configured"] is False
    assert status["reason"]


# --------------------------------------------------------------------------
# Token storage
# --------------------------------------------------------------------------

def test_tokens_round_trip():
    s = settings(token_encryption_key=FERNET_KEY)
    ciphertext = encrypt_token("gho_secret", s)
    assert "gho_secret" not in ciphertext
    assert decrypt_token(ciphertext, s) == "gho_secret"


def test_a_rotated_key_reads_as_no_token_rather_than_crashing():
    """The user signs in again; it must not raise into a request handler."""
    old = settings(token_encryption_key=FERNET_KEY)
    new = settings(token_encryption_key="pKQ0m8jXQyq3l2Xw8b8dJc0mY3xw1n0m6Q3kY0d0m2y=")
    assert decrypt_token(encrypt_token("gho_secret", old), new) is None


def test_refusing_to_store_a_token_without_a_key():
    """Never silently fall back to plaintext."""
    with pytest.raises(TokenCipherUnavailable):
        encrypt_token("gho_secret", settings())


def test_a_bad_key_explains_how_to_generate_one():
    with pytest.raises(TokenCipherUnavailable) as exc:
        encrypt_token("x", settings(token_encryption_key="not-a-fernet-key"))
    assert "Fernet.generate_key" in str(exc.value)


def test_session_tokens_are_stored_only_as_hashes():
    token = "a-session-token"
    digest = hash_session_token(token)
    assert token not in digest
    assert len(digest) == 64
    assert hash_session_token(token) == digest


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------

async def test_listing_is_scoped_to_the_owner():
    store = InMemoryReportStore()
    await store.save(make_report("mine"), owner_id="u1")
    await store.save(make_report("theirs"), owner_id="u2")
    await store.save(make_report("nobodys"))

    assert [r.id for r in await store.list(owner_id="u1")] == ["mine"]
    assert [r.id for r in await store.list(owner_id="u2")] == ["theirs"]


async def test_signed_out_listing_never_returns_owned_reports():
    """The bug this exists to fix: everyone's index handed to every caller."""
    store = InMemoryReportStore()
    await store.save(make_report("mine"), owner_id="u1")
    await store.save(make_report("nobodys"))

    assert [r.id for r in await store.list()] == ["nobodys"]


async def test_owned_reports_are_still_reachable_by_id():
    """Ownership scopes listing, not access — a report link stays shareable."""
    store = InMemoryReportStore()
    await store.save(make_report("mine"), owner_id="u1")
    assert (await store.get("mine")).id == "mine"


async def test_repository_filter_and_ownership_compose():
    store = InMemoryReportStore()
    await store.save(make_report("a", repository="x/y"), owner_id="u1")
    await store.save(make_report("b", repository="x/y"), owner_id="u2")

    listing = await store.list(repository="x/y", owner_id="u1")
    assert [r.id for r in listing] == ["a"]


async def test_eviction_forgets_ownership_too():
    """A stale owner entry would misattribute a later report with the same id."""
    store = InMemoryReportStore(capacity=1)
    await store.save(make_report("first"), owner_id="u1")
    await store.save(make_report("second"), owner_id="u2")
    assert await store.owner_of("first") is None


# --------------------------------------------------------------------------
# Deletion authorisation
# --------------------------------------------------------------------------

@pytest.fixture
def owned_store(monkeypatch):
    import app.store as store_module

    store = InMemoryReportStore()
    monkeypatch.setattr(store_module, "_store", store)
    return store


def _as(user_or_none):
    app.dependency_overrides[current_user] = lambda: user_or_none


def _anonymous():
    app.dependency_overrides.pop(current_user, None)


def seed(store, report, owner_id: str | None = None) -> None:
    """Populate the in-memory store from a synchronous test.

    `asyncio.run` rather than a shared loop: TestClient drives its own, and
    reaching for `get_event_loop()` here fails outright on 3.12.
    """
    asyncio.run(store.save(report, owner_id=owner_id))


def test_an_owner_may_delete_their_report(owned_store):
    seed(owned_store, make_report("mine"), owner_id="u1")
    _as(user("u1"))
    try:
        with TestClient(app) as client:
            assert client.delete("/api/reports/mine").status_code == 204
    finally:
        _anonymous()


def test_a_stranger_may_not_delete_someone_elses_report(owned_store):
    seed(owned_store, make_report("theirs"), owner_id="u2")
    _as(user("u1"))
    try:
        with TestClient(app) as client:
            response = client.delete("/api/reports/theirs")
        assert response.status_code == 403
        assert response.json()["code"] == "not_authorised"
    finally:
        _anonymous()


def test_anonymous_reports_cannot_be_deleted_through_the_api(owned_store):
    """An unguessable id is a read capability, not a destructive one."""
    seed(owned_store, make_report("open"))
    _as(user("u1"))
    try:
        with TestClient(app) as client:
            assert client.delete("/api/reports/open").status_code == 403
    finally:
        _anonymous()
