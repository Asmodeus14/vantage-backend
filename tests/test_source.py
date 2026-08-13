"""Reading a report's source after the fact.

Two implementations behind one interface: repositories are re-fetched from
GitHub pinned to the analysed commit, uploads are stored because there is
nothing to re-fetch them from. Most of what matters here is that the split
stays invisible to callers, and that a path from a URL cannot escape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import SourceInfo, SourceKind
from app.source.base import SourceUnavailable
from app.source.blobs import (
    MAX_TOTAL_BLOB_BYTES,
    InMemoryBlobStore,
)
from app.source.providers import (
    GitHubSourceProvider,
    StoredSourceProvider,
    provider_for,
    safe_path,
)
from tests.test_api_flow import make_report


@pytest.fixture
def snapshot(tmp_path: Path) -> Snapshot:
    (tmp_path / "src").mkdir()
    # `newline=""` so Windows does not rewrite \n as \r\n. Real input arrives
    # from an archive, which carries whatever the author committed.
    (tmp_path / "src" / "index.js").write_text(
        "const a = 1;\nconst b = 2;\n", newline=""
    )
    (tmp_path / "package.json").write_text('{"name":"demo"}', newline="")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00binary")
    return Snapshot.build(tmp_path)


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        "../etc/passwd",
        "../../secret",
        "src/../../outside.txt",
        "..\\windows\\system32",
        "",
        "   ",
    ],
)
def test_a_path_cannot_escape_the_project(hostile):
    """The viewer takes this straight from a URL, and both providers
    interpolate it — one into a GitHub URL, one into a SQL parameter."""
    with pytest.raises(SourceUnavailable):
        safe_path(hostile)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("src/index.js", "src/index.js"),
        # An absolute path is read as project-relative rather than refused: it
        # cannot escape once normalised, and `/src/index.js` is what someone
        # copying a path out of the tree will paste.
        ("/src/index.js", "src/index.js"),
        ("/etc/passwd", "etc/passwd"),
        ("./src/index.js", "src/index.js"),
        ("src/./deep/../index.js", "src/index.js"),
    ],
)
def test_ordinary_paths_survive_normalisation(path, expected):
    assert safe_path(path) == expected


# --------------------------------------------------------------------------
# Stored source (uploads)
# --------------------------------------------------------------------------

async def test_an_upload_round_trips_through_the_blob_store(snapshot):
    store = InMemoryBlobStore()
    kept = await store.put("r1", snapshot)

    assert kept >= 2
    tree = {entry.path for entry in await store.tree("r1")}
    assert "src/index.js" in tree
    assert "package.json" in tree
    assert await store.read("r1", "src/index.js") == "const a = 1;\nconst b = 2;\n"


async def test_binary_files_are_not_stored(snapshot):
    """They cannot be shown in a text viewer and would waste the budget."""
    store = InMemoryBlobStore()
    await store.put("r1", snapshot)
    assert "logo.png" not in {entry.path for entry in await store.tree("r1")}


async def test_reading_a_file_that_is_not_in_the_report_says_so(snapshot):
    store = InMemoryBlobStore()
    await store.put("r1", snapshot)
    with pytest.raises(SourceUnavailable):
        await store.read("r1", "src/nope.js")


async def test_deleting_a_report_takes_its_source_with_it(snapshot):
    """Otherwise blobs outlive every reference to them — a leak that only
    shows up as a growing disk bill."""
    store = InMemoryBlobStore()
    await store.put("r1", snapshot)
    await store.delete("r1")
    assert await store.tree("r1") == []


async def test_the_oldest_upload_is_evicted_when_the_budget_is_exceeded(snapshot):
    """Stored source is the one thing that grows without bound, and a managed
    free database has a finite allowance. Whole reports at a time — half a
    project is a broken tree, which is worse than an absent one that says so."""
    store = InMemoryBlobStore()
    for report_id in ("first", "second", "third"):
        await store.put(report_id, snapshot)

    # A budget that fits roughly one report's worth forces two evictions.
    one_report = sum(
        len(packed) for _, packed in store._files["third"].values()
    )
    evicted = await store.prune(budget=one_report)

    assert evicted == 2
    assert await store.tree("first") == [], "oldest goes first"
    assert await store.tree("second") == []
    assert await store.tree("third") != [], "newest survives"


async def test_pruning_does_nothing_while_under_budget(snapshot):
    store = InMemoryBlobStore()
    await store.put("r1", snapshot)
    assert await store.prune(budget=MAX_TOTAL_BLOB_BYTES) == 0
    assert await store.tree("r1") != []


async def test_deleting_a_report_keeps_the_eviction_order_consistent(snapshot):
    """An explicit delete must not leave a phantom in the eviction queue, or the
    next prune would evict something that is already gone and stop early."""
    store = InMemoryBlobStore()
    await store.put("r1", snapshot)
    await store.put("r2", snapshot)
    await store.delete("r1")

    assert await store.prune(budget=0) == 1, "only r2 was left to evict"
    assert await store.tree("r2") == []


async def test_an_upload_with_no_stored_source_explains_itself(snapshot):
    """Uploads analysed before this existed have nothing stored. The viewer
    must say why rather than showing an empty tree."""
    provider = StoredSourceProvider("never-stored")
    with pytest.raises(SourceUnavailable) as exc:
        await provider.tree()
    assert "re-upload" in exc.value.reason.lower()


# --------------------------------------------------------------------------
# Choosing an implementation
# --------------------------------------------------------------------------

def settings() -> Settings:
    return Settings(database_url=None, gemini_api_key=None)


def test_an_upload_gets_the_stored_provider():
    report = make_report("r1", repository=None)
    report.source = SourceInfo(kind=SourceKind.UPLOAD, filename="project.zip")
    assert isinstance(provider_for(report, settings()), StoredSourceProvider)


def test_a_repository_gets_the_github_provider():
    report = make_report("r1", repository="acme/app")
    report.source = SourceInfo(
        kind=SourceKind.REPOSITORY, repository="acme/app", ref="main", commit="abc123"
    )
    provider = provider_for(report, settings())
    assert isinstance(provider, GitHubSourceProvider)


def test_a_report_without_a_commit_is_refused_with_a_reason():
    """Line numbers only mean something against the tree that was analysed.
    Reading the branch head would show the wrong line after any push."""
    report = make_report("r1", repository="acme/app")
    report.source = SourceInfo(
        kind=SourceKind.REPOSITORY, repository="acme/app", ref="main", commit=None
    )
    with pytest.raises(SourceUnavailable) as exc:
        provider_for(report, settings())
    assert "re-analyse" in exc.value.reason.lower()


# --------------------------------------------------------------------------
# GitHub failures, in words
# --------------------------------------------------------------------------

"""HTTP surface"""


@pytest.fixture
def api(monkeypatch, snapshot):
    from app.config import get_settings
    from app.main import app
    from app.routers import health as health_module
    from app.store import InMemoryReportStore

    reports = InMemoryReportStore()
    blobs = InMemoryBlobStore()

    app.dependency_overrides[get_settings] = lambda: settings()

    async def fake_probe():
        return False, "No DATABASE_URL configured."

    monkeypatch.setattr(health_module, "probe_database", fake_probe)
    health_module._db_cache = None
    monkeypatch.setattr("app.routers.source.get_store", lambda: reports)
    monkeypatch.setattr("app.source.providers.get_blob_store", lambda: blobs)

    class Api:
        pass

    helper = Api()
    helper.reports = reports
    helper.blobs = blobs
    yield helper

    app.dependency_overrides.clear()
    health_module._db_cache = None


async def test_the_tree_carries_finding_counts_so_the_sidebar_can_show_them(
    api, snapshot
):
    """Otherwise the client fetches every file just to learn where to put a
    marker."""
    from fastapi.testclient import TestClient

    from app.main import app
    from tests.test_api_flow import make_finding

    report = make_report("r1", repository=None)
    report.source = SourceInfo(kind=SourceKind.UPLOAD, filename="project.zip")
    report.findings = [make_finding(id="a", file="src/index.js", line=1)]
    await api.reports.save(report)
    await api.blobs.put("r1", snapshot)

    with TestClient(app) as client:
        body = client.get("/api/reports/r1/files").json()

    by_path = {f["path"]: f for f in body["files"]}
    assert by_path["src/index.js"]["findings"] == 1
    assert by_path["package.json"]["findings"] == 0


async def test_reading_a_file_returns_its_findings_for_the_gutter(api, snapshot):
    from fastapi.testclient import TestClient

    from app.main import app
    from tests.test_api_flow import make_finding

    report = make_report("r1", repository=None)
    report.source = SourceInfo(kind=SourceKind.UPLOAD, filename="project.zip")
    report.findings = [
        make_finding(id="a", file="src/index.js", line=2, title="Here"),
        make_finding(id="b", file="package.json", line=1, title="Elsewhere"),
    ]
    await api.reports.save(report)
    await api.blobs.put("r1", snapshot)

    with TestClient(app) as client:
        body = client.get(
            "/api/reports/r1/file", params={"path": "src/index.js"}
        ).json()

    assert body["content"].startswith("const a = 1;")
    assert body["language"] == "javascript"
    # Only this file's findings — the gutter is drawn on first paint.
    assert [f["title"] for f in body["findings"]] == ["Here"]


async def test_escaping_the_project_over_http_is_refused(api, snapshot):
    from fastapi.testclient import TestClient

    from app.main import app

    report = make_report("r1", repository=None)
    report.source = SourceInfo(kind=SourceKind.UPLOAD, filename="project.zip")
    await api.reports.save(report)
    await api.blobs.put("r1", snapshot)

    with TestClient(app) as client:
        response = client.get(
            "/api/reports/r1/file", params={"path": "../../../../etc/passwd"}
        )

    assert response.status_code == 404
    assert response.json()["code"] == "source_unavailable"


async def test_an_unavailable_source_explains_itself_over_http(api):
    """A bare 404 leaves someone guessing whether the report or the file is
    the problem."""
    from fastapi.testclient import TestClient

    from app.main import app

    report = make_report("r1", repository="acme/app")
    report.source = SourceInfo(
        kind=SourceKind.REPOSITORY, repository="acme/app", ref="main", commit=None
    )
    await api.reports.save(report)

    with TestClient(app) as client:
        response = client.get("/api/reports/r1/files")

    assert response.status_code == 404
    assert "re-analyse" in response.json()["detail"].lower()


"""Private repositories"""


async def test_ingestion_refuses_a_private_repository_for_anonymous_callers(monkeypatch):
    """Defence in depth against a mis-scoped server token.

    Anonymous callers fall back to the server's credentials. If that token could
    reach private repositories, without this check any visitor could analyse
    someone's private code and then read whole files through the viewer.
    """
    import httpx

    from app.errors import PrivateRepositoryError
    from app.ingest.github import GitHubCredentials, RepositoryRef, fetch_repository

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"private": True, "default_branch": "main", "size": 10}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())
    ref = RepositoryRef("acme", "secret")

    for credentials in (
        None,
        GitHubCredentials(token="x", source="server"),
        GitHubCredentials(source="anonymous"),
    ):
        with pytest.raises(PrivateRepositoryError) as exc:
            await fetch_repository(ref, Path("."), settings(), credentials)
        assert "sign in" in (exc.value.detail or "").lower()
        assert exc.value.status_code == 403


async def test_a_signed_in_user_may_still_analyse_their_own_private_repository(
    monkeypatch, tmp_path
):
    """The guard must not break the flow it exists to protect. Someone who
    granted `repo` has already proved to GitHub that they can see it."""
    import httpx

    from app.ingest.github import GitHubCredentials, RepositoryRef, fetch_repository

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        def json(self):
            return {"private": True, "default_branch": "main", "size": 10}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            return FakeResponse()

        def stream(self, *args, **kwargs):
            raise RuntimeError("reached the download, so the guard let it through")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())

    with pytest.raises(RuntimeError, match="guard let it through"):
        await fetch_repository(
            RepositoryRef("acme", "secret"),
            tmp_path,
            settings(),
            GitHubCredentials(token="u", source="user"),
        )


async def test_the_viewer_refuses_private_source_to_anonymous_callers(api, snapshot):
    """A report id is a read capability for the *report*. Findings quote a few
    lines; this serves whole files, so sharing the link must not hand over the
    source of a private repository."""
    from fastapi.testclient import TestClient

    from app.main import app

    report = make_report("r1", repository="acme/secret")
    report.source = SourceInfo(
        kind=SourceKind.REPOSITORY,
        repository="acme/secret",
        ref="main",
        commit="abc123",
        private=True,
    )
    await api.reports.save(report)

    with TestClient(app) as client:
        for path in ("/api/reports/r1/files", "/api/reports/r1/file?path=a.py"):
            response = client.get(path)
            assert response.status_code == 403, path
            assert "private" in response.json()["message"].lower()


async def test_a_public_report_is_still_readable_by_anyone(api, snapshot):
    """The guard must not touch the ordinary case — a shared report link is the
    whole point of an unguessable id."""
    from fastapi.testclient import TestClient

    from app.main import app

    report = make_report("r1", repository=None)
    report.source = SourceInfo(kind=SourceKind.UPLOAD, filename="project.zip")
    await api.reports.save(report)
    await api.blobs.put("r1", snapshot)

    with TestClient(app) as client:
        assert client.get("/api/reports/r1/files").status_code == 200


"""Wider context for AI actions"""


class FakeProvider:
    def __init__(self, text: str | None) -> None:
        self._text = text

    async def tree(self):  # pragma: no cover - not used here
        return []

    async def read(self, path: str) -> str:
        if self._text is None:
            raise SourceUnavailable("gone")
        return self._text


async def widen(monkeypatch, finding, text: str | None):
    from app.ai.prompts import MAX_CONTEXT_LINES  # noqa: F401
    from app.routers import ai as ai_module

    monkeypatch.setattr(
        ai_module, "provider_for", lambda *a, **k: FakeProvider(text)
    )
    report = make_report("r1", repository="acme/app")
    return await ai_module._wider_source(report, finding, settings(), None)


async def test_ai_context_is_widened_from_the_real_file(monkeypatch):
    """A ±3-line snippet is why Propose fix so often answered
    INSUFFICIENT_CONTEXT: three lines rarely hold the imports and the
    surrounding function a correct patch has to match."""
    from tests.test_api_flow import make_finding

    text = "\n".join(f"line {i}" for i in range(1, 401))
    finding = make_finding(id="f1", file="src/a.ts", line=200, end_line=200)

    result = await widen(monkeypatch, finding, text)

    assert result is not None
    code, first, last = result
    assert first < 200 < last, "the finding should sit inside the window"
    assert len(code.split("\n")) > 50, "much wider than the snippet"
    assert "line 200" in code


async def test_the_window_is_centred_so_clamping_cannot_cut_the_finding(monkeypatch):
    """`clamp_context` truncates from the start, so a window running off the
    end would lose the very lines the finding points at."""
    from app.ai.prompts import MAX_CONTEXT_LINES
    from tests.test_api_flow import make_finding

    text = "\n".join(f"line {i}" for i in range(1, 1001))
    finding = make_finding(id="f1", file="src/a.ts", line=500, end_line=500)

    _code, first, last = await widen(monkeypatch, finding, text)

    assert last - first + 1 <= MAX_CONTEXT_LINES
    assert first < 500 < last
    # Roughly centred, so the finding survives any later truncation.
    assert abs((500 - first) - (last - 500)) <= 2


async def test_a_finding_at_the_top_of_a_file_still_gets_a_full_window(monkeypatch):
    from app.ai.prompts import MAX_CONTEXT_LINES
    from tests.test_api_flow import make_finding

    text = "\n".join(f"line {i}" for i in range(1, 1001))
    finding = make_finding(id="f1", file="src/a.ts", line=1, end_line=1)

    _code, first, last = await widen(monkeypatch, finding, text)

    assert first == 1
    assert last == MAX_CONTEXT_LINES


async def test_unavailable_source_falls_back_to_the_snippet(monkeypatch):
    """A rate-limited GitHub or a deleted repository must degrade, not fail the
    action — the snippet still produces a useful explanation."""
    from tests.test_api_flow import make_finding

    finding = make_finding(id="f1", file="src/a.ts", line=10)
    assert await widen(monkeypatch, finding, None) is None


async def test_a_project_wide_finding_is_not_widened(monkeypatch):
    """There is no file to read, and inventing one would be worse than the
    honest "(no source captured)"."""
    from tests.test_api_flow import make_finding

    finding = make_finding(id="f1", file=None, line=None)
    assert await widen(monkeypatch, finding, "irrelevant") is None


def test_the_reported_context_says_when_only_the_snippet_was_used():
    """The UI shows this so someone knows what the model actually saw. It must
    not claim context that was never sent."""
    from app.routers.ai import _describe_context
    from tests.test_api_flow import make_finding

    finding = make_finding(id="f1", file="src/a.ts", line=10, end_line=10)

    assert "snippet only" in _describe_context(finding, "acme/app", None)
    assert "lines 5–120" in _describe_context(
        finding, "acme/app", ("code", 5, 120)
    )


@pytest.mark.parametrize(
    "status,expected",
    [
        (404, "force-push"),
        (403, "rate limit"),
        (401, "rate limit"),
        (500, "500"),
    ],
)
def test_github_failures_say_what_someone_can_do_about_them(status, expected):
    """"Unavailable" tells nobody anything. Each of these is a different
    situation with a different remedy."""
    from app.ingest.github import RepositoryRef

    provider = GitHubSourceProvider(
        RepositoryRef("acme", "app", "main"), "abc123", settings()
    )
    assert expected in provider._unavailable(status).reason.lower()
