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
from app.source.blobs import InMemoryBlobStore, MAX_STORED_FILES
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
