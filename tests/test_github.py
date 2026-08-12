"""Repository URL parsing — the primary way code enters the product."""

from __future__ import annotations

import pytest

from app.errors import InvalidRepositoryError
from app.ingest.github import parse_repository_url


@pytest.mark.parametrize(
    "value,owner,repo,ref",
    [
        ("https://github.com/facebook/react", "facebook", "react", None),
        ("http://github.com/facebook/react", "facebook", "react", None),
        ("github.com/facebook/react", "facebook", "react", None),
        ("https://www.github.com/facebook/react", "facebook", "react", None),
        ("https://github.com/facebook/react/", "facebook", "react", None),
        ("https://github.com/facebook/react.git", "facebook", "react", None),
        ("git@github.com:facebook/react.git", "facebook", "react", None),
        ("facebook/react", "facebook", "react", None),
        ("https://github.com/facebook/react/tree/main", "facebook", "react", "main"),
        ("https://github.com/vercel/next.js", "vercel", "next.js", None),
        ("https://github.com/a-b/c_d.e-f", "a-b", "c_d.e-f", None),
        ("  https://github.com/facebook/react  ", "facebook", "react", None),
        ("https://github.com/facebook/react?tab=readme", "facebook", "react", None),
    ],
)
def test_accepts_the_shapes_developers_paste(value, owner, repo, ref):
    parsed = parse_repository_url(value)
    assert (parsed.owner, parsed.repo, parsed.ref) == (owner, repo, ref)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not a url",
        "https://gitlab.com/foo/bar",
        "https://github.com/onlyowner",
        "https://example.com/facebook/react",
        "ftp://github.com/a/b",
    ],
)
def test_rejects_everything_else(value):
    with pytest.raises(InvalidRepositoryError):
        parse_repository_url(value)


def test_full_name_and_url_are_derived():
    parsed = parse_repository_url("https://github.com/facebook/react/tree/v18")
    assert parsed.full_name == "facebook/react"
    assert parsed.html_url == "https://github.com/facebook/react"
    assert parsed.ref == "v18"
