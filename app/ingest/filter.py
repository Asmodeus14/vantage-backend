"""Deciding what is worth analysing.

Keeps v2's good instinct — the user should not have to hand-prune
``node_modules`` before submitting — while fixing its ordering bug: v2 deleted
vendor directories first and *then* tried to rescue ``package.json`` out of
them, so the rescue could never find anything.

Here nothing is deleted. Files are classified as they are walked, which is
cheaper (no repeated ``rglob`` size passes) and non-destructive.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

# Directories whose contents are dependency payloads or build output. Their
# manifests are still read; their contents are not analysed.
SKIP_DIRECTORIES = frozenset(
    {
        "node_modules", ".git", ".hg", ".svn", "dist", "build", "out",
        ".next", ".nuxt", ".output", ".svelte-kit", ".astro",
        "coverage", ".nyc_output", ".cache", ".parcel-cache", ".turbo",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
        "venv", ".venv", "env", "menv", "site-packages", "vendor",
        "bower_components", ".yarn", ".pnp", ".gradle", "target",
        ".idea", ".vscode", ".DS_Store", "tmp", "temp", "logs",
        ".terraform", "Pods", ".dart_tool",
    }
)

# Manifests and configuration that must be read even when they sit inside a
# skipped directory (e.g. a workspace package under a pruned path).
ALWAYS_READ = frozenset(
    {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "composer.json",
        "Gemfile", "Gemfile.lock", "tsconfig.json", "jsconfig.json",
        "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".gitignore", ".dockerignore", ".npmrc",
    }
)

# Binary or generated content: never useful to read as source.
SKIP_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp", ".avif",
        ".ico", ".icns", ".svg",
        ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mkv",
        ".mp3", ".wav", ".ogg", ".flac", ".m4a",
        ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".apk", ".msi",
        ".pyc", ".pyo", ".class", ".o", ".a", ".obj", ".pdb",
        ".map", ".min.js", ".min.css", ".lock",
        ".db", ".sqlite", ".sqlite3", ".bin", ".dat", ".wasm",
    }
)

LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".mts": "typescript",
    ".cts": "typescript", ".tsx": "typescript",
    ".py": "python", ".pyi": "python",
    ".rb": "ruby", ".go": "go", ".rs": "rust", ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".cs": "csharp", ".php": "php", ".scala": "scala", ".ex": "elixir",
    ".exs": "elixir", ".dart": "dart", ".lua": "lua", ".r": "r",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "powershell",
    ".sql": "sql", ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss", ".sass": "sass", ".less": "less",
    ".vue": "vue", ".svelte": "svelte", ".astro": "astro",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".xml": "xml", ".md": "markdown", ".mdx": "markdown", ".rst": "restructuredtext",
    ".graphql": "graphql", ".gql": "graphql", ".proto": "protobuf",
    ".tf": "terraform", ".hcl": "hcl",
}

# Languages we run source-level rules against.
ANALYSABLE_LANGUAGES = frozenset(
    {
        "javascript", "typescript", "python", "ruby", "go", "rust", "java",
        "kotlin", "swift", "c", "cpp", "csharp", "php", "vue", "svelte",
        "astro", "shell", "css", "scss", "html",
    }
)


def detect_language(path: PurePosixPath | Path) -> str | None:
    name = path.name.lower()
    if name in {"dockerfile", "makefile", "rakefile", "gemfile", "procfile"}:
        return name
    # Handle compound suffixes such as ".min.js" before the simple case.
    for compound in (".min.js", ".min.css", ".d.ts"):
        if name.endswith(compound):
            return None
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def is_skipped_directory(relative: PurePosixPath) -> bool:
    return any(part in SKIP_DIRECTORIES for part in relative.parts[:-1])


def should_read(relative: PurePosixPath) -> bool:
    """Whether the file's contents are worth loading at all.

    Order matters. The skip-directory check must win over ``ALWAYS_READ``:
    that list exists to rescue *the project's own* manifests from pruned build
    output, not to pull in the manifest of every vendored package. Checking
    ALWAYS_READ first made a project with node_modules present report 800+
    dependencies belonging to its dependencies.
    """
    if is_skipped_directory(relative):
        return False
    if relative.name.lower() in ALWAYS_READ:
        return True
    if relative.suffix.lower() in SKIP_EXTENSIONS:
        return False
    name = relative.name.lower()
    if name.endswith((".min.js", ".min.css", ".map")):
        return False
    return True


def should_analyse(relative: PurePosixPath) -> bool:
    """Whether source-level rules should run against the file."""
    if is_skipped_directory(relative):
        return False
    language = detect_language(relative)
    return language in ANALYSABLE_LANGUAGES
