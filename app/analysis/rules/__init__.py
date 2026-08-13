"""Rule implementations.

Importing this package registers every rule with the engine registry.
"""

from app.analysis.rules import (  # noqa: F401
    configuration,
    dependencies,
    python,
    quality,
    react,
    secrets,
)
