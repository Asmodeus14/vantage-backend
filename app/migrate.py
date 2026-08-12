"""Run database migrations, as a deploy step.

Invoked from ``render.yaml`` before uvicorn starts. It **always exits 0**: a
failed migration must degrade the service, not prevent it from booting. The
schema state is reported by ``/api/health`` so the degradation is visible rather
than silent.

    python -m app.migrate
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app.migrate")

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    from app.config import get_settings

    settings = get_settings()
    if not settings.db_configured:
        logger.info("No DATABASE_URL; nothing to migrate.")
        return 0

    try:
        from alembic import command
        from alembic.config import Config

        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "alembic"))
        command.upgrade(config, "head")
        logger.info("Migrations applied.")
    except Exception:
        # Deliberately swallowed. A bad migration should leave the previous
        # revision running, not take the service down on boot.
        logger.exception("Migrations failed; starting anyway on the current schema.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
