"""Shared rate limiter.

Lives in its own module so routers can apply per-route limits without importing
``app.main`` (which imports the routers).
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["240/hour"])
