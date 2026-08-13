"""Single-purpose credentials for the one request that cannot carry a session.

A ZIP upload posts **directly** to this API rather than through the frontend's
server, because serverless platforms cap proxied request bodies at a few
megabytes. That request therefore cannot carry the session cookie — it is
HttpOnly and first-party to the frontend's origin — so every signed-in user's
upload was recorded as anonymous.

An upload ticket closes that gap without widening anything else. It is minted
only for someone who already has a session, it says nothing except "this is
user X", and it expires in minutes.

**Fernet, not a bearer token.** The session token itself must never reach
JavaScript, which is the whole point of the HttpOnly cookie; handing it to the
browser to attach to an upload would trade a real protection for a convenience.
A ticket is a separate, narrow credential that authorises one thing.

**Stateless, like the OAuth `state`.** Fernet carries its own timestamp, so
expiry needs no storage, and Render runs more than one worker — a nonce table
would have to be shared to be worth anything. The cost is that a ticket is
replayable within its lifetime: someone who intercepted one could attribute
*their* upload to *your* account for a few minutes. That is a nuisance rather
than a disclosure — it cannot read anything — and it is the same exposure the
upload request itself already has.
"""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken

from app.auth.tokens import TokenCipherUnavailable, _cipher
from app.config import Settings

logger = logging.getLogger(__name__)

# Long enough to pick a file and start an upload, short enough that a leaked
# ticket is not worth reusing. The archive can take far longer than this to
# transfer — the ticket is checked when the request arrives, not when it ends.
TICKET_TTL_SECONDS = 600

_PREFIX = "upload:"


def issue_upload_ticket(user_id: str, settings: Settings) -> str:
    """Mint a ticket attributing one upload to ``user_id``."""
    cipher: Fernet = _cipher(settings)
    return cipher.encrypt(f"{_PREFIX}{user_id}".encode("utf-8")).decode("ascii")


def redeem_upload_ticket(ticket: str, settings: Settings) -> str | None:
    """The user this ticket belongs to, or ``None`` if it is not usable.

    Every failure is the same answer — the upload proceeds anonymously — so an
    expired or forged ticket degrades rather than rejecting a perfectly good
    archive someone just spent a minute uploading.
    """
    if not ticket:
        return None
    try:
        raw = _cipher(settings).decrypt(
            ticket.encode("ascii"), ttl=TICKET_TTL_SECONDS
        )
    except InvalidToken:
        logger.info("An upload ticket was expired or invalid; treating as anonymous.")
        return None
    except TokenCipherUnavailable:
        # Sign-in is not configured, so there was no ticket to honour anyway.
        return None
    except Exception:
        logger.exception("Unexpected failure reading an upload ticket")
        return None

    text = raw.decode("utf-8", errors="replace")
    # The prefix stops a ticket being swapped for any other Fernet value this
    # key protects — stored GitHub tokens use the same cipher.
    if not text.startswith(_PREFIX):
        logger.warning("A Fernet value that is not an upload ticket was presented.")
        return None

    user_id = text[len(_PREFIX) :]
    return user_id or None
