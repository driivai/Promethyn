"""The unforgeable candidate-start signal: tokens, transports, interpretation.

Fault classification rests on two questions a hostile candidate must not be
able to answer for us: did isolation start, and did the candidate definitely
begin executing? Both are carried by tokens a bootstrap emits at the moment
isolation is established, on a channel the candidate can neither read, forge,
nor suppress. Two transports carry the same signal:

* **Status pipe** (namespace adapter). The bootstrap writes plain tokens to an
  inherited pipe fd that is made close-on-exec before the candidate runs, so
  the candidate never holds the fd: it cannot write a token, and it cannot
  unsay one written before it ran. Setup failures and exec failures write
  their own tokens, so "the candidate never actually started" is positively
  distinguishable from "the candidate started and then crashed".

* **Nonce-keyed stream lines** (container adapter). No fd crosses the
  container boundary, so the host generates a fresh random nonce per run and
  sends it to the in-container bootstrap as the first line of stdin. The
  bootstrap consumes exactly that line before the candidate runs (the nonce is
  stored nowhere the candidate can read — not argv, not the environment, not a
  file) and emits ``<token>:<nonce>`` lines on stderr. The candidate may print
  anything, including the token names, but without the nonce it cannot forge
  the signal — and it cannot remove a line written before it ran.

The bootstrap scripts run standalone (``python -I`` inside the isolation
boundary) and cannot import this module, so they carry their own copies of the
token literals; a conformance test asserts the copies stay in sync.
"""

from __future__ import annotations

import secrets

#: Isolation is established and the candidate is about to be exec'd.
STARTED_TOKEN = b"prom-candidate-started"
#: The exec of the candidate failed after the started token was written: the
#: candidate never ran. Revokes a started token on the same channel.
EXEC_FAILED_TOKEN = b"prom-candidate-exec-failed"
#: Isolation setup failed before the candidate could be exec'd.
SETUP_FAILED_TOKEN = b"prom-sandbox-setup-failed"


# -- status-pipe transport (namespace adapter) --------------------------------


def pipe_candidate_started(data: bytes) -> bool:
    """Did the candidate definitely begin executing, per the status pipe?

    True only for a started token that was never revoked: an exec failure (the
    candidate never ran) or a setup failure on the same pipe wins over it.
    """

    return (
        STARTED_TOKEN in data
        and EXEC_FAILED_TOKEN not in data
        and SETUP_FAILED_TOKEN not in data
    )


def pipe_exec_failed(data: bytes) -> bool:
    return EXEC_FAILED_TOKEN in data


def pipe_setup_failed(data: bytes) -> bool:
    return SETUP_FAILED_TOKEN in data


# -- nonce-keyed stream transport (container adapter) --------------------------


def new_nonce() -> str:
    """A fresh per-run key for the stream transport (128 bits, hex)."""

    return secrets.token_hex(16)


def started_line(nonce: str) -> str:
    return f"{STARTED_TOKEN.decode('ascii')}:{nonce}"


def exec_failed_line(nonce: str) -> str:
    return f"{EXEC_FAILED_TOKEN.decode('ascii')}:{nonce}"


def interpret_stream(text: str | None, nonce: str) -> tuple[bool, str]:
    """Read the signal out of a stream: ``(candidate_started, cleaned_text)``.

    ``candidate_started`` is True only when the nonce-keyed started line is
    present and its nonce-keyed revocation is not. The returned text has the
    harness's own signal lines removed (they are transport, not candidate
    output); everything the candidate wrote — including any forged, un-keyed
    token text — is preserved verbatim.
    """

    if not text:
        return False, ""
    started = started_line(nonce)
    revoked = exec_failed_line(nonce)
    candidate_started = started in text and revoked not in text
    kept = [
        line
        for line in text.splitlines()
        if line.strip() not in (started, revoked)
    ]
    cleaned = "\n".join(kept)
    if kept and text.endswith("\n"):
        cleaned += "\n"
    return candidate_started, cleaned
