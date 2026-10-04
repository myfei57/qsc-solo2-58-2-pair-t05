"""Tokenization vault endpoints."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import require_text, require_text_list
from maskhub.errors import Forbidden, NotFound


def tokenize(runtime, request: Request) -> Response:
    """Mint tokens for a batch of raw values.

    Returns tokens positionally aligned with the submitted values and
    nothing else — the vault's mapping is never exposed on this path.
    """
    payload = request.json_object()
    values = require_text_list(payload, "values")
    tokens = runtime.vault.tokenize(values)
    return Response.json(200, {"count": len(tokens), "tokens": tokens})


def detokenize(runtime, request: Request) -> Response:
    """Reverse tokens for a caller holding a matching purpose grant.

    Every attempt, allowed or denied, is journaled with the caller, the
    purpose, and the tokens touched, so reversals stay answerable later.
    """
    payload = request.json_object()
    tokens = require_text_list(payload, "tokens")
    caller = require_text(payload, "caller")
    purpose = require_text(payload, "purpose")
    detail = f"purpose={purpose} tokens={','.join(tokens)}"
    if not runtime.grants.allows(caller, purpose):
        runtime.journal.append("token.detokenize.denied", caller, detail)
        raise Forbidden(f"caller {caller!r} holds no grant for purpose {purpose!r}")
    values = runtime.vault.detokenize(tokens)
    runtime.journal.append("token.detokenize", caller, detail)
    return Response.json(200, {"count": len(values), "values": values})


def grant(runtime, request: Request) -> Response:
    payload = request.json_object()
    caller = require_text(payload, "caller")
    purpose = require_text(payload, "purpose")
    granted_by = require_text(payload, "granted_by")
    runtime.grants.grant(caller, purpose, granted_by)
    runtime.journal.append("token.grant", granted_by, f"caller={caller} purpose={purpose}")
    return Response.json(200, {"caller": caller, "purpose": purpose, "granted_by": granted_by})


def revoke(runtime, request: Request) -> Response:
    payload = request.json_object()
    caller = require_text(payload, "caller")
    purpose = require_text(payload, "purpose")
    revoked_by = require_text(payload, "revoked_by")
    if not runtime.grants.revoke(caller, purpose):
        raise NotFound(f"no grant for caller {caller!r} purpose {purpose!r}")
    runtime.journal.append("token.revoke", revoked_by, f"caller={caller} purpose={purpose}")
    return Response.json(200, {"caller": caller, "purpose": purpose, "revoked": True})


def list_grants(runtime, request: Request) -> Response:
    grants = runtime.grants.as_dict()
    return Response.json(
        200,
        {"count": sum(len(purposes) for purposes in grants.values()), "grants": grants},
    )


def token_stats(runtime, request: Request) -> Response:
    """Report how many mappings exist without exposing any of them."""
    return Response.json(200, {"tokens": runtime.vault.count()})
