"""Data-plane endpoints for stable tokenization and controlled reverse mapping."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text
from maskhub.errors import NotFound, PermissionDenied, Unauthorized


def tokenize(runtime, request: Request) -> Response:
    payload = request.json_object()
    values = payload.get("values")
    if values is None and "value" in payload:
        values = [payload["value"]]
    tokens = runtime.mappings.tokenize(values)
    return Response.json(200, {"tokens": tokens})


def reveal_mapping(runtime, request: Request) -> Response:
    payload = request.json_object()
    token = optional_text(payload, "token")
    caller = request.headers.get("x-caller-id", "").strip()
    purpose = request.headers.get("x-purpose", "").strip() or optional_text(payload, "purpose")
    detail = f"purpose={purpose};token={token}"

    try:
        runtime.authorizer.require(caller, purpose)
    except (PermissionDenied, Unauthorized):
        runtime.journal.append("mapping.reveal.denied", caller or "anonymous", detail)
        raise

    record = runtime.mappings.reveal_record(token)
    target = record["digest"] if record is not None else token
    runtime.journal.append(
        "mapping.reveal",
        caller,
        f"{detail};target={target};found={'true' if record is not None else 'false'}",
    )
    if record is None:
        raise NotFound(f"unknown token {token!r}")
    return Response.json(200, {"token": token, "value": record["value"]})
