"""Global, persistent get-or-create storage for reversible tokens."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from maskhub.errors import InvalidRequest
from maskhub.store.kvstore import RecordStore

STATE_KEY = "mapping.global"
TOKEN_PREFIX = "tok_"
TOKEN_BYTES = 16
DOCUMENT_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def digest_for(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8"))
    return digest.hexdigest()


class MappingRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def tokenize(self, values: list[str]) -> list[str]:
        """Return one stable token per value, creating mappings for new values."""

        normalized = _require_values(values)
        unique_values = list(dict.fromkeys(normalized))

        def mutate(document: object) -> tuple[object, list[str]]:
            state = _normalize_state(document)
            mappings = state["mappings"]
            tokens = state["tokens"]
            created_at = _now()
            for value in unique_values:
                digest = digest_for(value)
                existing = mappings.get(digest)
                if existing is not None:
                    continue
                token = _new_token(tokens)
                mappings[digest] = {
                    "value": value,
                    "token": token,
                    "created_at": created_at,
                }
                tokens[token] = digest
            result = [mappings[digest_for(value)]["token"] for value in normalized]
            return state, result

        return self._store.update_json(STATE_KEY, mutate)

    def reveal_record(self, token: str) -> dict[str, str] | None:
        if not isinstance(token, str) or not token:
            raise InvalidRequest("token must be a non-empty string")
        state = _normalize_state(self._store.get_json(STATE_KEY))
        digest = state["tokens"].get(token)
        if digest is None:
            return None
        mapping = state["mappings"].get(digest)
        if mapping is None:
            return None
        return {
            "token": token,
            "digest": digest,
            "value": mapping["value"],
            "created_at": mapping["created_at"],
        }

    def reveal(self, token: str) -> str | None:
        record = self.reveal_record(token)
        return record["value"] if record is not None else None

    def count(self) -> int:
        state = _normalize_state(self._store.get_json(STATE_KEY))
        return len(state["mappings"])


def _require_values(values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise InvalidRequest("values must be a non-empty list")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise InvalidRequest("values entries must be non-empty strings")
        normalized.append(value)
    return normalized


def _normalize_state(document: object) -> dict[str, object]:
    if document is None:
        return {"version": DOCUMENT_VERSION, "mappings": {}, "tokens": {}}
    if not isinstance(document, dict):
        raise InvalidRequest("mapping state is invalid")
    mappings = document.get("mappings")
    tokens = document.get("tokens")
    if not isinstance(mappings, dict) or not isinstance(tokens, dict):
        raise InvalidRequest("mapping state is invalid")
    return {"version": DOCUMENT_VERSION, "mappings": mappings, "tokens": tokens}


def _new_token(existing_tokens: dict[str, str]) -> str:
    while True:
        token = TOKEN_PREFIX + secrets.token_hex(TOKEN_BYTES)
        if token not in existing_tokens:
            return token
