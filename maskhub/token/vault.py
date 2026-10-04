"""Deterministic tokenization vault shared by every pipeline.

One original value maps to exactly one token for the whole gateway, so
datasets processed independently (orders, calls, ...) stay joinable on the
token. Reversal is only possible through the grant-guarded detokenize path;
this module itself never lists or dumps the mapping.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from maskhub.errors import InvalidRequest
from maskhub.store.kvstore import RecordStore
from maskhub.store.query import count_with_prefix, keys_with_prefix

MAP_PREFIX = "token.map."
SECRET_KEY = "token.secret"
TOKEN_PREFIX = "tok_"


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidRequest("values must be non-empty strings")
    return value.strip()


@dataclass(frozen=True)
class TokenRecord:
    token: str
    value: str
    created_at: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "TokenRecord | None":
        if not isinstance(payload, dict):
            return None
        token = payload.get("token")
        value = payload.get("value")
        created_at = payload.get("created_at", "")
        if not all(isinstance(item, str) for item in (token, value, created_at)):
            return None
        return cls(token=token, value=value, created_at=created_at)


class TokenVault:
    """Get-or-create token allocation guarded by the store lock."""

    def __init__(self, store: RecordStore) -> None:
        self._store = store
        self._secret = self._load_secret()

    def tokenize(self, values: list[str]) -> list[str]:
        """Return one token per input value, positionally aligned.

        Each allocation is an atomic read-modify-write on the value's digest
        key: concurrent batches containing the same new value converge on a
        single token instead of racing into two.
        """
        return [self._tokenize_one(value) for value in values]

    def detokenize(self, tokens: list[str]) -> "list[str | None]":
        """Resolve tokens to original values; unknown tokens yield None.

        Scans the vault per call. Reversal is a rare, privileged operation,
        so no reverse index is maintained and there is one source of truth.
        """
        records = self._by_token()
        return [records[token].value if token in records else None for token in tokens]

    def count(self) -> int:
        return count_with_prefix(self._store, MAP_PREFIX)

    def _tokenize_one(self, value: object) -> str:
        normalized = normalize(value)
        key = MAP_PREFIX + self._digest(normalized)

        def allocate(document: object) -> tuple[object, str]:
            record = TokenRecord.from_dict(document)
            if record is not None:
                return None, record.token
            minted = TokenRecord(
                token=TOKEN_PREFIX + secrets.token_hex(16),
                value=normalized,
                created_at=utcnow(),
            )
            return minted.as_dict(), minted.token

        return self._store.update_json(key, allocate)

    def _digest(self, value: str) -> str:
        return hmac.new(self._secret, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _by_token(self) -> dict[str, TokenRecord]:
        records: dict[str, TokenRecord] = {}
        for key in keys_with_prefix(self._store, MAP_PREFIX):
            record = TokenRecord.from_dict(self._store.get_json(key))
            if record is not None:
                records[record.token] = record
        return records

    def _load_secret(self) -> bytes:
        """Load or mint the HMAC secret, persisted so digests survive restarts."""

        def ensure(document: object) -> tuple[object, str]:
            if isinstance(document, dict) and isinstance(document.get("secret"), str):
                return None, document["secret"]
            secret = secrets.token_hex(32)
            return {"secret": secret}, secret

        return self._store.update_json(SECRET_KEY, ensure).encode("utf-8")
