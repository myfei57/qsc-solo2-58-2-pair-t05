"""Caller and purpose authorization for controlled reverse mapping."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from maskhub.errors import PermissionDenied, Unauthorized


@dataclass(frozen=True)
class PurposeGrant:
    caller: str
    purposes: frozenset[str]

    @classmethod
    def parse(cls, raw: str) -> "PurposeGrant | None":
        text = raw.strip()
        if not text or ":" not in text:
            return None
        caller, _, purposes = text.partition(":")
        caller = caller.strip()
        allowed = frozenset(item.strip() for item in purposes.split(",") if item.strip())
        if not caller or not allowed:
            return None
        return cls(caller=caller, purposes=allowed)


class PurposeAuthorizer:
    """In-process grant table consulted before a reverse mapping is returned."""

    def __init__(self, grants: Mapping[str, frozenset[str]] | None = None) -> None:
        self._grants = {caller: frozenset(purposes) for caller, purposes in (grants or {}).items()}

    @classmethod
    def from_config(cls, raw: str = "") -> "PurposeAuthorizer":
        grants: dict[str, frozenset[str]] = {}
        for section in raw.split(";"):
            grant = PurposeGrant.parse(section)
            if grant is not None:
                grants[grant.caller] = grant.purposes
        return cls(grants)

    def is_authorized(self, caller: str, purpose: str) -> bool:
        return bool(caller) and bool(purpose) and purpose in self._grants.get(caller, frozenset())

    def require(self, caller: str, purpose: str) -> None:
        if not caller:
            raise Unauthorized("x-caller-id is required for reverse mapping")
        if not purpose:
            raise PermissionDenied("x-purpose is required for reverse mapping")
        if not self.is_authorized(caller, purpose):
            raise PermissionDenied(f"caller {caller!r} is not authorized for purpose {purpose!r}")
