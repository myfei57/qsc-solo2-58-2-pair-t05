"""Purpose-scoped grants controlling who may reverse tokens."""

from __future__ import annotations

from maskhub.store.kvstore import RecordStore
from maskhub.token.vault import utcnow

GRANTS_KEY = "token.grants"


class GrantRegistry:
    """Maps caller -> purpose -> grant metadata in one atomically updated document."""

    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def grant(self, caller: str, purpose: str, granted_by: str) -> None:
        def mutate(document: object) -> tuple[object, None]:
            grants = _normalize(document)
            purposes = dict(grants.get(caller, {}))
            purposes[purpose] = {"granted_by": granted_by, "granted_at": utcnow()}
            grants[caller] = purposes
            return grants, None

        self._store.update_json(GRANTS_KEY, mutate)

    def revoke(self, caller: str, purpose: str) -> bool:
        def mutate(document: object) -> tuple[object, bool]:
            grants = _normalize(document)
            purposes = dict(grants.get(caller, {}))
            if purpose not in purposes:
                return None, False
            del purposes[purpose]
            if purposes:
                grants[caller] = purposes
            else:
                grants.pop(caller, None)
            return grants, True

        return self._store.update_json(GRANTS_KEY, mutate)

    def allows(self, caller: str, purpose: str) -> bool:
        return purpose in _normalize(self._store.get_json(GRANTS_KEY)).get(caller, {})

    def as_dict(self) -> dict[str, dict[str, object]]:
        return _normalize(self._store.get_json(GRANTS_KEY))


def _normalize(document: object) -> dict[str, dict[str, object]]:
    if not isinstance(document, dict):
        return {}
    grants: dict[str, dict[str, object]] = {}
    for caller, purposes in document.items():
        if isinstance(caller, str) and isinstance(purposes, dict):
            grants[caller] = dict(purposes)
    return grants
