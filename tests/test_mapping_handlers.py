from __future__ import annotations

import json
import tempfile
import unittest

from maskhub.console.errors import error_response
from maskhub.console.handlers.mapping import reveal_mapping, tokenize
from maskhub.console.http import Request
from maskhub.console.runtime import build_runtime
from maskhub.errors import NotFound, PermissionDenied, Unauthorized


class MappingHandlerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from maskhub.store.kvstore import RecordStore

        store = RecordStore(self.temp.name)
        store.load()
        self.runtime = build_runtime(store, "billing:invoice-recovery")

    def post(self, path: str, payload: dict[str, object], headers: dict[str, str] | None = None):
        return Request(
            method="POST",
            path=path,
            query={},
            headers={name.lower(): value for name, value in (headers or {}).items()},
            body=json.dumps(payload).encode("utf-8"),
        )

    def body(self, response) -> dict[str, object]:
        return json.loads(response.payload.decode("utf-8"))

    def test_tokenize_returns_only_tokens_and_reuses_the_same_token(self) -> None:
        request = self.post("/tokenize", {"values": ["customer-1", "customer-1"]})
        response = tokenize(self.runtime, request)
        payload = self.body(response)

        self.assertEqual(response.status, 200)
        self.assertEqual(set(payload), {"tokens"})
        self.assertEqual(payload["tokens"][0], payload["tokens"][1])

        again = tokenize(self.runtime, self.post("/tokenize", {"values": ["customer-1"]}))
        self.assertEqual(self.body(again)["tokens"], [payload["tokens"][0]])

    def test_authorized_reveal_returns_value_and_writes_audit_entry(self) -> None:
        token = self.body(tokenize(self.runtime, self.post("/tokenize", {"values": ["secret-customer"]})))[
            "tokens"
        ][0]
        request = self.post(
            "/mapping/reveal",
            {"token": token},
            {"x-caller-id": "billing", "x-purpose": "invoice-recovery"},
        )

        response = reveal_mapping(self.runtime, request)

        self.assertEqual(response.status, 200)
        self.assertEqual(self.body(response)["value"], "secret-customer")
        entries = self.runtime.journal.by_action("mapping.reveal")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].subject, "billing")
        self.assertIn("invoice-recovery", entries[0].detail)
        self.assertIn(token, entries[0].detail)
        self.assertNotIn("secret-customer", entries[0].detail)

    def test_reveal_without_caller_is_unauthorized_and_audited(self) -> None:
        request = self.post(
            "/mapping/reveal",
            {"token": "tok_unknown"},
            {"x-purpose": "invoice-recovery"},
        )

        with self.assertRaises(Unauthorized):
            reveal_mapping(self.runtime, request)
        self.assertEqual(
            error_response(Unauthorized("x")).status,
            401,
        )
        self.assertEqual(len(self.runtime.journal.by_action("mapping.reveal.denied")), 1)

    def test_reveal_without_purpose_grant_is_denied_and_audited(self) -> None:
        request = self.post(
            "/mapping/reveal",
            {"token": "tok_unknown"},
            {"x-caller-id": "billing", "x-purpose": "bulk-export"},
        )

        with self.assertRaises(PermissionDenied):
            reveal_mapping(self.runtime, request)
        self.assertEqual(error_response(PermissionDenied("x")).status, 403)
        self.assertEqual(len(self.runtime.journal.by_action("mapping.reveal.denied")), 1)

    def test_authorized_unknown_token_is_not_found_and_audited(self) -> None:
        request = self.post(
            "/mapping/reveal",
            {"token": "tok_missing"},
            {"x-caller-id": "billing", "x-purpose": "invoice-recovery"},
        )

        with self.assertRaises(NotFound):
            reveal_mapping(self.runtime, request)
        entries = self.runtime.journal.by_action("mapping.reveal")
        self.assertEqual(len(entries), 1)
        self.assertIn("found=false", entries[0].detail)


if __name__ == "__main__":
    unittest.main()
