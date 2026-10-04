"""End-to-end checks for the tokenization vault over HTTP."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from maskhub.console.routes import build_router
from maskhub.console.runtime import build_runtime
from maskhub.console.server import ConsoleServer
from maskhub.store.kvstore import RecordStore


def call(server: ConsoleServer, method: str, path: str, payload: object = None) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        server.url + path, data=body, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class TokenVaultTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name) / "data"
        store = RecordStore(self.data_dir)
        store.load()
        self.runtime = build_runtime(store)
        self.server = ConsoleServer(build_router(self.runtime), "127.0.0.1", 0)
        self.server.start()
        self.addCleanup(self.server.stop)

    def tokenize(self, values: list[str]) -> list[str]:
        status, body = call(self.server, "POST", "/tokens", {"values": values})
        self.assertEqual(status, 200)
        return body["tokens"]

    def grant(self, caller: str = "analyst", purpose: str = "fraud-review") -> None:
        status, _ = call(
            self.server,
            "POST",
            "/token/grant",
            {"caller": caller, "purpose": purpose, "granted_by": "admin"},
        )
        self.assertEqual(status, 200)

    def detokenize(self, tokens: list[str], caller: str = "analyst", purpose: str = "fraud-review"):
        return call(
            self.server,
            "POST",
            "/token/detokenize",
            {"tokens": tokens, "caller": caller, "purpose": purpose},
        )

    def test_same_value_maps_to_same_token_across_pipelines(self):
        orders = self.tokenize(["cust-1", "cust-2"])
        calls = self.tokenize(["cust-2", "cust-1"])
        self.assertEqual(orders[0], calls[1])
        self.assertEqual(orders[1], calls[0])
        self.assertEqual(self.runtime.vault.count(), 2)

    def test_concurrent_batches_converge_on_one_token_per_value(self):
        values = [f"cust-{index}" for index in range(50)]
        barrier = threading.Barrier(8)
        results: list[list[str]] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=10)
                results.append(self.tokenize(values))
            except Exception as exc:  # noqa: BLE001 - surfaced by assertion
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertFalse(errors)
        self.assertEqual(len(results), 8)
        for result in results[1:]:
            self.assertEqual(result, results[0])
        self.assertEqual(len(set(results[0])), len(values))
        self.assertEqual(self.runtime.vault.count(), len(values))

    def test_detokenize_without_grant_is_denied_and_journaled(self):
        tokens = self.tokenize(["cust-1"])
        status, _ = self.detokenize(tokens)
        self.assertEqual(status, 403)
        denied = self.runtime.journal.by_action("token.detokenize.denied")
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].subject, "analyst")
        self.assertIn("fraud-review", denied[0].detail)
        self.assertIn(tokens[0], denied[0].detail)
        self.assertTrue(denied[0].at)

    def test_granted_detokenize_returns_values_and_is_journaled(self):
        tokens = self.tokenize(["cust-1", "cust-2"])
        self.grant()
        status, body = self.detokenize(tokens)
        self.assertEqual(status, 200)
        self.assertEqual(body["values"], ["cust-1", "cust-2"])
        entries = self.runtime.journal.by_action("token.detokenize")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].subject, "analyst")
        self.assertIn("purpose=fraud-review", entries[0].detail)
        self.assertIn(tokens[0], entries[0].detail)

    def test_wrong_purpose_is_denied(self):
        tokens = self.tokenize(["cust-1"])
        self.grant(purpose="fraud-review")
        status, _ = self.detokenize(tokens, purpose="marketing")
        self.assertEqual(status, 403)

    def test_revoke_closes_access(self):
        tokens = self.tokenize(["cust-1"])
        self.grant()
        status, _ = call(
            self.server,
            "POST",
            "/token/revoke",
            {"caller": "analyst", "purpose": "fraud-review", "revoked_by": "admin"},
        )
        self.assertEqual(status, 200)
        status, _ = self.detokenize(tokens)
        self.assertEqual(status, 403)

    def test_unknown_token_resolves_to_none(self):
        self.grant()
        status, body = self.detokenize(["tok_missing"])
        self.assertEqual(status, 200)
        self.assertEqual(body["values"], [None])

    def test_tokenize_response_carries_no_mapping(self):
        status, body = call(self.server, "POST", "/tokens", {"values": ["cust-1"]})
        self.assertEqual(status, 200)
        self.assertEqual(sorted(body), ["count", "tokens"])

    def test_vault_has_no_listing_route(self):
        status, _ = call(self.server, "GET", "/tokens")
        self.assertEqual(status, 405)

    def test_mappings_survive_restart(self):
        first = self.tokenize(["cust-1"])
        store = RecordStore(self.data_dir)
        store.load()
        runtime = build_runtime(store)
        self.assertEqual(runtime.vault.tokenize(["cust-1"]), first)

    def test_empty_values_rejected(self):
        status, _ = call(self.server, "POST", "/tokens", {"values": []})
        self.assertEqual(status, 400)
        status, _ = call(self.server, "POST", "/tokens", {"values": ["  "]})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
