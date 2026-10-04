from __future__ import annotations

import tempfile
import threading
import unittest

from maskhub.mapping.registry import MappingRegistry, digest_for
from maskhub.store.kvstore import RecordStore


class MappingRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = RecordStore(self.temp.name)
        self.store.load()
        self.mappings = MappingRegistry(self.store)

    def test_same_value_gets_same_token_within_and_across_batches(self) -> None:
        first = self.mappings.tokenize(["customer-42", "other"])
        second = self.mappings.tokenize(["customer-42"])

        self.assertEqual(first[0], second[0])
        self.assertNotEqual(first[0], first[1])
        self.assertEqual(self.mappings.reveal(first[0]), "customer-42")

    def test_duplicate_values_in_one_batch_share_a_mapping(self) -> None:
        tokens = self.mappings.tokenize(["same", "same", "same"])

        self.assertEqual(tokens, [tokens[0], tokens[0], tokens[0]])
        self.assertEqual(self.mappings.count(), 1)

    def test_concurrent_new_values_do_not_split_mappings_or_reuse_tokens(self) -> None:
        barrier = threading.Barrier(8)

        def tokenize_unique(value: str, result: dict[str, list[str]]) -> None:
            barrier.wait()
            result[value] = self.mappings.tokenize([value])

        results: dict[str, list[str]] = {}
        threads = [
            threading.Thread(target=tokenize_unique, args=(f"value-{index}", results))
            for index in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        tokens = [result[0] for result in results.values()]
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertEqual(self.mappings.count(), 8)

    def test_concurrent_same_value_returns_one_token(self) -> None:
        barrier = threading.Barrier(6)
        results: list[str] = []
        lock = threading.Lock()

        def tokenize_same_value() -> None:
            barrier.wait()
            token = self.mappings.tokenize(["shared-value"])[0]
            with lock:
                results.append(token)

        threads = [threading.Thread(target=tokenize_same_value) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(set(results), {results[0]})
        self.assertEqual(self.mappings.count(), 1)

    def test_state_is_reloaded_from_disk(self) -> None:
        token = self.mappings.tokenize(["persisted"])[0]
        reloaded_store = RecordStore(self.temp.name)
        reloaded_store.load()
        reloaded = MappingRegistry(reloaded_store)

        self.assertEqual(reloaded.reveal(token), "persisted")
        self.assertEqual(reloaded.count(), 1)

    def test_reveal_record_exposes_digest_without_using_value_as_key(self) -> None:
        token = self.mappings.tokenize(["secret"])[0]
        record = self.mappings.reveal_record(token)

        self.assertIsNotNone(record)
        self.assertEqual(record["digest"], digest_for("secret"))
        self.assertEqual(record["value"], "secret")


if __name__ == "__main__":
    unittest.main()
