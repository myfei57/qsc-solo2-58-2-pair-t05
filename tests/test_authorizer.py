from __future__ import annotations

import unittest

from maskhub.errors import PermissionDenied, Unauthorized
from maskhub.mapping.authorizer import PurposeAuthorizer


class PurposeAuthorizerTest(unittest.TestCase):
    def test_grants_are_scoped_to_caller_and_purpose(self) -> None:
        authorizer = PurposeAuthorizer.from_config("billing:invoice-recovery;ops:support,audit")

        self.assertTrue(authorizer.is_authorized("billing", "invoice-recovery"))
        self.assertTrue(authorizer.is_authorized("ops", "audit"))
        self.assertFalse(authorizer.is_authorized("billing", "audit"))
        self.assertFalse(authorizer.is_authorized("unknown", "invoice-recovery"))

    def test_missing_identity_is_unauthorized(self) -> None:
        authorizer = PurposeAuthorizer.from_config("billing:invoice-recovery")

        with self.assertRaises(Unauthorized):
            authorizer.require("", "invoice-recovery")

    def test_known_caller_without_purpose_grant_is_denied(self) -> None:
        authorizer = PurposeAuthorizer.from_config("billing:invoice-recovery")

        with self.assertRaises(PermissionDenied):
            authorizer.require("billing", "bulk-export")

    def test_authorized_purpose_passes(self) -> None:
        authorizer = PurposeAuthorizer.from_config("billing:invoice-recovery")

        self.assertIsNone(authorizer.require("billing", "invoice-recovery"))


if __name__ == "__main__":
    unittest.main()
