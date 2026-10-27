import unittest
from unittest.mock import patch

from secure_agent.__main__ import terminal_approval


class TerminalApprovalTests(unittest.TestCase):
    @patch("builtins.print")
    def test_only_explicit_approval_words_are_accepted(self, _print):
        proposal = {"operation": "delete_document", "doc_id": "eng-roadmap"}
        for response in ["yes", "approve", "YES", " Approve "]:
            with self.subTest(response=response), patch("builtins.input", return_value=response):
                self.assertTrue(terminal_approval(proposal))
        for response in ["", "no", "y", "true", "yes please", "DELETE eng-roadmap"]:
            with self.subTest(response=response), patch("builtins.input", return_value=response):
                self.assertFalse(terminal_approval(proposal))

    @patch("builtins.print")
    def test_interruption_rejects(self, _print):
        for exception in [EOFError, KeyboardInterrupt]:
            with self.subTest(exception=exception), patch("builtins.input", side_effect=exception):
                self.assertFalse(terminal_approval({"doc_id": "eng-roadmap"}))
