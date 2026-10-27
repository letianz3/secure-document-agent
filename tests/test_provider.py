"""Contract tests for the live adapter; HTTP is mocked, not live model evidence."""
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from secure_agent.models import GoogleModel
from secure_agent.security import Rejected


class ProviderTests(unittest.TestCase):
    def payload(self, text, finish="STOP"):
        return io.BytesIO(json.dumps({"candidates": [{"finishReason": finish,
            "content": {"parts": [{"text": text}]}}]}).encode())

    @patch("secure_agent.models.urllib.request.urlopen")
    def test_request_and_tool_response_contract(self, request):
        request.return_value = self.payload('{"tool":"read_document","args":{"doc_id":"handbook"}}')
        result = GoogleModel("FAKE-TEST-KEY").next([{"kind": "user_request", "text": "Read handbook"}])
        self.assertEqual(result["tool"], "read_document")
        sent = request.call_args.args[0]
        self.assertNotIn("FAKE-TEST-KEY", sent.full_url)
        self.assertNotIn("FAKE-TEST-KEY", sent.data.decode())
        self.assertEqual(sent.get_header("X-goog-api-key"), "FAKE-TEST-KEY")
        self.assertEqual(request.call_args.kwargs["timeout"], 30)
        body = json.loads(sent.data)
        self.assertEqual(body["contents"][0]["role"], "user")

    @patch("secure_agent.models.urllib.request.urlopen")
    def test_truncated_response_rejected(self, request):
        request.return_value = self.payload('{"final":"partial"}', "MAX_TOKENS")
        with self.assertRaises(Rejected):
            GoogleModel("FAKE-TEST-KEY").next([])

    @patch("secure_agent.models.urllib.request.urlopen")
    def test_http_error_does_not_expose_response_body_or_key(self, request):
        request.side_effect = urllib.error.HTTPError("https://example.test", 403,
            "SECRET-ERROR", {}, io.BytesIO(b"SECRET-BODY"))
        with self.assertRaises(Rejected) as caught:
            GoogleModel("FAKE-TEST-KEY").next([])
        self.assertIn("403", str(caught.exception))
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertNotIn("FAKE-TEST-KEY", str(caught.exception))

    @patch("secure_agent.models.urllib.request.urlopen")
    def test_empty_candidates_rejected(self, request):
        request.return_value = io.BytesIO(b'{"candidates":[]}')
        with self.assertRaises(Rejected):
            GoogleModel("FAKE-TEST-KEY").next([])


if __name__ == "__main__":
    unittest.main()
