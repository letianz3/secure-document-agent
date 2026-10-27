import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_agent.credentials import configured_key, load_key, save_key


class CredentialTests(unittest.TestCase):
    def test_environment_precedes_local_storage(self):
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "FAKE-ENV-KEY"}), \
             patch("secure_agent.credentials.load_key") as local:
            self.assertEqual(configured_key(), "FAKE-ENV-KEY")
            local.assert_not_called()

    def test_missing_local_key(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertIsNone(load_key(Path(folder) / "missing.dpapi"))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI only")
    def test_encrypted_roundtrip_and_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.dpapi"
            save_key("FAKE-TEST-KEY", path)
            self.assertNotIn(b"FAKE-TEST-KEY", path.read_bytes())
            self.assertEqual(load_key(path), "FAKE-TEST-KEY")
            path.write_bytes(b"invalid ciphertext")
            with self.assertRaises(OSError):
                load_key(path)


if __name__ == "__main__":
    unittest.main()
