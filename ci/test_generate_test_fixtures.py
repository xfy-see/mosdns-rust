"""Static fixture-policy checks: no TLS key is generated or read locally."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("generate-test-fixtures.py")
SPEC = importlib.util.spec_from_file_location("fixture_generator", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FixturePolicyTests(unittest.TestCase):
    def test_expected_original_fixture_paths_and_roles(self):
        self.assertEqual(len(MODULE.GENERATED), 6)
        private = {name for name, kind in MODULE.GENERATED.items() if kind == "private_key"}
        self.assertEqual(private, {
            MODULE.BASE + "localhost-key.der",
            MODULE.BASE + "system-trust/server-key.der",
        })
        self.assertEqual(sum(kind == "public_certificate" for kind in MODULE.GENERATED.values()), 4)

    def test_local_certificate_preserves_original_san(self):
        lines = MODULE.LOCAL_EXTENSIONS.splitlines()
        self.assertIn("subjectAltName = DNS:dns.test.invalid,IP:127.0.0.1", lines)
        self.assertIn("basicConstraints = critical,CA:FALSE", lines)
        self.assertNotIn("keyUsage", MODULE.LOCAL_EXTENSIONS)

    def test_trust_server_preserves_negative_hostname_cases(self):
        lines = MODULE.SERVER_EXTENSIONS.splitlines()
        self.assertIn("subjectAltName = DNS:dns.test.invalid,IP:192.0.2.1,IP:127.0.0.1", lines)
        self.assertNotIn("DNS:localhost", MODULE.SERVER_EXTENSIONS)
        self.assertNotIn("IP:::1", MODULE.SERVER_EXTENSIONS)
        self.assertIn("keyUsage = critical,digitalSignature,keyEncipherment", lines)
        self.assertIn("extendedKeyUsage = serverAuth", lines)

    def test_ca_usage_is_certificate_signing_only(self):
        self.assertIn("basicConstraints = critical,CA:TRUE", MODULE.CA_EXTENSIONS)
        self.assertIn("keyUsage = critical,keyCertSign,cRLSign", MODULE.CA_EXTENSIONS)
        self.assertNotIn("subjectAltName", MODULE.CA_EXTENSIONS)

    def test_input_digest_uses_bytes_and_hash_only(self):
        inputs = {"fixture.der": {"bytes": 10, "sha256": "a" * 64,
                                 "kind": "public_certificate", "packaged": True}}
        expected = hashlib.sha256(("fixture.der\0" + "10\0" + "a" * 64 + "\n").encode()).hexdigest()
        self.assertEqual(MODULE.tree_digest(inputs), expected)

    def test_generation_and_cleanup_refuse_local_execution_before_crypto(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(MODULE, "openssl_executable") as crypto:
            with self.assertRaisesRegex(MODULE.FixtureError, "restricted to GitHub Actions"):
                MODULE.generate()
            with self.assertRaisesRegex(MODULE.FixtureError, "restricted to GitHub Actions"):
                MODULE.remove_private_keys()
            crypto.assert_not_called()

    def test_cli_refuses_local_execution_without_output(self):
        environment = os.environ.copy()
        environment.pop("GITHUB_ACTIONS", None)
        result = subprocess.run([sys.executable, "-B", str(SCRIPT)], capture_output=True,
                                text=True, env=environment)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("restricted to GitHub Actions", result.stderr)


if __name__ == "__main__":
    unittest.main()
