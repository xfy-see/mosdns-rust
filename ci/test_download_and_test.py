#!/usr/bin/env python3
"""Tests for the fail-closed downloaded-artifact boundary; no Cargo needed."""
import importlib.util
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


spec = importlib.util.spec_from_file_location("artifact_verifier", Path(__file__).with_name("download-and-test.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
COMMIT = "1" * 40
TARGET = "aarch64-apple-darwin"


def fixture(root):
    root.mkdir()
    files = []
    for name, content, role in (
        ("runtime-source/rust/Cargo.toml", b"[package]\nname = 'test'\n", "source"),
        ("bin/mosdns-rs", b"production CLI", "production_cli"),
        ("harnesses/lib/fixture-harness", b"test harness", "test_harness"),
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        entry = {"path": name, "bytes": len(content), "sha256": verifier.sha256(path), "role": role}
        if role == "test_harness":
            entry.update(test=True, tests_all=["ordinary", "manual"], tests_ignored=["manual"])
        files.append(entry)
    source = files[0]
    inputs = {"rust/Cargo.toml": {key: source[key] for key in ("bytes", "sha256")}}
    manifest = {"schema_version": 1, "status": "complete", "commit": COMMIT, "target": TARGET, "profile": "full", "files": files, "source_inputs": inputs, "source_tree_sha256": verifier.source_tree_sha256(inputs), "production_version": "mosdns-rs 0.1.0"}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return manifest


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.artifact = self.directory / "download"
        self.manifest = fixture(self.artifact)

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return verifier.verify_artifact(self.artifact, COMMIT, TARGET, "full")

    def add_file(self, name, data, role="generated_test_fixture"):
        path = self.artifact / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entry = dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), role=role)
        self.manifest["files"].append(entry)
        return entry

    def write_manifest(self):
        (self.artifact / "manifest.json").write_text(json.dumps(self.manifest))

    def test_valid_manifest_is_accepted(self):
        self.assertEqual(self.verify()["commit"], COMMIT)

    def test_modified_binary_is_rejected(self):
        (self.artifact / "bin/mosdns-rs").write_bytes(b"altered binary")
        with self.assertRaisesRegex(verifier.VerificationError, "digest mismatch"):
            self.verify()

    def test_extra_file_is_rejected(self):
        (self.artifact / "unlisted").write_text("injected")
        with self.assertRaisesRegex(verifier.VerificationError, "unlisted"):
            self.verify()

    def test_symlink_is_rejected(self):
        (self.artifact / "linked").symlink_to(self.artifact / "bin/mosdns-rs")
        with self.assertRaisesRegex(verifier.VerificationError, "non-regular"):
            self.verify()

    def test_wrong_commit_prevents_any_execution(self):
        output = self.directory / "result"
        argv = ["verify", "--artifact", str(self.artifact), "--expected-commit", "2" * 40, "--expected-target", TARGET, "--expected-profile", "full", "--output", str(output)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(verifier, "run_validation") as runtime:
            self.assertEqual(verifier.main(), 1)
            runtime.assert_not_called()
        record = json.loads((output / "RESULT.json").read_text())
        self.assertFalse(record["executed"])
        self.assertIn("commit mismatch", record["error"])

    def test_modified_digest_prevents_any_execution(self):
        (self.artifact / "bin/mosdns-rs").write_text("tampered")
        output = self.directory / "result"
        argv = ["verify", "--artifact", str(self.artifact), "--expected-commit", COMMIT, "--expected-target", TARGET, "--expected-profile", "full", "--output", str(output)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(verifier, "run_validation") as runtime:
            self.assertEqual(verifier.main(), 1)
            runtime.assert_not_called()
        self.assertFalse(json.loads((output / "RESULT.json").read_text())["executed"])

    def test_wrong_target_or_profile_is_rejected(self):
        for target, profile in (("x86_64-apple-darwin", "full"), (TARGET, "minimal")):
            with self.subTest(target=target, profile=profile):
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_artifact(self.artifact, COMMIT, target, profile)

    def test_source_tree_binding_is_checked(self):
        self.manifest["source_tree_sha256"] = "0" * 64
        (self.artifact / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(verifier.VerificationError, "source tree"):
            self.verify()

    def test_local_dirty_source_is_rejected(self):
        source = self.directory / "checkout"
        (source / "rust").mkdir(parents=True)
        (source / "rust/Cargo.toml").write_text("modified after push")
        outputs = [COMMIT + "\n", b"rust/Cargo.toml\0"]
        with mock.patch.object(verifier.subprocess, "check_output", side_effect=outputs):
            with self.assertRaisesRegex(verifier.VerificationError, "local source input differs"):
                verifier.verify_artifact(self.artifact, COMMIT, TARGET, "full", source)

    def test_local_wrong_git_head_is_rejected(self):
        source = self.directory / "checkout"
        source.mkdir()
        with mock.patch.object(verifier.subprocess, "check_output", return_value="2" * 40 + "\n"):
            with self.assertRaisesRegex(verifier.VerificationError, "HEAD differs"):
                verifier.verify_artifact(self.artifact, COMMIT, TARGET, "full", source)

    def test_ignored_tests_must_belong_to_complete_inventory(self):
        self.manifest["files"][-1]["tests_ignored"] = ["unlisted"]
        (self.artifact / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(verifier.VerificationError, "ignored inventory"):
            self.verify()

    def test_generated_public_certificate_is_allowed_separately_from_tracked_sources(self):
        name = verifier.FIXTURE_ROOT + "generated-cert.der"
        entry = self.add_file("runtime-source/" + name, b"\x30\x07\x30\x00\x30\x00\x03\x01\x00")
        self.manifest["generated_test_inputs"] = {name: {"bytes": entry["bytes"], "sha256": entry["sha256"], "kind": "public_certificate", "packaged": True}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.write_manifest()
        self.assertEqual(self.verify()["generated_test_inputs"][name]["kind"], "public_certificate")
        self.assertNotIn(name, self.manifest["source_inputs"])

    def test_private_metadata_may_be_recorded_without_packaging_key(self):
        name = verifier.FIXTURE_ROOT + "localhost-key.der"
        self.manifest["generated_test_inputs"] = {name: {"bytes": 11, "sha256": "1" * 64, "kind": "private_key", "packaged": False}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.manifest["compile_only_private_key_files_removed"] = True
        self.write_manifest()
        self.assertFalse(self.verify()["generated_test_inputs"][name]["packaged"])

    def test_missing_ci_private_key_cleanup_confirmation_is_rejected(self):
        name = verifier.FIXTURE_ROOT + "localhost-key.der"
        self.manifest["generated_test_inputs"] = {name: {"bytes": 11, "sha256": "1" * 64, "kind": "private_key", "packaged": False}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "cleanup was not confirmed"):
            self.verify()

    def test_private_metadata_cannot_request_packaging_even_without_file(self):
        name = verifier.FIXTURE_ROOT + "localhost-key.der"
        self.manifest["generated_test_inputs"] = {name: {"bytes": 11, "sha256": "1" * 64, "kind": "private_key", "packaged": True}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "must not be packaged"):
            self.verify()

    def test_hash_matched_fixture_private_key_file_is_rejected(self):
        name = verifier.FIXTURE_ROOT + "localhost-key.der"
        data = b"\x30\x09\x02\x01\x00\x30\x00\x04\x02\x01\x02"
        entry = self.add_file("runtime-source/" + name, data)
        self.manifest["generated_test_inputs"] = {name: {"bytes": entry["bytes"], "sha256": entry["sha256"], "kind": "private_key", "packaged": True}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "private-key file"):
            self.verify()

    def test_renamed_der_private_key_cannot_claim_binary_role(self):
        self.add_file("bin/unexpected.der", b"\x30\x09\x02\x01\x00\x30\x00\x04\x02\x01\x02", "test_cli")
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "private-key contents"):
            self.verify()

    def test_pem_private_key_is_rejected_even_when_manifest_hash_matches(self):
        self.add_file("logs/leak.txt", b"-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n-----END PRIVATE KEY-----\n", "build_log")
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "private-key contents"):
            self.verify()

    def test_generated_public_whitelist_does_not_allow_arbitrary_data(self):
        name = verifier.FIXTURE_ROOT + "generated-cert.der"
        entry = self.add_file("runtime-source/" + name, b"not a certificate")
        self.manifest["generated_test_inputs"] = {name: {"bytes": entry["bytes"], "sha256": entry["sha256"], "kind": "public_certificate", "packaged": True}}
        self.manifest["generated_test_tree_sha256"] = verifier.source_tree_sha256(self.manifest["generated_test_inputs"])
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "not a certificate"):
            self.verify()

    def test_generated_and_tracked_input_overlap_is_rejected(self):
        self.manifest["generated_test_inputs"] = {"rust/Cargo.toml": self.manifest["source_inputs"]["rust/Cargo.toml"]}
        self.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "separate from tracked"):
            self.verify()

    def test_zip_traversal_is_rejected_before_writes(self):
        archive = self.directory / "bad.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("good.txt", "allowed")
            bundle.writestr("../escaped", "outside")
        extracted = self.directory / "extracted"
        with self.assertRaisesRegex(verifier.VerificationError, "unsafe"):
            verifier.safe_extract(archive, extracted)
        self.assertFalse(extracted.exists())
        self.assertFalse((self.directory / "escaped").exists())

    def test_zip_symlink_is_rejected(self):
        archive = self.directory / "bad.zip"
        member = zipfile.ZipInfo("linked")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(member, "/tmp/outside")
        with self.assertRaisesRegex(verifier.VerificationError, "non-regular"):
            verifier.safe_extract(archive, self.directory / "extracted")

    def test_zip_implicit_parent_case_collision_is_rejected(self):
        archive = self.directory / "bad.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("Parent/a", "a")
            bundle.writestr("parent/b", "b")
        with self.assertRaisesRegex(verifier.VerificationError, "collision"):
            verifier.safe_extract(archive, self.directory / "extracted")

    def test_zip_size_limit_is_enforced_before_writes(self):
        archive = self.directory / "large.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("large", b"x" * 20)
        extracted = self.directory / "extracted"
        with self.assertRaisesRegex(verifier.VerificationError, "size limit"):
            verifier.safe_extract(archive, extracted, max_bytes=10)
        self.assertFalse(extracted.exists())

    def test_verified_artifact_is_copied_and_not_executed(self):
        output = self.directory / "result"
        argv = ["verify", "--artifact", str(self.artifact), "--expected-commit", COMMIT, "--expected-target", TARGET, "--expected-profile", "full", "--output", str(output), "--verify-only"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(verifier, "run_validation") as runtime:
            self.assertEqual(verifier.main(), 0)
            runtime.assert_not_called()
        result = json.loads((output / "RESULT.json").read_text())
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["artifact_unchanged_after_validation"])
        self.assertFalse(result["executed"])

    def test_native_precompiled_harness_inventory_and_result_are_checked(self):
        cli = self.artifact / "bin/mosdns-rs"
        cli.write_text("#!/usr/bin/env python3\nimport sys\nprint('mosdns-rs 0.1.0' if sys.argv[1] == 'version' else 'configuration valid: 0 listeners')\n")
        harness = self.artifact / "harnesses/lib/fixture-harness"
        harness.write_text("#!/usr/bin/env python3\nimport sys\nif '--list' in sys.argv:\n    print('manual: test' if '--ignored' in sys.argv else 'manual: test\\nordinary: test')\nelse:\n    print('test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s')\n")
        for entry in self.manifest["files"]:
            path = self.artifact / entry["path"]
            entry.update(bytes=path.stat().st_size, sha256=verifier.sha256(path))
        self.manifest["files"][-1]["tests_all"] = ["manual", "ordinary"]
        self.manifest["target"] = verifier.host_target()
        (self.artifact / "manifest.json").write_text(json.dumps(self.manifest))
        verifier.verify_artifact(self.artifact, COMMIT, self.manifest["target"], "full")
        output = self.directory / "runtime-result"
        output.mkdir()
        result = verifier.run_validation(self.artifact, self.manifest, output, 1, 10, [])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["executions"][0]["summary"]["passed"], 1)
        self.assertEqual(result["harness_inventory"][0]["ordinary_count"], 1)
        self.assertEqual(result["ignored_not_run"], ["harnesses/lib/fixture-harness::manual"])
        self.assertTrue(result["executions"][0]["inventory_matches"])


if __name__ == "__main__":
    unittest.main()
