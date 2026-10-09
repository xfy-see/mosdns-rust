import importlib.util
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('router_under_test', Path(__file__).with_name('test-router.py'))
router = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router)


def output(line, tail='FINAL 0'):
    return ('HARNESS_LOG_BEGIN\n' + line + '\nHARNESS_LOG_END\n'
            'OWNED_PROCESSES_ZERO\nCLEANUP_VERIFIED\n' + tail + '\n')


class RouterSummaryTests(unittest.TestCase):
    def test_complete_ordinary_inventory_can_be_empty_for_gated_target(self):
        self.assertEqual(router.summary(output('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'))['passed'], 0)

    def test_failed_ordinary_test_rejected(self):
        with self.assertRaises(RuntimeError):
            router.summary(output('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;', 'FINAL 1'))

    def test_filtered_ordinary_test_rejected(self):
        with self.assertRaises(RuntimeError):
            router.summary(output('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'))

    def test_exact_ignored_requires_named_success(self):
        with self.assertRaises(RuntimeError):
            router.summary(output('test other .. ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;'), 'expected')

    def test_watchdog_error_never_counts_as_pass(self):
        with self.assertRaises(RuntimeError):
            router.summary(output('ERROR_monitor_memory\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'))

    def test_capability_failure_retains_failed_count(self):
        parsed = router.summary(output('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out;', 'FINAL 1'), expected_success=False)
        self.assertEqual(parsed['failed'], 1)

    def test_unverified_cleanup_rejected_even_on_capability_failure(self):
        with self.assertRaises(RuntimeError):
            router.summary('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;\n', expected_success=False)


class LocalRemote(router.Remote):
    """Execute the real generated maintenance commands locally, never over SSH."""

    def __init__(self, work):
        args = SimpleNamespace(port=22, identity=Path('/unused-identity'),
                               user='root', host='127.0.0.1', expected_boot='unused')
        super().__init__(args, work.parent)
        self.work = str(work)
        self.calls = []

    def call(self, label, command, data=None, timeout=20, allow_failure=False):
        self.calls.append(label)
        parsed = subprocess.run(['/bin/sh', '-n', '-c', command], capture_output=True)
        router.require(parsed.returncode == 0, parsed.stderr.decode())
        result = subprocess.run(['/bin/sh', '-c', 'set -eu; ' + command], input=data,
                                capture_output=True, timeout=timeout)
        router.require(allow_failure or result.returncode == 0,
                       label + ': ' + result.stderr.decode())
        return result


class RouterOwnedCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "owned work's root"
        self.work.mkdir()
        (self.work / 'tmp').mkdir()
        self.remote = LocalRemote(self.work)
        (self.work / 'owner.txt').write_text(self.remote.owner)
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        self.sentinel = self.outside / 'keep.txt'
        self.sentinel.write_text('unrelated data')

    def tearDown(self):
        self.temp.cleanup()

    def guarded_marker(self):
        marker = self.work / 'mutation'
        return self.remote.guard() + 'touch ' + shlex.quote(str(marker))

    def test_owned_guard_parses_and_allows_the_operation(self):
        self.remote.call('guard', self.guarded_marker())
        self.assertTrue((self.work / 'mutation').is_file())

    def test_wrong_owner_guard_blocks_the_operation(self):
        (self.work / 'owner.txt').write_text('different owner')
        with self.assertRaises(RuntimeError):
            self.remote.call('guard', self.guarded_marker())
        self.assertFalse((self.work / 'mutation').exists())

    def test_owner_symlink_guard_blocks_the_operation(self):
        alternate = self.outside / 'owner.txt'
        alternate.write_text(self.remote.owner)
        (self.work / 'owner.txt').unlink()
        (self.work / 'owner.txt').symlink_to(alternate)
        with self.assertRaises(RuntimeError):
            self.remote.call('guard', self.guarded_marker())
        self.assertFalse((self.work / 'mutation').exists())
        self.assertEqual(alternate.read_text(), self.remote.owner)

    def test_work_symlink_guard_blocks_the_operation(self):
        shutil.rmtree(self.work)
        (self.outside / 'owner.txt').write_text(self.remote.owner)
        self.work.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.remote.call('guard', self.guarded_marker())
        self.assertFalse((self.outside / 'mutation').exists())
        self.assertEqual(self.sentinel.read_text(), 'unrelated data')

    @unittest.skipUnless(shutil.which('sha256sum'), 'upload requires sha256sum')
    def test_verified_upload_then_cleanup_preserves_unrelated_files(self):
        payload = self.root / 'payload'
        payload.write_bytes(b'downloaded executable bytes\n')
        executable = self.work / 'minimal-cli'
        self.remote.upload('upload-cli', payload, str(executable))
        self.assertEqual(executable.read_bytes(), payload.read_bytes())
        self.assertEqual(executable.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.work / 'minimal-cli.stage').exists())
        self.remote.clean()
        self.assertFalse(self.work.exists())
        self.assertEqual(self.sentinel.read_text(), 'unrelated data')
        self.assertEqual(self.remote.calls,
                         ['upload-cli', 'owned-cleanup', 'cleanup-postflight'])

    @unittest.skipUnless(shutil.which('sha256sum'), 'upload requires sha256sum')
    def test_existing_staging_file_blocks_upload_before_overwrite(self):
        payload = self.root / 'payload'
        payload.write_bytes(b'new binary')
        executable = self.work / 'minimal-cli'
        executable.write_bytes(b'previous binary')
        staging = self.work / 'minimal-cli.stage'
        staging.write_bytes(b'previous incomplete upload')
        with self.assertRaises(RuntimeError):
            self.remote.upload('upload-cli', payload, str(executable))
        self.assertEqual(executable.read_bytes(), b'previous binary')
        self.assertEqual(staging.read_bytes(), b'previous incomplete upload')

    def test_wrong_owner_blocks_both_upload_and_cleanup(self):
        payload = self.root / 'payload'
        payload.write_bytes(b'new binary')
        executable = self.work / 'minimal-cli'
        executable.write_bytes(b'owned data')
        (self.work / 'owner.txt').write_text('different owner')
        with self.assertRaises(RuntimeError):
            self.remote.upload('upload-cli', payload, str(executable))
        self.assertFalse((self.work / 'minimal-cli.stage').exists())
        with self.assertRaises(RuntimeError):
            self.remote.clean()
        self.assertEqual(executable.read_bytes(), b'owned data')
        self.assertTrue((self.work / 'owner.txt').exists())
        self.assertTrue((self.work / 'tmp').is_dir())
        self.assertEqual(self.sentinel.read_text(), 'unrelated data')
        self.assertEqual(self.remote.calls, ['upload-cli', 'owned-cleanup'])

    def test_cleanup_rejects_a_symlinked_tmp_without_deleting_data(self):
        (self.work / 'tmp').rmdir()
        (self.work / 'tmp').symlink_to(self.outside, target_is_directory=True)
        executable = self.work / 'minimal-cli'
        executable.write_bytes(b'owned data')
        with self.assertRaises(RuntimeError):
            self.remote.clean()
        self.assertEqual(executable.read_bytes(), b'owned data')
        self.assertEqual(self.sentinel.read_text(), 'unrelated data')
        self.assertTrue((self.work / 'owner.txt').exists())
        self.assertEqual(self.remote.calls, ['owned-cleanup'])


if __name__ == '__main__':
    unittest.main()
