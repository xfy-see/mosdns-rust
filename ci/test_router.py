import importlib.util
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
