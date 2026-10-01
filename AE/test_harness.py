"""Regression checks for cap changes, incomplete evidence, and cleanup.

Run: python3 AE/test_harness.py (file-watch tests require Linux).
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cap_guard import CapGuard
import run


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux inotify required')
class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'memory.max').write_text('268435456\n')
        (self.root / 'memory.swap.max').write_text('0\n')
        self.guard = CapGuard(256 * 2**20, self.root)
        self.addCleanup(self.guard.close)

    def test_stable_limits(self):
        self.assertTrue(self.guard.start())
        self.assertTrue(self.guard.finish()['valid'])

    def test_swap_change_and_restore_between_polls(self):
        self.assertTrue(self.guard.start())
        path = self.root / 'memory.swap.max'
        path.write_text('max\n')
        path.write_text('0\n')
        self.assertFalse(self.guard.finish()['valid'])
        self.assertEqual(self.guard.report['last_observed']['memory.swap.max'], '0')

    def test_memory_change(self):
        self.assertTrue(self.guard.start())
        (self.root / 'memory.max').write_text('max\n')
        self.assertFalse(self.guard.finish()['valid'])

    def test_initial_wrong_cap(self):
        (self.root / 'memory.max').write_text('536870912\n')
        self.assertFalse(self.guard.start())

    def test_missing_limit_file(self):
        (self.root / 'memory.swap.max').unlink()
        self.assertFalse(self.guard.start())

    def test_watch_failure(self):
        with patch('cap_guard.ctypes.CDLL', side_effect=OSError('unavailable')):
            self.assertFalse(self.guard.start())

    def test_monitor_gap(self):
        self.guard.MAX_GAP = 0.01
        self.assertTrue(self.guard.start())
        time.sleep(0.02)
        self.assertFalse(self.guard.finish()['valid'])


class VerdictTests(unittest.TestCase):
    def setUp(self):
        self.cap = 256 * 2**20
        self.result = {'outcome': 'verified', 'memory_max': str(self.cap), 'swap_max': '0',
                       'cap_monitor': {'valid': True, 'complete': True,
                                       'file_write_watch': True, 'samples': 2,
                                       'expected_memory_bytes': self.cap,
                                       'expected_swap_max': '0', 'violations': []}}
        self.state = {'Memory': self.cap, 'MemorySwap': self.cap}

    def test_valid_evidence(self):
        self.assertTrue(run.limits_valid(self.result, self.state, self.cap))

    def test_missing_monitor_even_for_oom(self):
        self.assertFalse(run.limits_valid({'outcome': 'oom'}, self.state, self.cap))

    def test_restored_limits_do_not_clear_violation(self):
        self.result['cap_monitor']['violations'] = [{'reason': 'limit_file_event'}]
        self.assertFalse(run.limits_valid(self.result, self.state, self.cap))

    def test_wrong_requested_cap(self):
        self.assertFalse(run.limits_valid(self.result, self.state, 2 * self.cap))

    def test_docker_swap_configuration_mismatch(self):
        self.state['MemorySwap'] = -1
        self.assertFalse(run.limits_valid(self.result, self.state, self.cap))

    def test_incomplete_monitor(self):
        self.result['cap_monitor']['complete'] = False
        self.assertFalse(run.limits_valid(self.result, self.state, self.cap))


class CleanupTests(unittest.TestCase):
    def test_host_logging_error_still_removes_container(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            (work / 'build.json').write_text(json.dumps(
                {'source_sha256': 'source', 'image_id': 'image'}))
            args = SimpleNamespace(work=work, image='image', cpus=1)
            state = {'State': {'ExitCode': 0}, 'Image': 'image',
                     'HostConfig': {'Memory': 2**30, 'MemorySwap': 2**30, 'NanoCpus': 1}}
            with patch.object(run, 'source_hash', return_value='source'), \
                 patch.object(run, 'docker_json', side_effect=[[{'Id': 'image'}], [state]]), \
                 patch.object(run.subprocess, 'run', return_value=
                              subprocess.CompletedProcess([], 0, stderr='')) as execute, \
                 patch.object(Path, 'write_text', side_effect=PermissionError('regression')):
                with self.assertRaises(PermissionError):
                    run.run_case(args, 'test')
                self.assertIn('--user', execute.call_args_list[0].args[0])
                self.assertEqual(execute.call_args_list[-1].args[0][:3],
                                 ['docker', 'rm', '--force'])


if __name__ == '__main__':
    unittest.main()
