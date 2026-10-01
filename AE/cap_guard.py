"""Linux cgroup v2 limit monitoring for one measured subprocess.

Poll the limits and watch writes to their files. Fail closed if either method
cannot run; a notification is a violation even if the old value is restored.
"""
import ctypes
import os
from pathlib import Path
import struct
import time


class CapGuard:
    INTERVAL = 0.1
    MAX_GAP = 1.0

    def __init__(self, memory_bytes, root=Path('/sys/fs/cgroup')):
        self.root = Path(root)
        self.expected = {'memory.max': str(memory_bytes), 'memory.swap.max': '0'}
        self.fd = None
        self.watches = {}
        self.last_sample = None
        self.report = {'expected_memory_bytes': memory_bytes, 'expected_swap_max': '0',
                       'poll_interval_seconds': self.INTERVAL,
                       'max_allowed_gap_seconds': self.MAX_GAP,
                       'samples': 0, 'max_sample_gap_seconds': 0.0,
                       'file_write_watch': False, 'complete': False,
                       'valid': False, 'violations': []}

    def violation(self, reason, **details):
        # Bound the record even if a broken environment repeatedly triggers errors.
        if len(self.report['violations']) < 16:
            self.report['violations'].append({'reason': reason, **details})

    def start(self):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            if self.fd < 0:
                self.fd = None
                raise OSError(ctypes.get_errno(), 'inotify_init1 failed')
            for name in self.expected:
                # IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF
                wd = libc.inotify_add_watch(self.fd, os.fsencode(self.root / name), 0xC06)
                if wd < 0:
                    raise OSError(ctypes.get_errno(), 'inotify_add_watch failed', name)
                self.watches[wd] = name
            self.report['file_write_watch'] = True
        except (OSError, AttributeError) as exc:
            self.violation('watch_unavailable', error=str(exc))
        self.sample()
        return not self.report['violations']

    def sample(self):
        now = time.monotonic()
        if self.last_sample is not None:
            gap = now - self.last_sample
            self.report['max_sample_gap_seconds'] = max(
                self.report['max_sample_gap_seconds'], gap)
            if gap > self.MAX_GAP:
                self.violation('monitor_gap', seconds=gap)
        self.last_sample = now
        if self.fd is not None:
            try:
                while True:
                    events = os.read(self.fd, 65536)
                    if not events:
                        self.violation('watch_closed')
                        break
                    offset = 0
                    while offset < len(events):
                        wd, mask, _, length = struct.unpack_from('iIII', events, offset)
                        offset += 16 + length
                        self.violation('limit_file_event', file=self.watches.get(wd, 'watch'),
                                       mask=mask)
            except BlockingIOError:
                pass
            except OSError as exc:
                self.violation('watch_read_failed', error=str(exc))
        observed = {}
        for name, expected in self.expected.items():
            try:
                observed[name] = (self.root / name).read_text().strip()
                if observed[name] != expected:
                    self.violation('limit_mismatch', file=name,
                                   expected=expected, observed=observed[name])
            except OSError as exc:
                self.violation('limit_unreadable', file=name, error=str(exc))
        self.report['last_observed'] = observed
        self.report['samples'] += 1
        return not self.report['violations']

    def finish(self):
        self.sample()
        self.report['complete'] = True
        self.report['valid'] = bool(self.report['file_write_watch'] and
                                    not self.report['violations'])
        self.close()
        return self.report

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
