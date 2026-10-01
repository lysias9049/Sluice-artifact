#!/usr/bin/env python3
"""Container-side measurement; never writes historical Experiments/ records."""
import argparse
import csv
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from cap_guard import CapGuard


def snapshot():
    root = Path('/sys/fs/cgroup')
    names = ['memory.max', 'memory.swap.max', 'memory.current', 'memory.peak',
             'memory.events', 'memory.stat', 'io.stat', 'cpu.stat']
    return {name: (root / name).read_text() for name in names if (root / name).exists()}


def oom_count(state):
    fields = dict(line.split() for line in state.get('memory.events', '').splitlines())
    return int(fields.get('oom_kill', 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['test', 'materialize', 'prove'])
    ap.add_argument('--variant', choices=['rw', 'std'], default='rw')
    ap.add_argument('--log-n', type=int, default=10)
    ap.add_argument('--name', required=True)
    ap.add_argument('--memory-bytes', type=int, required=True)
    args = ap.parse_args()
    work = Path('/workspace')
    logs = work / 'logs' / args.name
    logs.mkdir(parents=True, exist_ok=False)
    scratch = work / 'tmp' / args.name
    scratch.mkdir(parents=True, exist_ok=False)
    data = work / 'data' / f'{args.variant}-{args.log_n}'
    data.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch), RWG_RECORD_MACHINE_ID='0')
    binary = f'target/release/{args.variant}_prove_only'
    if args.mode == 'test':
        command = ['cargo', 'test', '--locked', '--offline', '--release']
    elif args.mode == 'materialize':
        command = [binary, '--materialize-only', str(args.log_n), str(data)]
    else:
        command = [binary, '--prove', str(args.log_n), str(data), '0']
        env['RWG_PROOF_OUT'] = str(logs / 'proof.bin')
    before = snapshot()
    (logs / 'cgroup.before.json').write_text(json.dumps(before, indent=2) + '\n')
    started = time.time()
    guard = CapGuard(args.memory_bytes)
    ready = guard.start()
    returncode = None
    with (logs / 'stdout.txt').open('w') as out, (logs / 'stderr.txt').open('w') as err:
        if ready:
            proc = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(logs / 'time.txt'),
                                     *command], env=env, stdout=out, stderr=err,
                                    start_new_session=True)
            try:
                while True:
                    try:
                        returncode = proc.wait(timeout=guard.INTERVAL)
                        break
                    except subprocess.TimeoutExpired:
                        if not guard.sample():
                            # Kill time and its descendants, rather than only the wrapper.
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            returncode = proc.wait()
                            break
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
    cap_monitor = guard.finish()
    (logs / 'cap-monitor.json').write_text(json.dumps(cap_monitor, indent=2) + '\n')
    after = snapshot()
    (logs / 'cgroup.after.json').write_text(json.dumps(after, indent=2) + '\n')
    result = {'name': args.name, 'mode': args.mode, 'variant': args.variant,
              'log_n': args.log_n, 'exit_code': returncode,
              'wall_seconds': round(time.time() - started, 3),
              'oom_kill_delta': oom_count(after) - oom_count(before),
              'memory_max': after.get('memory.max', '').strip(),
              'swap_max': after.get('memory.swap.max', '').strip(),
              'source_revision': env.get('RWG_SOURCE_REVISION', 'unknown'),
              'command': command, 'cap_monitor': cap_monitor, 'outcome': 'failed'}
    if not cap_monitor['valid']:
        result['outcome'] = 'invalid_limits'
    elif returncode == 0:
        result['outcome'] = 'completed'
        if args.mode == 'prove':
            rows = list(csv.reader((logs / 'stdout.txt').read_text().splitlines()))
            row = next((r for r in rows if len(r) == 18 and
                        r[0] in ['rw_rw_prove_only', 'std_prove_only']), None)
            proof = logs / 'proof.bin'
            valid = bool(row and row[1] == str(args.log_n) and
                         row[2] == str(1 << args.log_n) and row[7:9] == ['128', 'true']
                         and proof.exists() and proof.stat().st_size == 128)
            result['proof_valid'] = valid
            result['proof_bytes'] = proof.stat().st_size if proof.exists() else 0
            result['outcome'] = 'verified' if valid else 'failed'
            if row:
                result.update(prove_ms=float(row[3]), peak_rss_mib=float(row[5]),
                              read_bytes=int(row[9]), write_bytes=int(row[10]))
        elif args.mode == 'materialize':
            result['data_bytes'] = sum(p.stat().st_size for p in data.iterdir() if p.is_file())
    elif result['oom_kill_delta'] > 0 and returncode in [137, -9]:
        result['outcome'] = 'oom'
    (logs / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if result['outcome'] in ['completed', 'verified', 'oom'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
