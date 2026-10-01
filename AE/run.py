#!/usr/bin/env python3
"""Reproduce Sluice in fresh containers with immutable historical records."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def source_hash():
    files = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    for folder in ['src', 'tests']:
        files += [p for p in (ROOT / folder).rglob('*')
                  if p.is_file() and '__pycache__' not in p.parts and p.name != '.DS_Store']
    files += [ROOT / 'AE' / name for name in ['worker.py', 'run.py', 'cap_guard.py', 'Dockerfile']]
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes() + b'\0')
    return h.hexdigest()


def docker_json(*args):
    return json.loads(subprocess.check_output(['docker', *args], text=True))


def doctor(work):
    info = docker_json('info', '--format', '{{json .}}')
    if info.get('OSType') != 'linux' or str(info.get('CgroupVersion')) != '2':
        raise SystemExit('Linux Docker with cgroup v2 is required.')
    result = {k: info.get(k) for k in ['Architecture', 'NCPU', 'MemTotal', 'CgroupVersion',
                                     'ServerVersion', 'KernelVersion']}
    result['free_disk_bytes'] = shutil.disk_usage(work).free
    (work / 'environment.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return result


def build(args):
    stamp = time.strftime('%Y%m%d-%H%M%S')
    log = args.work / f'build-{stamp}.log'
    fingerprint = source_hash()
    print(f'Building {args.image}; log: {log}', flush=True)
    with log.open('w') as stream:
        subprocess.run(['docker', 'build', '--progress=plain', '-f', str(ROOT / 'AE/Dockerfile'),
                        '-t', args.image, str(ROOT)], stdout=stream, stderr=subprocess.STDOUT,
                       check=True)
    if source_hash() != fingerprint:
        raise SystemExit('Source changed during build. Run build again.')
    image = docker_json('image', 'inspect', args.image)[0]
    record = {'source_sha256': fingerprint, 'image_id': image['Id'],
              'image': args.image, 'architecture': image['Architecture']}
    (args.work / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


def run_case(args, mode, variant='rw', log_n=10, cap='1g', expected='completed'):
    record = json.loads((args.work / 'build.json').read_text())
    if record['source_sha256'] != source_hash():
        raise SystemExit('Source differs from the measured image. Run build again first.')
    image = docker_json('image', 'inspect', args.image)[0]
    if image['Id'] != record['image_id']:
        raise SystemExit('Image tag changed. Run build again first.')
    name = f'{mode}-{variant}-n{log_n}-{cap}-{uuid.uuid4().hex[:8]}'
    container = f'sluice-ae-{uuid.uuid4().hex[:12]}'
    command = ['docker', 'run', '--name', container, '--network', 'none',
               '--user', f'{os.getuid()}:{os.getgid()}',
               '--memory', cap, '--memory-swap', cap, '--cpus', str(args.cpus),
               '-e', f'RAYON_NUM_THREADS={args.cpus}',
               '-e', f'RWG_SOURCE_REVISION=sha256:{record["source_sha256"]}',
               '--mount', f'type=bind,source={args.work},target=/workspace',
               args.image, 'python3', 'AE/worker.py', mode,
               '--variant', variant, '--log-n', str(log_n), '--name', name,
               '--memory-bytes', str(cap_bytes(cap))]
    print(f'START {name}; expected={expected}', flush=True)
    try:
        proc = subprocess.run(command)
        state = docker_json('inspect', container)[0]
        log = args.work / 'logs' / name
        log.mkdir(parents=True, exist_ok=True)
        # Retain selected state without host paths or credentials.
        state_record = {'State': state['State'], 'Image': state['Image'],
                        'Memory': state['HostConfig']['Memory'],
                        'MemorySwap': state['HostConfig']['MemorySwap'],
                        'NanoCpus': state['HostConfig']['NanoCpus']}
        (log / 'docker.json').write_text(json.dumps(state_record, indent=2) + '\n')
        result_file = log / 'result.json'
        if result_file.exists():
            result = json.loads(result_file.read_text())
        else:
            # OOMKilled alone cannot certify that the limits held throughout.
            result = {'name': name, 'mode': mode, 'variant': variant, 'log_n': log_n,
                      'outcome': 'failed', 'failure_reason': 'missing_worker_result',
                      'source_revision': 'sha256:' + record['source_sha256']}
        result['docker_exit_code'] = proc.returncode
        result['expected'] = expected
        result['limits_valid'] = limits_valid(result, state_record, cap_bytes(cap))
        result['passed'] = (result['outcome'] == expected and result['limits_valid'] and
                            proc.returncode == 0 and state['State']['ExitCode'] == 0)
        result['image_id'] = record['image_id']
        result_file.write_text(json.dumps(result, indent=2) + '\n')
    finally:
        # Include interruption and host-side logging/inspection failures.
        cleanup = subprocess.run(['docker', 'rm', '--force', container],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if cleanup.returncode and 'No such container' not in cleanup.stderr:
            print(f'Container cleanup failed for {container}: {cleanup.stderr}', file=sys.stderr)
    print(f'END {name}: {result["outcome"]}; passed={result["passed"]}', flush=True)
    if not result['passed']:
        raise SystemExit(f'Unexpected outcome; inspect {log}')


def cap_bytes(cap):
    return int(cap[:-1]) * {'m': 2**20, 'g': 2**30}[cap[-1]]


def limits_valid(result, state, memory_bytes):
    monitor = result.get('cap_monitor', {})
    return bool(monitor.get('valid') is True and monitor.get('complete') is True and
                monitor.get('file_write_watch') is True and monitor.get('samples', 0) >= 2 and
                monitor.get('expected_memory_bytes') == memory_bytes and
                monitor.get('expected_swap_max') == '0' and not monitor.get('violations') and
                result.get('memory_max') == str(memory_bytes) and result.get('swap_max') == '0' and
                state['Memory'] == memory_bytes and state['MemorySwap'] == memory_bytes)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['doctor', 'build', 'test', 'smoke', 'prepare',
                                       'prove', 'full', 'results', 'verify-records'])
    ap.add_argument('--work', type=Path, default=ROOT / '.ae-work')
    ap.add_argument('--image', default='sluice-ae:1.0.1')
    ap.add_argument('--cpus', type=int, default=8)
    ap.add_argument('--log-n', type=int, default=23, choices=range(1, 26))
    ap.add_argument('--variant', choices=['rw', 'std'], default='rw')
    ap.add_argument('--cap', choices=['256m', '1g', '8g', '12g', '16g'], default='8g')
    ap.add_argument('--expect', choices=['verified', 'oom'], default='verified')
    args = ap.parse_args()
    if args.command == 'verify-records':
        return subprocess.run(['bash', str(ROOT / 'Experiments/run_cgroup_n23.sh'), 'verify'],
                              cwd=ROOT).returncode
    args.work = args.work.expanduser().resolve()
    args.work.mkdir(parents=True, exist_ok=True)
    if ',' in str(args.work):
        raise SystemExit('Docker bind-mount work path must not contain commas.')
    if args.command == 'results':
        for file in sorted((args.work / 'logs').glob('*/result.json')):
            print(file.read_text())
        return 0
    env = doctor(args.work)
    if args.command == 'doctor':
        return 0
    if args.command == 'build':
        build(args)
    elif args.command == 'test':
        run_case(args, 'test', cap='4g')
    elif args.command == 'smoke':
        for variant in ['rw', 'std']:
            run_case(args, 'materialize', variant, 10, '1g')
            run_case(args, 'prove', variant, 10, '256m', 'verified')
    elif args.command in ['prepare', 'full']:
        if args.command == 'full' and args.log_n != 23:
            raise SystemExit('The full comparison is defined only at log_n=23.')
        if args.log_n >= 23 and (env['MemTotal'] < 23 * 2**30 or
                                env['free_disk_bytes'] < 100 * 2**30):
            raise SystemExit('Full preparation requires >=23 GiB Docker RAM and >=100 GiB free disk.')
        variants = ['rw', 'std'] if args.command == 'full' else [args.variant]
        for variant in variants:
            run_case(args, 'materialize', variant, args.log_n, '22g')
        if args.command == 'full':
            for variant, cap, expected in [('rw', '8g', 'verified'), ('std', '8g', 'oom'),
                                           ('std', '16g', 'verified')]:
                run_case(args, 'prove', variant, 23, cap, expected)
    elif args.command == 'prove':
        run_case(args, 'prove', args.variant, args.log_n, args.cap, args.expect)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
