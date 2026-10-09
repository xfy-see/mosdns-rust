#!/usr/bin/env python3
"""Run verified CI harnesses on an explicitly selected ARM64 Linux router.

No builds or production service changes. Each invocation owns a fresh /tmp UUID
directory; watchdogs bind signals to boot, PID, starttime and executable identity.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('artifact_verify', HERE / 'download-and-test.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
CONFIGS = ('/etc/config/dhcp', '/etc/config/network', '/etc/config/firewall',
           '/etc/sing-box/config.json', '/etc/nsswitch.conf', '/etc/network/interfaces', '/etc/resolv.conf')
NFT_TESTS = ('native_nftset_membership_interval_families_and_set_default_timeout',
             'native_nftset_explicit_timeout_is_read_back_without_timing_out_end_marker')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def summary(text, exact=None, expected_success=True):
    require(text.count('CLEANUP_VERIFIED\n') == 1 and 'OWNED_PROCESSES_ZERO\n' in text,
            'owned process cleanup was not verified')
    require('HARNESS_LOG_BEGIN\n' in text and 'HARNESS_LOG_END\n' in text, 'missing framed test output')
    log = text.split('HARNESS_LOG_BEGIN\n', 1)[1].split('HARNESS_LOG_END\n', 1)[0]
    results = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', log, re.M)
    require(len(results) == 1, 'expected one Rust test summary')
    status, *counts = results[0]
    passed, failed, ignored, measured, filtered = map(int, counts)
    require(measured == 0, 'unexpected measured tests')
    if expected_success:
        require(status == 'ok' and failed == 0 and text.rstrip().endswith('FINAL 0'), 'test failed')
        require(not any(line.startswith(('ERROR_', 'WATCHDOG_OR_SIGNAL_ABORT')) for line in text.splitlines()),
                'watchdog or resource guard failed')
        if exact:
            require(passed == 1 and ignored == 0 and re.search(r'^test ' + re.escape(exact) + r' \.\.\. ok$', log, re.M),
                    'exact ignored invocation did not pass exactly one test')
        else:
            require(filtered == 0, 'ordinary tests were filtered')
    return dict(passed=passed, failed=failed, ignored=ignored, measured=measured, filtered=filtered,
                minimum_memavailable_kib=min([int(x) for x in re.findall(r'^MEMAVAILABLE (\d+)$', text, re.M)] or [0]))


class Remote:
    def __init__(self, args, output):
        self.args, self.output, self.sequence = args, output, 0
        self.owner = 'mosdns-rust-ci-' + uuid.uuid4().hex
        self.work = '/tmp/' + self.owner
        self.ssh = ['ssh', '-p', str(args.port), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
                    '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2', '-o', 'ControlMaster=no',
                    '-o', 'ControlPath=none', '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'UserKnownHostsFile=' + str(output / 'known_hosts'), '-o', 'IdentitiesOnly=yes',
                    '-i', str(args.identity), args.user + '@' + args.host]

    def call(self, label, command, data=None, timeout=20, allow_failure=False):
        self.sequence += 1
        q = shlex.quote
        boot = 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + q(self.args.expected_boot)
        guarded = 'set -u; ' + boot + ' || exit 42; (set -eu; ' + command + '); r=$?; ' + boot + ' || exit 42; exit "$r"'
        prefix = self.output / ('ssh-%03d-%s' % (self.sequence, label))
        result = subprocess.run(self.ssh + [guarded], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
        record = dict(label=label, command=command, started_at_unix=time.time(), exit_code=result.returncode,
                      stdout_sha256=hashlib.sha256(result.stdout).hexdigest(), stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
        with (self.output / 'commands.jsonl').open('a') as stream:
            stream.write(json.dumps(record) + '\n')
        require(result.returncode != 42, 'router rebooted; recorded scope is no longer valid')
        require(allow_failure or result.returncode == 0, 'remote step failed: ' + label)
        return result

    def guard(self):
        q = shlex.quote
        return ('[ -d ' + q(self.work) + ' ] && [ ! -L ' + q(self.work) + ' ] && [ ! -L ' + q(self.work + '/owner.txt') +
                ' ] && [ "$(cat ' + q(self.work + '/owner.txt') + ')" = ' + q(self.owner) + '; ')

    def snapshot(self, label):
        cmd = "printf 'MEMAVAILABLE '; awk '/^MemAvailable:/ {print $2}' /proc/meminfo; printf 'TMP_AVAILABLE '; df -Pk /tmp | awk 'NR==2 {print $4}'; "
        cmd += 'for f in ' + ' '.join(map(shlex.quote, CONFIGS)) + '; do if [ -f "$f" ]; then sha256sum "$f"; elif [ -e "$f" ] || [ -L "$f" ]; then exit 12; else printf "ABSENT %s\\n" "$f"; fi; done; '
        cmd += "printf 'PORT53_BEGIN\\n'; netstat -lntu | awk 'NR>2 && $4 ~ /:53$/ {print $1, $4, $6}' | sort; printf 'PORT53_END\\n'; printf 'NFT_BEGIN\\n'; nft list tables | sort; printf 'NFT_END\\n'"
        text = self.call(label, cmd).stdout.decode()
        hashes = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] in CONFIGS:
                require(fields[0] == 'ABSENT' or re.fullmatch('[a-f0-9]{64}', fields[0]), 'invalid config digest')
                hashes[fields[1]] = fields[0]
        require(set(hashes) == set(CONFIGS), 'incomplete static config inventory')
        return dict(boot=self.args.expected_boot, static=hashes,
                    port53=text.split('PORT53_BEGIN\n')[1].split('PORT53_END')[0],
                    nft_tables=text.split('NFT_BEGIN\n')[1].split('NFT_END')[0],
                    memavailable_kib=int(re.search(r'^MEMAVAILABLE (\d+)$', text, re.M).group(1)),
                    tmp_available_kib=int(re.search(r'^TMP_AVAILABLE (\d+)$', text, re.M).group(1)))

    def upload(self, label, local, remote):
        q = shlex.quote
        digest = verifier.sha256(local)
        cmd = self.guard() + 'test ! -e ' + q(remote + '.stage') + '; cat > ' + q(remote + '.stage') + '; '
        cmd += '[ "$(sha256sum ' + q(remote + '.stage') + " | awk '{print $1}')\" = " + q(digest) + ' ]; '
        cmd += 'chmod 755 ' + q(remote + '.stage') + '; mv ' + q(remote + '.stage') + ' ' + q(remote)
        self.call(label, cmd, local.read_bytes())

    def clean(self):
        q = shlex.quote
        cmd = self.guard() + 'for f in /proc/[0-9]*/exe; do e=$(readlink "$f" 2>/dev/null || true); case "$e" in '
        cmd += q(self.work) + '/*) echo ERROR_owned_process_alive >&2; exit 13;; esac; done; '
        cmd += '[ -d ' + q(self.work + '/tmp') + ' ] && [ ! -L ' + q(self.work + '/tmp') + ' ]; rm -rf -- ' + q(self.work + '/tmp') + '; '
        for name in ['minimal-cli', 'minimal-cli.stage', 'current-harness', 'current-harness.stage', 'session.sh', 'session.sh.stage',
                     'watchdog.fifo', 'harness.log', 'monitor.log', 'identity.txt', 'cleanup-targets.txt', 'remaining-pids.txt']:
            cmd += 'rm -f -- ' + q(self.work + '/' + name) + '; '
        cmd += 'rm -- ' + q(self.work + '/owner.txt') + '; rmdir -- ' + q(self.work)
        self.call('owned-cleanup', cmd)
        self.call('cleanup-postflight', 'test ! -e ' + q(self.work))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--profile', required=True, choices=['full', 'minimal'])
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', default='root')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--identity', required=True, type=Path)
    parser.add_argument('--known-hosts', required=True, type=Path)
    parser.add_argument('--expected-boot', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--nft', action='store_true')
    parser.add_argument('--socket-options', action='store_true')
    parser.add_argument('--ipset-probe', action='store_true', help='run the read-only ignored IPSET capability probe; unsupported is retained separately')
    args = parser.parse_args()
    ipaddress.ip_address(args.host)
    require(re.fullmatch(r'[a-z_][a-z0-9_-]*', args.user), 'invalid SSH user')
    require(re.fullmatch(r'[a-f0-9-]{36}', args.expected_boot), 'invalid boot ID')
    root, output = args.artifact.resolve(), args.output.resolve()
    manifest = verifier.verify_artifact(root, args.expected_commit, 'aarch64-unknown-linux-musl', args.profile,
                                        source_root=args.source_root.resolve())
    require(not output.exists(), 'result directory already exists')
    output.mkdir(parents=True)
    shutil.copyfile(args.known_hosts, output / 'known_hosts')
    remote = Remote(args, output)
    tests = [x for x in manifest['files'] if x.get('role') == 'test_harness']
    cli = next(x for x in manifest['files'] if x.get('role') == 'production_cli')
    session = HERE / 'router-session.sh'
    available_ignored = {name for entry in tests for name in entry.get('tests_ignored', [])}
    if args.nft:
        require(set(NFT_TESTS).issubset(available_ignored), 'requested NFT coverage is absent from this artifact')
    if args.socket_options:
        require(any(name.endswith('linux_socket_mark_and_bind_device_are_applied_before_bind') for name in available_ignored),
                'requested socket option coverage is absent from this artifact')
    if args.ipset_probe:
        require('native_ipset_protocol_only_reports_subsystem_availability' in available_ignored,
                'requested IPSet capability probe is absent from this artifact')
    plan = dict(commit=args.expected_commit, profile=args.profile, host=args.host, boot=args.expected_boot,
                artifact_manifest_sha256=verifier.sha256(root / 'manifest.json'), remote_root=remote.work,
                owner=remote.owner, harnesses=tests, cli=cli, session_sha256=verifier.sha256(session),
                ignored_opt_in=dict(nft=args.nft, socket_options=args.socket_options, ipset_probe=args.ipset_probe), execute=args.execute)
    write(output / 'plan.json', plan)
    if not args.execute:
        print(json.dumps(dict(prepared=True, executed=False, plan=str(output / 'plan.json'))))
        return
    result = dict(completed=False, invocations=[], capability=[], remote_cleanup_verified=False, started_at_unix=time.time(),
                  ignored_not_run=[dict(harness=entry['path'], test=name) for entry in tests for name in entry.get('tests_ignored', [])])
    owned, before = False, None
    try:
        require(remote.call('architecture', 'uname -m').stdout.strip() == b'aarch64', 'router architecture differs')
        before = remote.snapshot('system-before')
        result['before'] = before
        require(before['memavailable_kib'] >= 32768, 'available memory below 32 MiB')
        require(before['tmp_available_kib'] * 1024 >= cli['bytes'] + max(x['bytes'] for x in tests) + 4*1024**2,
                'insufficient tmp space for one serial harness and CLI')
        q = shlex.quote
        remote.call('create-owned', 'test ! -e ' + q(remote.work) + '; mkdir -m 700 ' + q(remote.work) + '; printf %s ' + q(remote.owner) +
                    ' > ' + q(remote.work + '/owner.txt') + '; mkdir ' + q(remote.work + '/tmp'))
        owned = True
        remote.upload('upload-cli', root / cli['path'], remote.work + '/minimal-cli')
        remote.upload('upload-session', session, remote.work + '/session.sh')
        for index, entry in enumerate(tests):
            verifier.verify_artifact(root, args.expected_commit, 'aarch64-unknown-linux-musl', args.profile, source_root=args.source_root.resolve())
            remote.upload('upload-harness-%02d' % index, root / entry['path'], remote.work + '/current-harness')
            ignored = entry.get('tests_ignored', [])
            todo = [(None, False)]
            for name in ignored:
                if args.nft and name in NFT_TESTS:
                    todo.append((name, False))
                elif args.socket_options and name.endswith('linux_socket_mark_and_bind_device_are_applied_before_bind'):
                    todo.append((name, False))
                elif args.ipset_probe and name == 'native_ipset_protocol_only_reports_subsystem_availability':
                    todo.append((name, True))
            for invocation, capability in todo:
                remote.call('reset-harness-state', remote.guard() + 'rm -f -- ' + ' '.join(q(remote.work + '/' + n) for n in
                            ['watchdog.fifo', 'harness.log', 'monitor.log', 'identity.txt', 'cleanup-targets.txt', 'remaining-pids.txt']))
                command = [remote.work + '/session.sh', remote.work, remote.owner, args.expected_boot, entry['sha256']]
                if invocation:
                    command += ['--ignored', '--exact', invocation, '--nocapture']
                else:
                    command += ['--nocapture']
                run = remote.call('harness-%02d-%02d' % (index, len(result['invocations'])), ' '.join(map(q, command)), timeout=95, allow_failure=capability)
                text = run.stdout.decode()
                parsed = summary(text, invocation, expected_success=not capability or run.returncode == 0)
                if invocation is None:
                    require(parsed['passed'] + parsed['ignored'] == len(entry['tests_all']) and
                            parsed['ignored'] == len(entry['tests_ignored']), 'router test counts differ from CI inventory')
                observation = dict(harness=entry['path'], exact_test=invocation, exit_code=run.returncode, summary=parsed)
                if invocation:
                    result['ignored_not_run'] = [item for item in result['ignored_not_run']
                                                if item != dict(harness=entry['path'], test=invocation)]
                if capability:
                    observation['status'] = 'supported' if run.returncode == 0 else 'unavailable_or_failed'
                    result['capability'].append(observation)
                else:
                    result['invocations'].append(observation)
        verifier.verify_artifact(root, args.expected_commit, 'aarch64-unknown-linux-musl', args.profile, source_root=args.source_root.resolve())
        require(verifier.sha256(session) == plan['session_sha256'], 'session changed during tests')
        result['completed'] = True
    except Exception as error:
        result['error'] = str(error)
    finally:
        try:
            if owned:
                remote.clean()
                result['remote_cleanup_verified'] = True
            if before:
                after = remote.snapshot('system-after')
                result['after'] = after
                require(all(before[k] == after[k] for k in ['boot', 'static', 'port53', 'nft_tables']),
                        'router static config/DNS/NFT state changed')
                result['router_state_unchanged'] = True
        except Exception as error:
            result['completed'] = False
            result['cleanup_or_state_error'] = str(error)
        result['finished_at_unix'] = time.time()
        write(output / 'RESULT.json', result)
    print(json.dumps(dict(completed=result['completed'], invocations=len(result['invocations']),
                         passed=sum(x['summary']['passed'] for x in result['invocations']),
                         capability=result['capability'], remote_cleanup_verified=result['remote_cleanup_verified'], output=str(output))))
    if not result['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
