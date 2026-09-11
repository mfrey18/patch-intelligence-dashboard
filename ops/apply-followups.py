#!/usr/bin/env python3
"""Apply a pinned native release, verify product parity, stage CI access, and resume ingestion.

Run with sudo from the reviewed checkout. The release archive must match the
explicit SHA-256. Public routing and GitHub configuration are not changed here.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = pathlib.Path('/Library/PatchIntelligence')
OPS = pathlib.Path(__file__).resolve().parent
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def run(*args, **kwargs):
    return subprocess.run([str(value) for value in args], check=True, **kwargs)


def validate_arguments(release, digest):
    if not re.fullmatch(r'[a-f0-9]{40}', release):
        raise RuntimeError('--release must be a lowercase 40-character Git revision')
    if not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise RuntimeError('--sha256 must be a lowercase 64-character archive checksum')


def root_owned(path, directory=False):
    info = path.lstat()
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f'Expected a root-owned, non-writable path: {path}')


def archive_snapshot(path, expected_digest):
    """Validate the same private snapshot later copied into incoming, avoiding upload races."""
    snapshot = tempfile.TemporaryFile()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE_BYTES:
                raise RuntimeError('Archive must be a nonempty regular file no larger than 256 MiB')
            digest = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                if not block:
                    raise RuntimeError('Release archive changed or was truncated while reading')
                snapshot.write(block)
                digest.update(block)
                remaining -= len(block)
        if digest.hexdigest() != expected_digest:
            raise RuntimeError('Release archive SHA-256 mismatch; no host services were changed')
        snapshot.seek(0)
        return snapshot
    except BaseException:
        snapshot.close()
        raise


def atomic_write(path, data, mode=0o644):
    if path.is_symlink():
        raise RuntimeError(f'Refusing a symlink: {path}')
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as target:
            if isinstance(data, (str, bytes)):
                target.write(data.encode() if isinstance(data, str) else data)
            else:
                data.seek(0)
                while block := data.read(1024 * 1024):
                    target.write(block)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def current_release():
    link = ROOT / 'current'
    if not link.is_symlink() or link.lstat().st_uid != 0:
        raise RuntimeError('Expected the existing root-owned current release symlink')
    current = link.resolve(strict=True)
    if current.parent != ROOT / 'releases':
        raise RuntimeError('Current release must be inside the managed releases directory')
    root_owned(current, directory=True)
    return current


def ensure_bootstrap_idle():
    result = subprocess.run(['/bin/launchctl', 'print', 'system/com.patch.bootstrap'], capture_output=True, text=True)
    if re.search(r'^\s*state\s*=\s*running\s*$', result.stdout, re.MULTILINE):
        raise RuntimeError('Bootstrap is still running. Wait for /Library/PatchIntelligence/logs/com.patch.bootstrap.log to finish before applying this release')


def dashboard(path):
    # Full request URLs are cache keys. A unique ignored parameter measures an
    # application-cache miss without restarting or emptying other cached entries.
    url = 'http://127.0.0.1:3001' + path + ('&' if '?' in path else '?') + 'verification=' + uuid.uuid4().hex
    request = urllib.request.Request(url, headers={'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.perf_counter()
    with opener.open(request, timeout=120) as response:
        value = json.loads(response.read(8 * 1024 * 1024))
    elapsed = round((time.perf_counter() - started) * 1000, 2)
    series = value.get('productSeries') if isinstance(value, dict) else None
    if not isinstance(series, list) or any(not isinstance(item, dict) or not isinstance(item.get('label'), str) or type(item.get('value')) not in (int, float) for item in series):
        raise RuntimeError('Dashboard response is missing a valid productSeries')
    return value, elapsed


def same_products(before, after):
    # Preserve array order and every product field; exclude generatedAt and other
    # dashboard sections whose time-dependent values are unrelated to this query.
    return json.dumps(before['productSeries'], sort_keys=True) == json.dumps(after['productSeries'], sort_keys=True)


def rollback(previous):
    root_owned(previous, directory=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.current.rollback-', dir=ROOT)
    os.close(descriptor)
    os.unlink(temporary)
    try:
        os.symlink(previous, temporary)
        os.replace(temporary, ROOT / 'current')
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    atomic_write(ROOT / 'deployed-sha', previous.name + '\n')
    run('/bin/launchctl', 'kickstart', '-k', 'system/com.patch.api')


def apply(release, archive, digest):
    validate_arguments(release, digest)
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo to apply the reviewed release and protected host configuration')
    operator = pwd.getpwnam(os.environ.get('SUDO_USER', 'root'))
    if operator.pw_uid < 500:
        raise RuntimeError('Run sudo from your normal Mac account; the GitHub setup export needs a non-root owner')
    os.umask(0o077)
    # Nothing affecting the installed application runs before checksum validation.
    with archive_snapshot(archive, digest) as snapshot:
        ensure_bootstrap_idle()
        for path in [ROOT, ROOT / 'ops', ROOT / 'logs', ROOT / 'releases']:
            root_owned(path, directory=True)
        previous = current_release()
        requested = ROOT / 'releases' / release
        if requested != previous and requested.exists():
            raise RuntimeError('Requested release directory already exists but is not current; inspect the prior deployment before retrying')
        identity = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        report_path = ROOT / 'logs' / f'followups-{identity}.json'
        report = {'release': release, 'archiveSha256': digest, 'previousRelease': previous.name,
                  'status': 'started', 'deployment': 'already-current' if requested == previous else 'pending',
                  'productParity': 'pending', 'sshSetup': 'pending', 'bootstrap': 'not-started'}
        write_json(report_path, report)
        print(f'Verification report: {report_path}', flush=True)
        deployed = False
        try:
            before, before_ms = dashboard('/api/dashboard?include=products')
            write_json(ROOT / 'logs' / f'followups-{identity}-before.json', before)
            report['beforeDashboardMs'] = before_ms
            root_owned(ROOT / 'ops/backup.sh')
            run(ROOT / 'ops/backup.sh')
            report['preDeploymentBackup'] = 'passed'
            ensure_bootstrap_idle()
            if requested != previous:
                # The helper independently snapshots and validates archive members.
                # Incoming may belong to _patchdeploy; the installed copy is root-owned.
                incoming = ROOT / 'incoming'
                if not stat.S_ISDIR(incoming.lstat().st_mode):
                    raise RuntimeError('Incoming must be an existing directory, not a symlink')
                atomic_write(ROOT / 'ops/deploy-release.sh', (OPS / 'deploy-release.sh').read_bytes(), 0o755)
                atomic_write(incoming / f'{release}.tar.gz', snapshot, 0o600)
                run(ROOT / 'ops/deploy-release.sh', release)
                deployed = True
                report['deployment'] = 'applied'
            products, cold_ms = dashboard('/api/dashboard/analytics/products')
            after, after_ms = dashboard('/api/dashboard?include=products')
            write_json(ROOT / 'logs' / f'followups-{identity}-after.json', after)
            report['afterDashboardMs'] = after_ms
            report['productParity'] = 'passed' if same_products(before, after) else 'failed'
            if report['productParity'] != 'passed':
                raise RuntimeError('Product series changed before ingestion; restoring the previous application release')
            if not same_products(after, products):
                report['productParity'] = 'failed'
                raise RuntimeError('Product analytics differs from the verified dashboard; restoring the previous application release')
            report['coldProductAnalyticsMs'] = cold_ms
            report['productSeries'] = products['productSeries']
            report['timingScope'] = 'Uncached local HTTP request; excludes Funnel and includes serialization, not a database-buffer cold start'
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            report['status'] = 'failed'
            report['error'] = str(error)
            try:
                # The helper can switch before readiness fails; inspect the actual link.
                if deployed or current_release() != previous:
                    rollback(previous)
                    report['deployment'] = 'rolled-back'
            except (RuntimeError, OSError, subprocess.SubprocessError) as recovery_error:
                report['rollbackError'] = str(recovery_error)
            write_json(report_path, report)
            raise
        write_json(report_path, report)
        # SSH activation may require Terminal Full Disk Access. It must not block
        # independent power/log maintenance and background ingestion once parity passes.
        ssh = subprocess.run(['/usr/bin/python3', str(OPS / 'install-deployment-access.py')])
        report['sshSetup'] = 'installed' if ssh.returncode == 0 else 'pending'
        if ssh.returncode:
            print('SSH setup remains pending; follow its local administrator instruction. Continuing independent maintenance and ingestion.', flush=True)
        try:
            run('/usr/bin/python3', OPS / 'continue-setup.py')
            report['bootstrap'] = 'started'
            report['status'] = 'applied' if ssh.returncode == 0 else 'applied-with-pending-ssh'
        except subprocess.SubprocessError:
            report['bootstrap'] = 'failed-to-start'
            report['status'] = 'pending-maintenance'
            write_json(report_path, report)
            raise
        write_json(report_path, report)
        print(json.dumps({'status': report['status'], 'release': release, 'productParity': report['productParity'],
                          'coldProductAnalyticsMs': report['coldProductAnalyticsMs'], 'sshSetup': report['sshSetup'],
                          'bootstrap': report['bootstrap'], 'report': str(report_path)}))
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    apply(args.release, args.archive, args.sha256)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'Follow-ups stopped: {error}', file=sys.stderr)
        sys.exit(1)
