#!/usr/bin/env python3
"""Apply host maintenance and start a bounded, observable background bootstrap."""
import os
import pathlib
import plistlib
import subprocess

ROOT = pathlib.Path('/Library/PatchIntelligence')
REPO = pathlib.Path(__file__).resolve().parent.parent
LABEL = 'com.patch.bootstrap'

def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)

def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo to install the root-owned operation scripts.')
    if not (ROOT/'current').exists():
        raise SystemExit('Deploy the application release before bootstrapping.')
    status = subprocess.run(['launchctl', 'print', f'system/{LABEL}'], capture_output=True, text=True)
    if 'state = running' in status.stdout:
        raise SystemExit('Bootstrap is already running; inspect /Library/PatchIntelligence/logs/com.patch.bootstrap.log.')
    run('/usr/bin/python3', REPO/'ops/complete-host-setup.py')
    for source, destination, mode in [
        (REPO/'scripts/bootstrap.mjs', ROOT/'ops/bootstrap.mjs', 0o644),
        (REPO/'ops/bootstrap-job.sh', ROOT/'ops/bootstrap-job.sh', 0o755),
    ]:
        run('/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', oct(mode)[2:], source, destination)
    log = ROOT/'logs/com.patch.bootstrap.log'
    # Preserve earlier logs across resumptions.
    log.touch(exist_ok=True)
    os.chown(log, 0, 20)
    os.chmod(log, 0o640)
    config = {
        'Label': LABEL,
        'ProgramArguments': [str(ROOT/'ops/bootstrap-job.sh')],
        'EnvironmentVariables': {'LC_ALL': 'en_US.UTF-8', 'LANG': 'en_US.UTF-8'},
        'StandardOutPath': str(log),
        'StandardErrorPath': str(log),
    }
    path = pathlib.Path('/Library/LaunchDaemons')/f'{LABEL}.plist'
    if status.returncode == 0:
        run('launchctl', 'bootout', f'system/{LABEL}')
    path.write_bytes(plistlib.dumps(config))
    os.chown(path, 0, 0)
    os.chmod(path, 0o644)
    run('launchctl', 'bootstrap', 'system', path)
    run('launchctl', 'kickstart', f'system/{LABEL}')
    print('Bootstrap started in the background. Progress: /Library/PatchIntelligence/logs/com.patch.bootstrap.log')
    print('No Pages, tailnet policy, or public routing changes were made.')

if __name__ == '__main__':
    main()
