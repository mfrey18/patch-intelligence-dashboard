#!/usr/bin/env python3
"""Stage restricted native deployment SSH access; run this reviewed installer with sudo.

Preserves existing SSH configuration and host keys. No external secrets are sent.
The local GitHub setup file contains only the native ingestion token, CI SSH key,
and pinned public host key. Run again safely after enabling Remote Login if macOS
requires Terminal Full Disk Access. This script does not configure tailnet policy.
"""
import grp
import json
import os
import pathlib
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path('/Library/PatchIntelligence')
OPS = pathlib.Path(__file__).resolve().parent
ACCOUNT = '_patchdeploy'
MARKER = '# Managed by Patch Intelligence deployment access installer.\n'


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def root_owned(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f'Requires a root-owned, non-writable {"directory" if directory else "file"}: {path}')


def atomic_write(path, data, mode=0o600, uid=0, gid=0):
    """Never follow an existing target symlink or expose partial secret contents."""
    if path.is_symlink():
        raise RuntimeError(f'Refusing a symlink: {path}')
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data if isinstance(data, bytes) else data.encode())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ensure_directory(path, mode=0o755, uid=0, gid=0):
    if not path.exists():
        path.mkdir(mode=mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
        raise RuntimeError(f'Refusing unexpected directory owner or symlink: {path}')
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def ensure_account():
    home = str(ROOT / 'deploy')
    try:
        entry = pwd.getpwnam(ACCOUNT)
    except KeyError:
        entry = None
    if entry is not None:
        try:
            group = grp.getgrnam(ACCOUNT)
        except KeyError as error:
            raise RuntimeError(f'Existing {ACCOUNT} account has no dedicated group; refusing to alter it') from error
        if entry.pw_dir != home or entry.pw_shell != '/bin/bash' or entry.pw_gid != group.gr_gid:
            raise RuntimeError(f'Existing {ACCOUNT} account differs from this installer; refusing to alter it')
        return entry
    # A separate group prevents the deployment account reading staff-group logs.
    occupied = {entry.pw_uid for entry in pwd.getpwall()} | {entry.gr_gid for entry in grp.getgrall()}
    identity = next(value for value in range(400, 499) if value not in occupied)
    try:
        group = grp.getgrnam(ACCOUNT)
        group_id = group.gr_gid
    except KeyError:
        group_id = identity
        run('/usr/bin/dscl', '.', '-create', f'/Groups/{ACCOUNT}', 'PrimaryGroupID', group_id)
    values = [('UniqueID', identity), ('PrimaryGroupID', group_id), ('NFSHomeDirectory', home),
              ('UserShell', '/bin/bash'), ('IsHidden', '1'), ('RealName', 'Patch Intelligence deployment'),
              ('Password', '*')]
    for key, value in values:
        run('/usr/bin/dscl', '.', '-create', f'/Users/{ACCOUNT}', key, value)
    return pwd.getpwnam(ACCOUNT)


def ingest_token():
    entries = []
    for line in (ROOT / 'secrets/api.env').read_text().splitlines():
        if line.startswith('INGEST_SECRET='):
            values = shlex.split(line.split('=', 1)[1], comments=True)
            if len(values) == 1:
                entries.append(values[0])
    if len(entries) != 1 or len(entries[0]) < 32:
        raise RuntimeError('api.env must contain exactly one valid INGEST_SECRET; no credentials changed')
    return entries[0]


def tailnet_hostname():
    binaries = [pathlib.Path('/opt/homebrew/opt/tailscale/bin/tailscale'), pathlib.Path('/usr/local/opt/tailscale/bin/tailscale')]
    binary = next((candidate for candidate in binaries if candidate.is_file()), None)
    if binary is None:
        raise RuntimeError('Native Tailscale CLI is missing')
    result = run(binary, '--socket=/var/run/tailscaled.socket', 'status', '--json', capture_output=True, text=True, timeout=15)
    status = json.loads(result.stdout)
    hostname = status.get('Self', {}).get('DNSName', '').rstrip('.')
    if status.get('BackendState') != 'Running' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]+\.ts\.net', hostname):
        raise RuntimeError('Authenticate the system Tailscale service before installing deployment access')
    return hostname


def configure_remote_login():
    result = run('/usr/sbin/systemsetup', '-getremotelogin', capture_output=True, text=True)
    if 'Remote Login: On' in result.stdout:
        enabled = True
    elif 'Remote Login: Off' in result.stdout:
        enabled = False
    else:
        raise RuntimeError('Could not determine Remote Login state; existing SSH settings were preserved')
    try:
        grp.getgrnam('com.apple.access_ssh')
        scoped = True
    except KeyError:
        scoped = False
    if not enabled and not scoped:
        # With login previously disabled, start with only the dedicated account.
        # If login is already enabled for all users, preserve that existing policy.
        run('/usr/sbin/dseditgroup', '-o', 'create', 'com.apple.access_ssh')
        scoped = True
    if scoped:
        run('/usr/sbin/dseditgroup', '-o', 'edit', '-a', ACCOUNT, '-t', 'user', 'com.apple.access_ssh')
    if not enabled:
        result = subprocess.run(['/usr/sbin/systemsetup', '-setremotelogin', 'on'], capture_output=True, text=True)
        check = subprocess.run(['/usr/sbin/systemsetup', '-getremotelogin'], capture_output=True, text=True)
        if result.returncode or 'Remote Login: On' not in check.stdout:
            raise RuntimeError('Deployment access is staged, but macOS could not enable Remote Login. Grant Terminal Full Disk Access in System Settings > Privacy & Security, then rerun this installer, or enable Remote Login in System Settings > General > Sharing. Existing SSH settings were preserved.')


def export_setup(operator, hostname, key):
    public_host_key = pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub')
    if not public_host_key.exists():
        # ssh-keygen -A creates only missing host keys; existing identities stay intact.
        run('/usr/bin/ssh-keygen', '-A', stdout=subprocess.DEVNULL)
    root_owned(public_host_key)
    fields = public_host_key.read_text().split()
    if len(fields) < 2 or fields[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/=]+', fields[1]):
        raise RuntimeError('Invalid local SSH Ed25519 public host key')
    setup = {
        'variables': {'DEPLOY_HOST': hostname, 'DEPLOY_USER': ACCOUNT,
                      'PRIVATE_API_BASE_URL': f'https://{hostname}:8443'},
        'secrets': {'DEPLOY_SSH_KEY': key.read_text(), 'DEPLOY_KNOWN_HOSTS': f'{hostname} {fields[0]} {fields[1]}\n',
                    'INGEST_SECRET': ingest_token()},
    }
    export = ROOT / 'secrets/github-setup.json'
    atomic_write(export, json.dumps(setup, indent=2) + '\n', uid=operator.pw_uid, gid=operator.pw_gid)
    print(f'Local GitHub setup file: {export} (owned by {operator.pw_name}, mode 600; credentials not printed).')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo; this creates the restricted CI account and SSH configuration')
    operator = pwd.getpwnam(os.environ.get('SUDO_USER', 'root'))
    if operator.pw_uid < 500:
        raise RuntimeError('Run sudo from your normal Mac account so the local GitHub setup file has a specific non-root owner')
    os.umask(0o077)
    for directory in [ROOT, ROOT / 'ops', ROOT / 'secrets', pathlib.Path('/etc/sudoers.d')]:
        root_owned(directory, directory=True)
    for source in [OPS / 'deploy-ssh-command.sh', OPS / 'deploy-release.sh']:
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f'Missing reviewed script: {source}')
    hostname = tailnet_hostname()
    ingest_token()  # Validate before making any account or SSH changes.
    entry = ensure_account()
    ensure_directory(ROOT / 'deploy')
    ensure_directory(ROOT / 'deploy/.ssh')
    ensure_directory(ROOT / 'incoming', 0o700, entry.pw_uid, entry.pw_gid)
    for name in ['deploy-ssh-command.sh', 'deploy-release.sh']:
        atomic_write(ROOT / 'ops' / name, (OPS / name).read_bytes(), mode=0o755)
    key = ROOT / 'secrets/github-deploy-key'
    if not key.exists():
        run('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'patch-intelligence-native-deploy', '-f', key)
    root_owned(key)
    os.chmod(key, 0o600)
    # Derive from the private key so a stale .pub file cannot configure a wrong key.
    public_key = run('/usr/bin/ssh-keygen', '-y', '-f', key, capture_output=True, text=True).stdout.strip()
    if not public_key.startswith('ssh-ed25519 '):
        raise RuntimeError('Deployment key must be Ed25519')
    authorized = ROOT / 'deploy/.ssh/authorized_keys'
    line = f'restrict,command="{ROOT}/ops/deploy-ssh-command.sh" {public_key}\n'
    if authorized.exists() and authorized.read_text() != line:
        raise RuntimeError('Existing deployment authorized_keys differs; refusing to replace it')
    atomic_write(authorized, line, mode=0o644)
    export_setup(operator, hostname, key)
    configure_remote_login()
    # Install privilege last, after keys, helpers, and Remote Login are ready.
    # Validate the precise argument regex with this Mac's sudo version before installation.
    sudoers = pathlib.Path('/etc/sudoers.d/patch-intelligence-deploy')
    if sudoers.exists() and not sudoers.read_text().startswith(MARKER):
        raise RuntimeError('Existing deployment sudoers file is not installer-managed')
    rule = MARKER + f'{ACCOUNT} ALL=(root) NOPASSWD: {ROOT}/ops/deploy-release.sh ^[a-f0-9]{{40}}$\n'
    descriptor, temporary = tempfile.mkstemp(prefix='.patch-deploy-', dir='/etc/sudoers.d')
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(rule)
        os.chmod(temporary, 0o440)
        run('/usr/sbin/visudo', '-cf', temporary, stdout=subprocess.DEVNULL)
        if sudoers.is_symlink():
            raise RuntimeError('Refusing a symlink for deployment sudoers')
        os.replace(temporary, sudoers)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('Restricted deployment account installed. Verify tailnet SSH grants and a signed CI deployment before enabling automatic deployment. Existing sshd_config was not edited.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        # Never print subprocess stdout/stderr: future commands may handle secrets.
        message = str(error) if not isinstance(error, subprocess.SubprocessError) else 'A host setup command failed; no command output or credentials are printed. Inspect prerequisites and rerun.'
        print(f'Deployment setup incomplete: {message}', file=sys.stderr)
        sys.exit(1)
