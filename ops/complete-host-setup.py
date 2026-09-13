#!/usr/bin/env python3
"""Finish native host availability and bounded log retention as administrator.

No network, reboot, disk encryption, credential, or API configuration changes.
"""
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path("/Library/PatchIntelligence")
LABEL = "com.patch.rotate-logs"


def run(*args, **kwargs):
    return subprocess.run([str(value) for value in args], check=True, **kwargs)


def install_file(source, destination, mode=0o644):
    if source.resolve() != destination.resolve():
        shutil.copyfile(source, destination)
    os.chown(destination, 0, 0)
    os.chmod(destination, mode)


def main():
    if os.geteuid() != 0:
        sys.exit("Run with sudo to install the daily log job and AC power recovery settings.")
    source = pathlib.Path(__file__).resolve().parent
    if not (ROOT / "ops").is_dir() or not (ROOT / "logs").is_dir():
        sys.exit("Initialize the host with ops/install-native.py first.")
    # pmset receives no displaysleep argument; the user's display setting survives.
    capabilities = run("/usr/bin/pmset", "-g", "cap", capture_output=True, text=True).stdout
    settings = ["sleep", "0"]
    if "autorestart" in capabilities.split():
        settings += ["autorestart", "1"]
    else:
        print("Automatic power recovery is unavailable on this hardware.")
    run("/usr/bin/pmset", "-c", *settings)
    for name in ("rotate-logs.py", "complete-host-setup.py"):
        install_file(source / name, ROOT / "ops" / name)
    configuration = {
        "Label": LABEL,
        "ProgramArguments": ["/usr/bin/python3", str(ROOT / "ops/rotate-logs.py")],
        "StartCalendarInterval": {"Hour": 0, "Minute": 30},
        "EnvironmentVariables": {"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"},
        "StandardOutPath": str(ROOT / "logs" / (LABEL + ".log")),
        "StandardErrorPath": str(ROOT / "logs" / (LABEL + ".err")),
    }
    plist = pathlib.Path("/Library/LaunchDaemons") / (LABEL + ".plist")
    contents = plistlib.dumps(configuration)
    changed = not plist.exists() or plist.read_bytes() != contents
    if changed:
        plist.write_bytes(contents)
    os.chown(plist, 0, 0)
    os.chmod(plist, 0o644)
    for suffix in ("log", "err"):
        path = ROOT / "logs" / (LABEL + "." + suffix)
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
    loaded = subprocess.run(["/bin/launchctl", "print", "system/" + LABEL], capture_output=True).returncode == 0
    if loaded and changed:
        run("/bin/launchctl", "bootout", "system/" + LABEL)
        loaded = False
    if not loaded:
        run("/bin/launchctl", "bootstrap", "system", plist)
    run("/usr/bin/python3", ROOT / "ops/rotate-logs.py")
    print("Daily log rotation installed for 00:30, with seven compressed archives per log.")
    print("Copy/truncate preserves active service descriptors; a small concurrent-write window may lose log lines.")
    run("/usr/bin/pmset", "-g", "custom")
    state = {}
    for service in ("postgres", "api", "tailscaled", "rotate-logs"):
        result = subprocess.run(["/bin/launchctl", "print", "system/com.patch." + service], capture_output=True, text=True)
        state[service] = next((line.strip().removeprefix("state = ") for line in result.stdout.splitlines() if line.strip().startswith("state = ")), "loaded" if result.returncode == 0 else "not loaded")
    print(json.dumps({"launchd": state, "rebootRecoveryVerified": False}))


if __name__ == "__main__":
    main()
