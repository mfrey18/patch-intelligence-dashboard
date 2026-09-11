#!/usr/bin/env python3
"""Rotate launchd output without replacing its open file descriptors.

Copy/truncate has a small concurrent-write loss window. Keep seven compressed
archives per known log; archive permissions are restricted to the operator.
"""
import argparse
import datetime
import fcntl
import gzip
import json
import os
import pathlib
import stat
import tempfile

LABELS = ("api", "postgres", "tailscaled", "backup", "restore-test", "rotate-logs", "bootstrap")
KEEP = 7
COPY_BLOCK = 1024 * 1024


def rotate(root):
    logs = root / "logs"
    archive = logs / "archive"
    if not stat.S_ISDIR(logs.lstat().st_mode):
        raise RuntimeError("Logs path must be a real directory")
    archive.mkdir(mode=0o700, exist_ok=True)
    if not stat.S_ISDIR(archive.lstat().st_mode):
        raise RuntimeError("Archive path must be a real directory")
    archive.chmod(0o700)
    lock_fd = os.open(archive / ".rotate.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"rotated": 0, "bytesArchived": 0, "alreadyRunning": True}
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        count = total = 0
        for label in LABELS:
            for suffix in ("log", "err"):
                name = "com.patch.{}.{}".format(label, suffix)
                path = logs / name
                try:
                    source_fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                except FileNotFoundError:
                    continue
                with os.fdopen(source_fd, "r+b", buffering=0) as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise RuntimeError("Expected a regular log file: " + name)
                    if before.st_size:
                        destination = archive / (name + "." + stamp + ".gz")
                        temporary = None
                        try:
                            with tempfile.NamedTemporaryFile(dir=archive, prefix=".partial-", delete=False) as output:
                                temporary = pathlib.Path(output.name)
                                with gzip.GzipFile(filename="", fileobj=output, mode="wb") as compressed:
                                    remaining = before.st_size
                                    while remaining:
                                        block = source.read(min(remaining, COPY_BLOCK))
                                        if not block:
                                            raise RuntimeError("Log shrank during rotation: " + name)
                                        compressed.write(block)
                                        remaining -= len(block)
                                output.flush()
                                os.fsync(output.fileno())
                            os.replace(temporary, destination)
                            temporary = None
                            # Preserve the inode used by launchd. Writes between the
                            # initial size snapshot and this truncate can be lost.
                            os.ftruncate(source.fileno(), 0)
                            os.fsync(source.fileno())
                            count += 1
                            total += before.st_size
                        finally:
                            if temporary is not None:
                                temporary.unlink(missing_ok=True)
                existing = sorted(archive.glob(name + ".*.gz"), reverse=True)
                for expired in existing[KEEP:]:
                    expired.unlink()
        return {"rotated": count, "bytesArchived": total, "archivesPerLog": KEEP}
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/Library/PatchIntelligence"))
    print(json.dumps(rotate(parser.parse_args().root)))
