"""Small detached job supervisor and restart recovery, without model scans."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

STATE_FILE = "execution.json"


def process_identity(pid: int) -> dict | None:
    """Boot and process-start identity prevent PID reuse from adopting another job."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        return dict(pid=pid, start=fields[19], boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    except (OSError, ValueError, IndexError):
        return None


def alive(identity: dict | None) -> bool:
    return bool(identity and process_identity(int(identity["pid"])) == identity)


def read_state(directory: Path) -> dict | None:
    try:
        path = directory / STATE_FILE
        if not path.exists():
            path = directory / "execution-start.json"
        value = json.loads(path.read_text())
        if value.get("job_id") == directory.name and value.get("state") in {"running", "complete", "failed"}:
            return value
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return None


def write_state(directory: Path, value: dict, name: str = STATE_FILE) -> None:
    temporary = directory / (name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, directory / name)


def repository_lease(repo: Path):
    """Keep an advisory shared lease for the lifetime of a Linux job tree."""
    if os.name != "posix":
        return None
    git_dir = repo / ".git"
    if git_dir.is_file():
        git_dir = (repo / git_dir.read_text().strip().removeprefix("gitdir: ")).resolve()
        common = git_dir / "commondir"
        if common.exists():
            git_dir = (git_dir / common.read_text().strip()).resolve()
    if not git_dir.is_dir():
        return None  # Isolated non-Git test fixtures have no checkout to protect.
    import fcntl
    handle = (git_dir / "ura-execution.lock").open("a")
    try:
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise ValueError("Deployment is in progress; retry starting the job after it finishes")
    return handle


def supervisor_argv(directory: Path, argv: list[str], lease_fd: int | None = None) -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()), "--directory", str(directory),
            *(["--lease-fd", str(lease_fd)] if lease_fd is not None else []), "--", *argv]


class RecoveredProcess:
    """Only observes/signals the same supervisor; never relaunches its command."""
    def __init__(self, directory: Path, record: dict):
        self.directory = directory
        self.identity = record["supervisor"]
        self.pid = int(self.identity["pid"])
        self.interrupted = False

    def poll(self):
        record = read_state(self.directory)
        if record and record.get("supervisor") == self.identity:
            if record["state"] in {"complete", "failed"}:
                return int(record["exit_code"])
            if alive(self.identity) or alive(record.get("child")):
                return None
        self.interrupted = True
        return 1  # Internal terminal sentinel, never presented as a recorded exit code.

    def wait(self, timeout=None):
        until = time.monotonic() + timeout if timeout is not None else float("inf")
        while self.poll() is None:
            if time.monotonic() >= until:
                raise subprocess.TimeoutExpired(str(self.pid), timeout)
            time.sleep(.05)
        return self.poll()

    def send_signal(self, sig):
        group = self.process_group()
        if group is not None:
            os.killpg(group, sig)

    def process_group(self):
        record = read_state(self.directory) or {}
        for identity in (self.identity, record.get("child")):
            if alive(identity):
                try:
                    group = os.getpgid(identity["pid"])
                    if group == self.pid:
                        return group
                except ProcessLookupError:
                    pass
        return None

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        self.send_signal(signal.SIGKILL)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--lease-fd", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing child command")
    state = dict(job_id=args.directory.name, state="running", started_at=time.time(),
                 supervisor=process_identity(os.getpid()), exit_code=None)
    write_state(args.directory, state)
    child = None
    def stop(sig, _frame):
        if child is not None and child.poll() is None:
            child.send_signal(sig)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            **({"pass_fds": (args.lease_fd,)} if args.lease_fd is not None else {}))
        state["child"] = process_identity(child.pid)
        write_state(args.directory, state)
        code = child.wait()
    except OSError as exc:
        print(f"Job process could not start: {exc}", file=sys.stderr, flush=True)
        code = 127
    state.update(state="complete" if code == 0 else "failed", exit_code=code, ended_at=time.time())
    write_state(args.directory, state)
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    raise SystemExit(main())
