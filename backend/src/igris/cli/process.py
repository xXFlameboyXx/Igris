"""Process and networking utilities for Igris CLI launcher."""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def check_port_in_use(host: str, port: int) -> bool:
    """Check whether a TCP port is currently occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        try:
            res = sock.connect_ex((host, port))
            return res == 0
        except OSError:
            return False


def check_is_igris_instance(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check whether an active service on host:port is an Igris instance."""
    url = f"http://{host}:{port}/health"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
            if response.status == 200:
                body = response.read().decode("utf-8", errors="ignore")
                data = json.loads(body)
                service_name = str(data.get("service", "")).lower()
                return "igris" in service_name
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError):
        pass
    return False


def wait_for_health(
    host: str,
    port: int,
    timeout: float = 20.0,
    poll_interval: float = 0.2,
) -> bool:
    """Poll the /health endpoint until it returns 200 OK or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if check_is_igris_instance(host, port, timeout=poll_interval):
            return True
        time.sleep(poll_interval)
    return False


def get_pid_file_path(root: Path) -> Path:
    """Return the canonical path to the Igris PID file."""
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "igris.pid"


def write_pid_file(root: Path, pid: int) -> None:
    """Record running server PID to file."""
    pid_file = get_pid_file_path(root)
    try:
        pid_file.write_text(str(pid), encoding="utf-8")
    except OSError:
        pass


def read_pid_file(root: Path) -> int | None:
    """Read running server PID from file if present and valid."""
    pid_file = get_pid_file_path(root)
    if not pid_file.is_file():
        return None
    try:
        content = pid_file.read_text(encoding="utf-8").strip()
        return int(content)
    except (ValueError, OSError):
        return None


def remove_pid_file(root: Path) -> None:
    """Remove server PID file upon clean shutdown."""
    pid_file = get_pid_file_path(root)
    try:
        if pid_file.is_file():
            pid_file.unlink()
    except OSError:
        pass


def is_pid_alive(pid: int) -> bool:
    """Check whether a process with the given PID is currently active."""
    if pid <= 0:
        return False
    try:
        if sys.platform == "win32":
            import ctypes

            windll = getattr(ctypes, "windll", None)
            if windll:
                handle = windll.kernel32.OpenProcess(0x1000, False, pid)
                if handle:
                    windll.kernel32.CloseHandle(handle)
                    return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ProcessLookupError, PermissionError):
        return False


def terminate_pid(pid: int, timeout: float = 3.0) -> bool:
    """Terminate a process by PID gracefully with timeout."""
    if not is_pid_alive(pid):
        return True

    try:
        if sys.platform == "win32":
            import subprocess

            subprocess.run(  # noqa: S603
                ["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S607
                capture_output=True,
                check=False,
            )
            return True
        else:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + timeout
            while time.time() < deadline:
                if not is_pid_alive(pid):
                    return True
                time.sleep(0.1)
            os.kill(pid, signal.SIGKILL)
            return True
    except (OSError, ProcessLookupError, PermissionError):
        return False
