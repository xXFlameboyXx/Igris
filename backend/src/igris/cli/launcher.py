"""Global CLI Launcher for Igris Malware Analysis & Intelligence Platform."""

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import webbrowser
from pathlib import Path

from igris.cli.discovery import (
    ensure_frontend_built,
    find_frontend_dist,
    find_igris_root,
    find_python_executable,
    get_app_version,
)
from igris.cli.process import (
    check_is_igris_instance,
    check_port_in_use,
    read_pid_file,
    remove_pid_file,
    terminate_pid,
    wait_for_health,
    write_pid_file,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser for Igris launcher."""
    parser = argparse.ArgumentParser(
        prog="igris",
        description="Igris: Explainable Malware Analysis & Threat Intelligence Platform.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Show Igris version and exit.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check whether Igris is currently running.",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop any active Igris background server instance.",
    )
    parser.add_argument(
        "--repair",
        action="store_true",
        help="Rebuild frontend assets and verify system environment.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Port to bind the Igris server to (default: 8000).",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind the Igris server to (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the web browser automatically upon server startup.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Start in development mode with active Vite dev server.",
    )
    return parser


def handle_version() -> int:
    """Print version string."""
    print(f"Igris v{get_app_version()}")
    return 0


def handle_status(host: str, port: int, root: Path) -> int:
    """Check and display running server status."""
    is_in_use = check_port_in_use(host, port)
    is_igris = check_is_igris_instance(host, port) if is_in_use else False
    pid = read_pid_file(root)

    if is_igris:
        pid_info = f" (PID: {pid})" if pid else ""
        print(f"Igris is running at http://{host}:{port}{pid_info}")
        return 0
    elif is_in_use:
        print(f"Port {port} is occupied by another application.")
        return 1
    else:
        print(f"Igris is not currently running on http://{host}:{port}.")
        return 0


def handle_stop(host: str, port: int, root: Path) -> int:
    """Stop active Igris server instance."""
    pid = read_pid_file(root)
    stopped = False

    if pid:
        stopped = terminate_pid(pid)
        remove_pid_file(root)

    if not stopped and check_is_igris_instance(host, port):
        print(f"Warning: Could not terminate PID {pid}, but Igris responds on port {port}.")
        return 1

    print("Igris server stopped successfully.")
    return 0


def handle_repair(root: Path) -> int:
    """Rebuild frontend and verify dependencies."""
    print("Repairing Igris...")
    print(f"Repository Root: {root}")
    print("Building frontend production bundle...")
    success = ensure_frontend_built(root, auto_build=True)
    if success:
        print("Frontend built successfully.")
        print("Igris repair completed successfully.")
        return 0
    else:
        print("Error: Failed to build frontend. Ensure Node.js and npm are installed.")
        return 1


def launch_igris(
    *,
    host: str,
    port: int,
    no_browser: bool,
    dev_mode: bool,
    root: Path,
    python_exe: Path,
) -> int:
    """Launch the Igris application."""
    url = f"http://{host}:{port}"

    if check_port_in_use(host, port):
        if check_is_igris_instance(host, port):
            print(f"Igris is already running at {url}")
            if not no_browser:
                print(f"Opening existing Igris instance in browser: {url}")
                webbrowser.open(url)
            return 0
        else:
            print(
                f"Error: Port {port} is already occupied by another application.\n"
                f"Use --port <PORT> to specify an available port, e.g.: igris --port 8080"
            )
            return 1

    if not dev_mode:
        dist_dir = find_frontend_dist(root)
        if not dist_dir:
            print("Frontend production bundle not found. Building...")
            if not ensure_frontend_built(root, auto_build=True):
                print(
                    "Error: Could not find or build frontend production bundle.\n"
                    "Run 'igris --repair' or 'npm run build' inside the frontend/ directory."
                )
                return 1

    processes: list[subprocess.Popen[bytes]] = []

    def cleanup_processes(signum: int | None = None, frame: object = None) -> None:
        print("\nShutting down Igris...")
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=3)
            except (subprocess.SubprocessError, OSError):
                try:
                    p.kill()
                except OSError:
                    pass
        remove_pid_file(root)
        print("Igris stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_processes)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, cleanup_processes)

    print("Starting Igris...")
    print("Backend: starting...")

    backend_cwd = str(root)
    app_dir = str(root / "backend" / "src")
    backend_cmd = [
        str(python_exe),
        "-m",
        "uvicorn",
        "igris.main:app",
        "--host",
        host,
        "--port",
        str(port),
        "--app-dir",
        app_dir,
    ]

    backend_proc = subprocess.Popen(  # noqa: S603
        backend_cmd,
        cwd=backend_cwd,
    )
    processes.append(backend_proc)
    write_pid_file(root, backend_proc.pid)

    if dev_mode:
        print("Frontend (dev): starting Vite...")
        npm_bin = "npm.cmd" if sys.platform == "win32" else "npm"
        frontend_proc = subprocess.Popen(  # noqa: S603
            [npm_bin, "run", "dev"],
            cwd=str(root / "frontend"),
        )
        processes.append(frontend_proc)

    ready = wait_for_health(host, port, timeout=25.0)
    if not ready:
        print(f"Error: Igris backend failed to start on {url} within timeout.")
        cleanup_processes()
        return 1

    print(f"Backend: ready ({url})")
    print("Frontend: ready")

    target_open_url = "http://127.0.0.1:5173" if dev_mode else url

    if not no_browser:
        print(f"Opening Igris in your browser: {target_open_url}")
        webbrowser.open(target_open_url)

    print("\nIgris is running. Press Ctrl+C to stop.")

    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        cleanup_processes()

    remove_pid_file(root)
    return 0


def main(args: list[str] | None = None) -> int:
    """CLI entry point for igris command."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.version:
        return handle_version()

    root = find_igris_root()
    python_exe = find_python_executable(root)

    if parsed.status:
        return handle_status(parsed.host, parsed.port, root)

    if parsed.stop:
        return handle_stop(parsed.host, parsed.port, root)

    if parsed.repair:
        return handle_repair(root)

    return launch_igris(
        host=parsed.host,
        port=parsed.port,
        no_browser=parsed.no_browser,
        dev_mode=parsed.dev,
        root=root,
        python_exe=python_exe,
    )


if __name__ == "__main__":
    sys.exit(main())
