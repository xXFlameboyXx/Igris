"""Global CLI Launcher for Igris Malware Analysis & Intelligence Platform."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import webbrowser
from pathlib import Path

from igris.cli.banner import print_banner
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
        "--update",
        action="store_true",
        help="Pull latest changes from GitHub, update dependencies, and rebuild assets.",
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


def handle_update(host: str, port: int, root: Path) -> int:
    """Pull latest updates from Git, update dependencies, and rebuild frontend."""
    print("Updating Igris...")
    print(f"Repository Root: {root}")

    # 1. Stop running instance if one exists
    if check_port_in_use(host, port) and check_is_igris_instance(host, port):
        print("Stopping running Igris instance for update...")
        handle_stop(host, port, root)

    # 2. Check Git availability and pull
    git_bin = shutil.which("git")
    if not git_bin:
        print("Error: Git executable not found on PATH. Please install Git or update manually.")
        return 1

    print("[1/3] Pulling latest changes from GitHub...")
    try:
        git_res = subprocess.run(  # noqa: S603
            [git_bin, "pull"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if git_res.returncode != 0:
            err_msg = git_res.stderr.strip() or git_res.stdout.strip()
            print(f"Warning: Git pull reported issues:\n{err_msg}")
        else:
            print(f"Git: {git_res.stdout.strip()}")
    except OSError as exc:
        print(f"Error running git pull: {exc}")
        return 1

    # 3. Update Python dependencies
    print("[2/3] Updating backend dependencies...")
    uv_bin = shutil.which("uv")
    if uv_bin:
        try:
            subprocess.run(  # noqa: S603
                [uv_bin, "sync"],
                cwd=str(root),
                check=True,
                capture_output=True,
            )
            print("Backend dependencies synchronized via uv.")
        except (subprocess.SubprocessError, OSError):
            print("Note: uv sync completed with warnings.")
    else:
        python_exe = find_python_executable(root)
        try:
            subprocess.run(  # noqa: S603
                [str(python_exe), "-m", "pip", "install", "-e", "."],
                cwd=str(root),
                check=True,
                capture_output=True,
            )
            print("Backend package refreshed via pip.")
        except (subprocess.SubprocessError, OSError):
            pass

    # 4. Rebuild frontend bundle
    print("[3/3] Rebuilding frontend production bundle...")
    frontend_dir = root / "frontend"
    npm_bin = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm_bin and sys.platform == "win32":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "npm.cmd"
        if candidate.is_file():
            npm_bin = str(candidate)

    if npm_bin and (frontend_dir / "package.json").is_file():
        try:
            subprocess.run(  # noqa: S603
                [npm_bin, "install"],
                cwd=str(frontend_dir),
                check=True,
                capture_output=True,
            )
            subprocess.run(  # noqa: S603
                [npm_bin, "run", "build"],
                cwd=str(frontend_dir),
                check=True,
                capture_output=True,
            )
            print("Frontend production bundle compiled successfully.")
        except (subprocess.SubprocessError, OSError) as exc:
            print(f"Error: Failed to rebuild frontend: {exc}")
            return 1
    else:
        print("Warning: npm not found or frontend package.json missing.")

    print("\n========================================================")
    print(f"✔ Igris updated successfully! (v{get_app_version()})")
    print("Run 'igris' from any terminal to start the updated platform.")
    print("========================================================")
    return 0


def launch_igris(
    *,
    host: str,
    port: int,
    no_browser: bool,
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

    print_banner(target_url=url, version=f"v{get_app_version()}")

    print("Starting Igris...")
    print("Backend: starting...")

    backend_cwd = str(root)
    app_dir = str(root / "backend" / "src")
    backend_env = {**os.environ, "IGRIS_LOG_LEVEL": "WARNING"}
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
        "--log-level",
        "warning",
        "--no-access-log",
    ]

    backend_proc = subprocess.Popen(  # noqa: S603
        backend_cmd,
        cwd=backend_cwd,
        env=backend_env,
    )
    processes.append(backend_proc)
    write_pid_file(root, backend_proc.pid)

    ready = wait_for_health(host, port, timeout=25.0)
    if not ready:
        print(f"Error: Igris backend failed to start on {url} within timeout.")
        cleanup_processes()
        return 1

    print(f"Backend: ready ({url})")
    print("Frontend: ready")

    if not no_browser:
        print(f"Opening Igris in your browser: {url}")
        webbrowser.open(url)

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

    if parsed.update:
        return handle_update(parsed.host, parsed.port, root)

    return launch_igris(
        host=parsed.host,
        port=parsed.port,
        no_browser=parsed.no_browser,
        root=root,
        python_exe=python_exe,
    )


if __name__ == "__main__":
    sys.exit(main())
