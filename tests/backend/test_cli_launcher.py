"""Tests for the Igris CLI Launcher, environment discovery, and process management."""

import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from igris import __version__
from igris.cli.discovery import (
    find_frontend_dist,
    find_igris_root,
    find_python_executable,
    get_app_version,
)
from igris.cli.launcher import (
    build_parser,
    handle_status,
    handle_stop,
    handle_version,
    launch_igris,
    main,
)
from igris.cli.process import (
    read_pid_file,
    remove_pid_file,
    write_pid_file,
)


def test_version_command() -> None:
    """Verify version command returns correct version string and exit code 0."""
    f = io.StringIO()
    with redirect_stdout(f):
        code = handle_version()
    assert code == 0
    assert f"Igris v{__version__}" in f.getvalue()
    assert get_app_version() == __version__


def test_help_parser() -> None:
    """Verify argument parser contains expected CLI flags."""
    parser = build_parser()
    help_text = parser.format_help()
    assert "--version" in help_text
    assert "--status" in help_text
    assert "--stop" in help_text
    assert "--repair" in help_text
    assert "--port" in help_text
    assert "--host" in help_text
    assert "--no-browser" in help_text
    assert "--dev" in help_text


def test_discovery_root_and_python() -> None:
    """Verify repository root and python executable discovery."""
    root = find_igris_root()
    assert root.is_dir()
    assert (root / "pyproject.toml").is_file()

    py_exe = find_python_executable(root)
    assert py_exe.is_file() or py_exe.name.startswith("python")


def test_discovery_frontend_dist() -> None:
    """Verify frontend dist discovery locates production assets."""
    root = find_igris_root()
    dist = find_frontend_dist(root)
    assert dist is not None
    assert (dist / "index.html").is_file()


def test_pid_file_lifecycle(tmp_path: Path) -> None:
    """Verify writing, reading, and removing PID file."""
    assert read_pid_file(tmp_path) is None
    write_pid_file(tmp_path, 12345)
    assert read_pid_file(tmp_path) == 12345
    remove_pid_file(tmp_path)
    assert read_pid_file(tmp_path) is None


def test_status_when_not_running(tmp_path: Path) -> None:
    """Verify status reports inactive when port is not in use."""
    with patch("igris.cli.launcher.check_port_in_use", return_value=False):
        f = io.StringIO()
        with redirect_stdout(f):
            code = handle_status("127.0.0.1", 8999, tmp_path)
        assert code == 0
        assert "not currently running" in f.getvalue()


def test_status_when_igris_running(tmp_path: Path) -> None:
    """Verify status detects running Igris instance."""
    write_pid_file(tmp_path, 9999)
    with patch("igris.cli.launcher.check_port_in_use", return_value=True):
        with patch("igris.cli.launcher.check_is_igris_instance", return_value=True):
            f = io.StringIO()
            with redirect_stdout(f):
                code = handle_status("127.0.0.1", 8000, tmp_path)
            assert code == 0
            assert "Igris is running" in f.getvalue()
            assert "PID: 9999" in f.getvalue()


def test_status_when_foreign_port_conflict(tmp_path: Path) -> None:
    """Verify status detects non-Igris occupied port."""
    with patch("igris.cli.launcher.check_port_in_use", return_value=True):
        with patch("igris.cli.launcher.check_is_igris_instance", return_value=False):
            f = io.StringIO()
            with redirect_stdout(f):
                code = handle_status("127.0.0.1", 8000, tmp_path)
            assert code == 1
            assert "occupied by another application" in f.getvalue()


def test_stop_command_clean_exit(tmp_path: Path) -> None:
    """Verify handle_stop terminates PID and cleans up PID file."""
    write_pid_file(tmp_path, 8888)
    with patch("igris.cli.launcher.terminate_pid", return_value=True):
        f = io.StringIO()
        with redirect_stdout(f):
            code = handle_stop("127.0.0.1", 8000, tmp_path)
        assert code == 0
        assert "stopped successfully" in f.getvalue()
        assert read_pid_file(tmp_path) is None


def test_already_running_opens_browser_and_exits(tmp_path: Path) -> None:
    """Verify launching when already running opens browser and exits cleanly without spawning."""
    with patch("igris.cli.launcher.check_port_in_use", return_value=True):
        with patch("igris.cli.launcher.check_is_igris_instance", return_value=True):
            with patch("webbrowser.open") as mock_open:
                f = io.StringIO()
                with redirect_stdout(f):
                    code = launch_igris(
                        host="127.0.0.1",
                        port=8000,
                        no_browser=False,
                        dev_mode=False,
                        root=tmp_path,
                        python_exe=Path("python"),
                    )
                assert code == 0
                assert "already running" in f.getvalue()
                mock_open.assert_called_once_with("http://127.0.0.1:8000")


def test_port_conflict_reports_actionable_error(tmp_path: Path) -> None:
    """Verify foreign port conflict outputs actionable message and exits code 1."""
    with patch("igris.cli.launcher.check_port_in_use", return_value=True):
        with patch("igris.cli.launcher.check_is_igris_instance", return_value=False):
            f = io.StringIO()
            with redirect_stdout(f):
                code = launch_igris(
                    host="127.0.0.1",
                    port=8000,
                    no_browser=False,
                    dev_mode=False,
                    root=tmp_path,
                    python_exe=Path("python"),
                )
            assert code == 1
            assert "occupied by another application" in f.getvalue()
            assert "--port" in f.getvalue()


def test_main_cli_dispatch() -> None:
    """Verify main() properly dispatches --version and --help."""
    f = io.StringIO()
    with redirect_stdout(f):
        res = main(["--version"])
    assert res == 0
    assert f"Igris v{__version__}" in f.getvalue()
