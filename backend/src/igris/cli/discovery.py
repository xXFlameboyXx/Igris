"""Environment, repository, and asset discovery for Igris CLI launcher."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from igris import __version__


def get_app_version() -> str:
    """Return the canonical Igris version."""
    return __version__


def find_igris_root() -> Path:
    """Discover the Igris repository or installation root directory."""
    env_home = os.environ.get("IGRIS_HOME")
    if env_home:
        candidate = Path(env_home).resolve()
        if candidate.is_dir() and (candidate / "pyproject.toml").is_file():
            return candidate

    current = Path(__file__).resolve()
    for parent in current.parents:
        pyproject = parent / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8")
                if 'name = "igris"' in text or "name = 'igris'" in text:
                    return parent
            except OSError:
                pass

    return current.parents[3]


def find_python_executable(root: Path | None = None) -> Path:
    """Locate the Python executable within the Igris environment."""
    repo_root = root or find_igris_root()

    win_venv = repo_root / ".venv" / "Scripts" / "python.exe"
    if win_venv.is_file():
        return win_venv

    posix_venv = repo_root / ".venv" / "bin" / "python"
    if posix_venv.is_file():
        return posix_venv

    return Path(sys.executable)


def find_frontend_dist(root: Path | None = None) -> Path | None:
    """Locate the built frontend production directory if present."""
    repo_root = root or find_igris_root()
    dist = repo_root / "frontend" / "dist"
    if dist.is_dir() and (dist / "index.html").is_file():
        return dist
    return None


def ensure_frontend_built(root: Path | None = None, auto_build: bool = True) -> bool:
    """Ensure the frontend is compiled; attempt build with npm if missing."""
    repo_root = root or find_igris_root()
    if find_frontend_dist(repo_root) is not None:
        return True

    if not auto_build:
        return False

    frontend_dir = repo_root / "frontend"
    if not (frontend_dir / "package.json").is_file():
        return False

    npm_bin = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm_bin:
        return False

    try:
        if not (frontend_dir / "node_modules").is_dir():
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
        return find_frontend_dist(repo_root) is not None
    except (subprocess.SubprocessError, OSError):
        return False
