"""Run the generator with `python -m imsovain`.

The first run from a checkout creates `.venv`, builds the search extension,
and continues with the same arguments.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
VENV_PYTHON = VENV / "bin" / "python"
_BOOTSTRAPPED = "IMSOVAIN_BOOTSTRAPPED"


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def _is_checkout() -> bool:
    return (ROOT / "pyproject.toml").is_file() and (ROOT / "accel" / "search.c").is_file()


def _in_project_venv() -> bool:
    return Path(sys.prefix).resolve() == VENV.resolve()


def _extension_imports(python: Path) -> bool:
    completed = subprocess.run(
        [str(python), "-c", "import imsovain._accel"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _extension_imports_here() -> bool:
    try:
        import imsovain._accel  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


def _ensure_venv() -> Path:
    if VENV_PYTHON.is_file() and os.access(VENV_PYTHON, os.X_OK):
        return VENV_PYTHON
    try:
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    except subprocess.CalledProcessError:
        _fail(f"could not create {VENV} with {sys.executable}")
    if not VENV_PYTHON.is_file():
        _fail(f"{VENV_PYTHON} is missing after creating the virtualenv")
    return VENV_PYTHON


def _install(python: Path) -> None:
    try:
        subprocess.run(
            [str(python), "-m", "pip", "install", "-e", str(ROOT)],
            check=True,
            cwd=ROOT,
        )
    except subprocess.CalledProcessError:
        _fail(f"could not install {ROOT} into {python}")


def _reexec(python: Path, *, installed: bool) -> None:
    env = os.environ.copy()
    if installed:
        env[_BOOTSTRAPPED] = "1"
    os.execve(str(python), [str(python), "-m", "imsovain", *sys.argv[1:]], env)


def main() -> None:
    """Create the checkout environment when needed, then search."""
    if not _is_checkout() or (_in_project_venv() and _extension_imports_here()):
        from imsovain.cli import main as search

        search()
        return
    if os.environ.get(_BOOTSTRAPPED) == "1":
        _fail("the search extension did not load. From the repository root, run: pip install -e .")
    python = _ensure_venv()
    installed = False
    if not _extension_imports(python):
        _install(python)
        installed = True
    _reexec(python, installed=installed)


if __name__ == "__main__":
    main()
