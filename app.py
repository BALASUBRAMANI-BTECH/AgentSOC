"""
AgentSOC Application Launcher
Runs the FastAPI backend and React Dashboard using Uvicorn.
"""
import os
import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
VENV_PYTHON = BACKEND_DIR / "venv" / "Scripts" / "python.exe"


def main():
    # If not running inside the project's virtualenv and the venv exists, delegate to it
    if VENV_PYTHON.exists() and Path(sys.executable).resolve() != VENV_PYTHON.resolve():
        cmd = [str(VENV_PYTHON), str(Path(__file__).resolve())] + sys.argv[1:]
        sys.exit(subprocess.call(cmd))

    # Ensure backend directory is in sys.path and PYTHONPATH
    backend_str = str(BACKEND_DIR)
    if backend_str not in sys.path:
        sys.path.insert(0, backend_str)

    current_pythonpath = os.environ.get("PYTHONPATH", "")
    if backend_str not in current_pythonpath.split(os.pathsep):
        os.environ["PYTHONPATH"] = f"{backend_str}{os.pathsep}{current_pythonpath}" if current_pythonpath else backend_str

    import uvicorn

    print("=" * 65)
    print("  AGENTSOC — Autonomous AI-Powered Security Operations Center")
    print("=" * 65)
    print("  * Dashboard:   http://127.0.0.1:8000/dashboard")
    print("  * API Docs:    http://127.0.0.1:8000/docs")
    print("  * Health:      http://127.0.0.1:8000/health")
    print("  * Admin Pass:  24282428")
    print("=" * 65)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        reload_dirs=[backend_str],
        app_dir=backend_str
    )


if __name__ == "__main__":
    main()
