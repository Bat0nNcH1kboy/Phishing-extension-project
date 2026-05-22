from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
EXTENSION = ROOT / "extension"


def run(command: list[str], cwd: Path = ROOT) -> None:
    print("\n$", " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    os.environ.setdefault("PHISHING_DNS_CHECK_ENABLED", "0")
    run([sys.executable, "-m", "compileall", "backend"], ROOT)
    run([sys.executable, "-m", "pytest", "-q"], BACKEND)
    run([sys.executable, "scripts/release_audit.py"], ROOT)
    node = "node.exe" if os.name == "nt" else "node"
    try:
        run([node, "--check", str(EXTENSION / "popup.js")], ROOT)
        run([node, "--check", str(EXTENSION / "background.js")], ROOT)
    except FileNotFoundError:
        print("node не найден: Python/pytest проверки выполнены, JS syntax-check пропущен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
