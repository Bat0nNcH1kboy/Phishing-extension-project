from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "CHECK_10_RUNS.txt"


def main() -> int:
    lines = ["10-run release audit verification", ""]
    for index in range(1, 11):
        started = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "scripts/release_audit.py"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
        elapsed = time.perf_counter() - started
        ok = proc.returncode == 0 and "Release audit passed" in proc.stdout
        lines.append(f"RUN {index}/10 release-audit: {'OK' if ok else 'FAIL'} ({elapsed:.2f}s)")
        if not ok:
            lines.append("--- failing output tail ---")
            lines.extend(proc.stdout.splitlines()[-80:])
            LOG.write_text("\n".join(lines), encoding="utf-8")
            print("\n".join(lines))
            return 1
    lines.append("")
    lines.append("RESULT: 10/10 release audits passed.")
    lines.append("For the full compile/pytest/node check run: python scripts/check_project.py")
    LOG.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
