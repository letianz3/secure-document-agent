"""Run reproducible checks without site packages and retain accurate evidence."""
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    tests = subprocess.run([sys.executable, "-S", "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=root, text=True, capture_output=True)
    output = f"Interpreter: {sys.version}\nMode: OFFLINE; provider HTTP mocked; site packages disabled.\n"
    output += tests.stdout + tests.stderr
    (evidence / "test_results.txt").write_text(output, encoding="utf-8")
    print(output)
    if tests.returncode:
        return tests.returncode
    return subprocess.run([sys.executable, "-S", "-m", "secure_agent", "--demo"], cwd=root).returncode


if __name__ == "__main__":
    raise SystemExit(main())
