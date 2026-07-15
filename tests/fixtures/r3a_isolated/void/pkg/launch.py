import os
import subprocess
import sys

os.environ["PYTHONWARNINGS"] = "error"
ARGV = [sys.executable, "-I", "child.py"]


def run() -> None:
    subprocess.run(ARGV, check=True)
