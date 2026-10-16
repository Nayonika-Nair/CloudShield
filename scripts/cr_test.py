"""Test command used by Cosmic Ray: run pytest, merge stderr into stdout so every kill records *why* the tests failed.

Cosmic Ray keeps only stdout of a failing test command; without this wrapper an ImportError (stderr) looks like an empty kill.
Usage: python cr_test.py <pytest args...>
"""
import subprocess
import sys

proc = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *sys.argv[1:]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
print(proc.stdout)
sys.exit(proc.returncode)
