"""Closed production selectors and read-only CLI inspection, without daemon launch."""

import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stock_ssh_compatibility.py"


@pytest.mark.parametrize("extra", [
    [], ["--configuration", "A"],
    ["--configuration", "A", "--case", "host"],
    ["--configuration", "C", "--case", "O1"],
    ["--configuration", "A", "--case", "O1", "--target", "127.0.0.1"],
    ["--configuration", "A", "--case", "O1", "--binary", "/usr/bin/anything"],
    ["--configuration", "A", "--case", "O1", "--credential-file", "secret"],
    ["--configuration", "A", "--case", "O1", "--command", "true"],
    ["--configuration", "A", "--case", "O1", "--model", "paid"],
    ["--configuration", "A", "--case", "O1", "--exec"],
])
def test_cli_refuses_missing_or_unbounded_selector_before_output(tmp_path, extra):
    directory = tmp_path / "must-not-exist"
    result = subprocess.run([sys.executable, str(SCRIPT), "run", "--directory", str(directory), *extra],
                            capture_output=True, timeout=10)
    assert result.returncode == 2 and not directory.exists()
