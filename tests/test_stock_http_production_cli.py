"""Closed production selectors and read-only CLI inspection, without daemon launch."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_stock_http_production_evidence import manifest, save

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stock_http_compatibility.py"


@pytest.mark.parametrize("extra", [
    [], ["--implementation", "apache"],
    ["--implementation", "nginx", "--configuration", "A", "--case", "host"],
    ["--implementation", "python", "--configuration", "A", "--case", "O1"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--target", "127.0.0.1"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--binary", "/usr/bin/anything"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--credential-file", "secret"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--command", "true"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--model", "paid"],
    ["--implementation", "apache", "--configuration", "A", "--case", "O1", "--exec"],
])
def test_cli_refuses_missing_or_unbounded_selector_before_output(tmp_path, extra):
    directory = tmp_path / "must-not-exist"
    result = subprocess.run([sys.executable, str(SCRIPT), "run", "--directory", str(directory), *extra],
                            capture_output=True, timeout=10)
    assert result.returncode == 2 and not directory.exists()


def test_saved_dry_run_inspects_without_runtime_preflight_or_restoring_authority(tmp_path):
    directory = tmp_path / "dry-run"
    report = save(directory, manifest(), None, execute=False)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    result = subprocess.run([sys.executable, str(SCRIPT), "inspect", str(directory)], capture_output=True, timeout=10)
    assert result.returncode == 1 and json.loads(result.stdout) == report
    assert report["execution_status"] == "dry_run" and report["case_passed"] is False
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
