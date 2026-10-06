"""Desktop startup errors stay portable and create no authority."""

import subprocess
import sys

import pytest

from recon_cockpit.gui import cli


def test_help_does_not_import_tk_or_need_a_display():
    code = "import sys; from recon_cockpit.gui.cli import main; sys.modules['tkinter'] = None; main(['--help'])"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and "--assessment" in result.stdout and not result.stderr


@pytest.mark.parametrize("args", [["--execute"], ["--approve"], ["--theme", "invalid"]])
def test_no_execution_or_approval_options(args):
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == 2


def test_missing_tk_reports_actionable_dependency(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "tkinter", None)
    assert cli.main([]) == 2
    assert "python3-tk" in capsys.readouterr().err


def test_missing_display_reports_local_graphical_session(monkeypatch, capsys):
    from types import SimpleNamespace
    class NoDisplay(Exception):
        pass
    def fail():
        raise NoDisplay()
    monkeypatch.setitem(sys.modules, "tkinter", SimpleNamespace(Tk=fail, TclError=NoDisplay))
    assert cli.main([]) == 2
    assert "local graphical session" in capsys.readouterr().err
