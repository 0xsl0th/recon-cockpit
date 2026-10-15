"""Native networkless parsing only; no daemon or scanner is launched."""

import os
import sys

import pytest

from recon_cockpit.secure_agent import stock_ssh_parser as parser
from recon_cockpit.secure_agent import stock_ssh_parser_runtime as isolated
from test_stock_ssh_parser import xml, key, banner

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for stock SSH networkless parser execution")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("tool", (parser.NMAP, parser.SSH))
def test_actual_parser_preserves_full_version_or_unverified_key_without_host_fallback(monkeypatch, configuration, tool):
    raw, stderr = (xml(configuration), b"") if tool == parser.NMAP else (key(configuration), banner(configuration))
    expected = parser.parse_output(tool, raw, stderr, configuration=configuration)
    monkeypatch.setattr(parser, "parse_output", lambda *a, **k: pytest.fail("host parser fallback"))
    assert isolated.parse_isolated_tool_output(tool, raw, stderr, configuration=configuration) == expected


@pytest.mark.parametrize("tool", (parser.NMAP, parser.SSH))
def test_actual_parser_refuses_malformed_bytes_without_host_fallback(monkeypatch, tool):
    monkeypatch.setattr(parser, "parse_output", lambda *a, **k: pytest.fail("host parser fallback"))
    with pytest.raises(ValueError, match="invalid_stock_ssh_tool_output"):
        isolated.parse_isolated_tool_output(tool, b"malformed", configuration="A")
