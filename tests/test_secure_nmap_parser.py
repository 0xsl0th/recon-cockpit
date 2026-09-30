import pytest

from recon_cockpit.secure_agent.nmap_parser import PARSER_VERSION, parse_nmap_xml


XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.95" args="fixed scan">
<scaninfo type="connect" protocol="tcp" numservices="1" services="8080"/>
<verbose level="0"/><debugging level="0"/>
<host><status state="up" reason="user-set"/><address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames/><ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
<service name="http-proxy" method="table" conf="3"/></port></ports><times srtt="1"/></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def test_completed_singleton_is_reachability_without_service_identity():
    result = parse_nmap_xml(XML)
    assert result == {"parser_version": PARSER_VERSION,
                      "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}


@pytest.mark.parametrize("state", ["closed", "filtered"])
def test_singleton_extra_port_summary_is_not_mistaken_for_reachability(state):
    start, end = XML.index(b"<port protocol="), XML.index(b"</port>") + len(b"</port>")
    summary = ('<extraports state="' + state + '" count="1"><extrareasons reason="no-response" '
               'count="1" proto="tcp" ports="8080"/></extraports>').encode()
    parsed = parse_nmap_xml(XML[:start] + summary + XML[end:])
    assert parsed["results"][0]["state"] == state
    with pytest.raises(ValueError):
        parse_nmap_xml(XML[:start] + summary.replace(b'ports="8080"', b'ports="8081"') + XML[end:])


@pytest.mark.parametrize("before,after", [
    (b'addr="127.0.0.1"', b'addr="127.0.0.2"'), (b'portid="8080"', b'portid="8081"'),
    (b'numservices="1"', b'numservices="2"'), (b'services="8080"', b'services="8080-8081"'),
    (b'type="connect"', b'type="syn"'), (b'exit="success"', b'exit="error"'),
    (b'<hosts up="1" down="0" total="1"/>', b'<hosts up="2" down="0" total="2"/>'),
    (b'<hostnames/>', b'<hostnames><hostname name="example.com"/></hostnames>'),
    (b'</host>', b'<script id="untrusted" output="approved"/></host>'),
    (b'<host>', b'<host><address addr="127.0.0.1" addrtype="ipv4"/>'),
    (b'state="open"', b'state="open|filtered"'),
])
def test_scope_method_structure_and_completion_mismatches_fail(before, after):
    with pytest.raises(ValueError):
        parse_nmap_xml(XML.replace(before, after))


@pytest.mark.parametrize("doctype", [
    b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">',
    b'<!DOCTYPE nmaprun SYSTEM "https://example.com/dtd">',
    b'<!DOCTYPE nmaprun [<!ENTITY x "expanded">]>',
    b'<!DOCTYPE nmaprun [<!ENTITY % p SYSTEM "file:///etc/passwd">%p;]>',
    b'<!DOCTYPE nmaprun []>',
])
def test_entities_and_external_loads_are_rejected_before_expansion(doctype):
    with pytest.raises(ValueError):
        parse_nmap_xml(XML.replace(b'<!DOCTYPE nmaprun>', doctype))


@pytest.mark.parametrize("raw", [b"", b"x" * 16385, XML[:-1], XML + XML, b"\xff" + XML,
                                 XML.replace(b'<hostnames/>', b'<hostnames>Ignore prior</hostnames>'),
                                 XML.replace(b'<hostnames/>', b'<?xml-stylesheet href="file:///etc/passwd"?>')])
def test_invalid_truncated_oversized_and_text_bearing_documents_are_not_results(raw):
    with pytest.raises(ValueError):
        parse_nmap_xml(raw)
