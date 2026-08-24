from __future__ import annotations

from pathlib import Path

from recon_cockpit.parsers import (
    ingest_command_output,
    parse_nmap_xml,
    parse_nmap_xml_text,
    strip_ansi,
)


NMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 10.10.11.123">
  <host>
    <status state="up" reason="echo-reply" />
    <address addr="00:11:22:33:44:55" addrtype="mac" />
    <address addr="10.10.11.123" addrtype="ipv4" />
    <hostnames>
      <hostname name="DC01.corp.htb" type="PTR" />
      <hostname name="dc01.corp.htb" type="user" />
      <hostname type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" />
        <service name="http" product="Microsoft IIS httpd" version="10.0"
                 extrainfo="Windows Server 2022" tunnel="ssl" />
        <script id="http-title" output="Intranet Portal" />
        <script id="http-server-header">
          <elem key="server">Microsoft-IIS/10.0</elem>
        </script>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" product="Microsoft Windows Server 2008 R2 - 2012" />
        <script id="smb2-security-mode" output="Message signing enabled and required" />
      </port>
      <port protocol="udp" portid="53">
        <state state="open|filtered" />
      </port>
      <port protocol="tcp"><state state="open" /></port>
    </ports>
    <os>
      <osmatch name="Microsoft Windows Server 2019" accuracy="91" />
      <osmatch name="Microsoft Windows Server 2022" accuracy="98" />
    </os>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_text_captures_service_evidence_and_best_os_guess() -> None:
    hosts, services = parse_nmap_xml_text(NMAP_XML)

    assert len(hosts) == 1
    assert hosts[0].address == "10.10.11.123"
    assert hosts[0].status == "up"
    assert hosts[0].hostnames == ["DC01.corp.htb"]
    assert hosts[0].os_guess == "Microsoft Windows Server 2022"

    assert [service.port for service in services] == [80, 445, 53]
    http = services[0]
    assert (http.protocol, http.state, http.name) == ("tcp", "open", "http")
    assert http.product == "Microsoft IIS httpd"
    assert http.version == "10.0"
    assert http.extra_info == "Windows Server 2022"
    assert http.tunnel == "ssl"
    assert http.banner == "Microsoft IIS httpd 10.0 Windows Server 2022"
    assert http.scripts == {
        "http-title": "Intranet Portal",
        "http-server-header": "Microsoft-IIS/10.0",
    }
    assert services[2].name == "unknown"
    assert services[2].state == "open|filtered"


def test_parse_nmap_xml_accepts_a_path_and_tolerates_missing_attributes(
    tmp_path: Path,
) -> None:
    xml_path = tmp_path / "initial.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <address addr="fd00::10" addrtype="ipv6" />
            <ports>
              <port portid="5985">
                <script output="no id present" />
              </port>
            </ports>
            <os>
              <osclass vendor="Microsoft" osfamily="Windows" osgen="2022"
                       type="general purpose" accuracy="95" />
            </os>
          </host>
          <host><address addrtype="ipv4" /></host>
        </nmaprun>
        """,
        encoding="utf-8",
    )

    hosts, services = parse_nmap_xml(xml_path)

    assert [host.address for host in hosts] == ["fd00::10", ""]
    assert hosts[0].status == "unknown"
    assert hosts[0].os_guess == "Microsoft Windows 2022 general purpose"
    assert services[0].host == "fd00::10"
    assert services[0].protocol == "tcp"
    assert services[0].state == "unknown"
    assert services[0].scripts == {"script-1": "no id present"}


def test_parse_nmap_xml_also_accepts_an_xml_string() -> None:
    hosts, services = parse_nmap_xml(NMAP_XML)

    assert hosts[0].address == "10.10.11.123"
    assert services[1].scripts["smb2-security-mode"].endswith("required")


NXC_OUTPUT = """\
\x1b[34mSMB         10.10.11.123   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:CORP.HTB) (signing:True) (SMBv1:False)\x1b[0m
SMB         10.10.11.123   445    DC01             [-] CORP.HTB\\alice:WrongPassword STATUS_LOGON_FAILURE
SMB         10.10.11.123   445    DC01             [+] CORP.HTB\\svc_backup:S3cret! (Pwn3d!)
SMB         10.10.11.123   445    DC01             [+] CORP.HTB\\svc_backup:S3cret! (Pwn3d!)
SMB         10.10.11.123   445    DC01             [*] Enumerated shares
SMB         10.10.11.123   445    DC01             Share           Permissions     Remark
SMB         10.10.11.123   445    DC01             -----           -----------     ------
SMB         10.10.11.123   445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.123   445    DC01             DEV             READ,WRITE      Engineering files
SMB         10.10.11.123   445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.123   445    DC01             [*] Brute forcing RIDs
SMB         10.10.11.123   445    DC01             500: CORP\\Administrator (SidTypeUser)
SMB         10.10.11.123   445    DC01             1104: CORP\\svc_backup (SidTypeUser)
SMB         10.10.11.123   445    DC01             1104: CORP\\svc_backup (SidTypeUser)
"""


def test_ingest_nxc_smb_output_extracts_and_deduplicates_evidence() -> None:
    result = ingest_command_output(NXC_OUTPUT, source="loot/nxc.txt")

    assert result.target_ips == ["10.10.11.123"]
    assert result.hostnames == ["DC01"]
    assert result.domains == ["CORP.HTB", "CORP"]
    assert result.usernames == ["svc_backup", "Administrator"]

    assert len(result.credentials) == 1
    credential = result.credentials[0]
    assert credential.username == "svc_backup"
    assert credential.domain == "CORP.HTB"
    assert credential.secret == "S3cret!"
    assert credential.status == "successful (admin)"
    assert credential.source == "loot/nxc.txt"
    assert all(item.username != "alice" for item in result.credentials)

    assert [(share.name, share.permissions, share.remark) for share in result.shares] == [
        ("ADMIN$", "", "Remote Admin"),
        ("DEV", "READ,WRITE", "Engineering files"),
        ("IPC$", "READ", "Remote IPC"),
    ]
    assert all(share.host == "10.10.11.123" for share in result.shares)
    assert all(share.source == "loot/nxc.txt" for share in result.shares)

    categories = [finding.category for finding in result.findings]
    assert categories.count("SMB banner") == 1
    assert categories.count("Administrative authentication") == 1
    assert categories.count("RID enumeration") == 2
    assert all(finding.source == "loot/nxc.txt" for finding in result.findings)


def test_ingest_handles_hash_secrets_and_headerless_share_rows() -> None:
    output = """
    SMB 192.168.56.20 445 FILE01 [*] Unix (Samba 4.17.12) (name:FILE01) (domain:WORKGROUP)
    SMB 192.168.56.20 445 FILE01 [+] FILE01\\localuser:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    SMB 192.168.56.20 445 FILE01 [*] Enumerated shares
    SMB 192.168.56.20 445 FILE01 public          READ
    SMB 192.168.56.20 445 FILE01 print$                          Printer Drivers
    """

    result = ingest_command_output(output, source="nxc")

    assert result.credentials[0].username == "localuser"
    assert result.credentials[0].domain == "FILE01"
    assert result.credentials[0].secret.endswith("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert result.credentials[0].status == "successful"
    assert [(item.name, item.permissions, item.remark) for item in result.shares] == [
        ("public", "READ", ""),
        ("print$", "", "Printer Drivers"),
    ]


def test_strip_ansi_removes_colour_and_osc_sequences() -> None:
    decorated = "\x1b]0;nxc output\x07\x1b[31mSMB\x1b[0m"

    assert strip_ansi(decorated) == "SMB"


def test_ingest_does_not_treat_arbitrary_positive_status_as_authentication() -> None:
    output = """
    [+] Download complete: /tmp/report.txt
    HTTP 10.10.11.7 returned [+] Status:200
    random text (name:NOT-A-HOST) (domain:NOT-A-DOMAIN)
    SMB 10.10.11.7 445 FILE01 [+] Status:200
    SMB 10.10.11.7 445 FILE01 [+] Enumerated:shares
    SMB 10.10.11.7 445 FILE01 [+] Result:42
    """

    result = ingest_command_output(output)

    assert result.credentials == []
    assert result.usernames == []
    assert result.hostnames == ["FILE01"]
    assert result.domains == []


def test_ingest_accepts_validated_nxc_ipv6_and_non_smb_authentication() -> None:
    output = """
    WINRM 2001:0db8:0:0::7 5985 DCV6 [*] (name:DCV6) (domain:V6.LAB)
    WINRM 2001:db8::7 5985 DCV6 [+] V6.LAB\\alice:Winter2026!
    """

    result = ingest_command_output(output)

    assert result.target_ips == ["2001:db8::7"]
    assert result.hostnames == ["DCV6"]
    assert result.domains == ["V6.LAB"]
    assert result.credentials[0].username == "alice"
    assert result.credentials[0].status == "successful"


def test_nmap_ipv6_addresses_are_canonicalized() -> None:
    hosts, services = parse_nmap_xml_text(
        """
        <nmaprun><host><address addr="2001:0db8:0:0::7" addrtype="ipv6"/>
        <ports><port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh"/></port></ports></host></nmaprun>
        """
    )

    assert hosts[0].address == "2001:db8::7"
    assert services[0].host == "2001:db8::7"
