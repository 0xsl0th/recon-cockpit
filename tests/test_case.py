from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from recon_cockpit.case import (
    CASE_SUBDIRECTORIES,
    CaseStore,
    case_dir_for_target,
    create_case,
    find_case_for_ingest,
    load_case,
    merge_ingest,
    merge_scan,
    render_notes,
    sanitize_target,
    save_case,
)
from recon_cockpit.constants import (
    MANUAL_NOTES_END,
    MANUAL_NOTES_START,
    NOTES_FILENAME,
    STATE_FILENAME,
)
from recon_cockpit.models import (
    CaseState,
    Credential,
    Finding,
    Host,
    IngestResult,
    Service,
    Share,
)


def test_create_case_builds_layout_and_is_idempotent(tmp_path: Path) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")

    assert state.target == "10.10.11.123"
    assert case_dir == tmp_path / "cases" / "10.10.11.123"
    assert (case_dir / STATE_FILENAME).is_file()
    assert (case_dir / NOTES_FILENAME).is_file()
    assert all((case_dir / child).is_dir() for child in CASE_SUBDIRECTORIES)
    assert stat.S_IMODE(case_dir.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE((case_dir / child).stat().st_mode) == 0o700
        for child in CASE_SUBDIRECTORIES
    )
    assert stat.S_IMODE((case_dir / STATE_FILENAME).stat().st_mode) == 0o600
    assert stat.S_IMODE((case_dir / NOTES_FILENAME).stat().st_mode) == 0o600

    state.findings.append(Finding("manual", "Do not discard me"))
    save_case(case_dir, state)
    state_before = (case_dir / STATE_FILENAME).read_bytes()
    notes_before = (case_dir / NOTES_FILENAME).read_bytes()

    reopened, reopened_dir = create_case("10.10.11.123", tmp_path / "cases")

    assert reopened_dir == case_dir
    assert reopened.findings == [Finding("manual", "Do not discard me")]
    assert (case_dir / STATE_FILENAME).read_bytes() == state_before
    assert (case_dir / NOTES_FILENAME).read_bytes() == notes_before


def test_sanitize_target_is_safe_and_deterministic(tmp_path: Path) -> None:
    assert sanitize_target(" 10.10.11.123 ") == "10.10.11.123"
    assert sanitize_target("Example.COM") == "example.com"
    assert sanitize_target("../../10.0.0.1") == "10.0.0.1"
    assert sanitize_target("2001:db8::7") == "2001_db8_7"
    assert case_dir_for_target("../box", tmp_path) == tmp_path / "box"
    with pytest.raises(ValueError):
        sanitize_target("../..")


def test_save_load_and_notes_cover_all_evidence(tmp_path: Path) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path)
    state.hosts = [
        Host(
            "10.10.11.123",
            hostnames=["dc01.example.test", "line\nbreak"],
            os_guess="Windows | Server",
        )
    ]
    state.services = [
        Service(
            host="10.10.11.123",
            port=445,
            name="microsoft-ds",
            product="Windows | SMB",
            version="3",
            scripts={"smb-os-discovery": "password=pa|ss\nword"},
        )
    ]
    state.findings = [Finding("SMB", "Leaked pa|ss\nword", "loot/out.txt")]
    state.domains = ["EXAMPLE.TEST"]
    state.usernames = ["alice", "bob|admin"]
    state.credentials = [
        Credential(
            username="alice",
            secret="pa|ss\nword",
            domain="EXAMPLE.TEST",
            status="successful",
            source="manual",
        )
    ]
    state.shares = [
        Share("10.10.11.123", "Engineering|Docs", "READ", "Quarterly\nfiles")
    ]
    state.next_actions = ["Review pa|ss\nword in output", "Enumerate SMB"]
    state.scan_command = ["nmap", "--script", "pa|ss\nword", "10.10.11.123"]

    save_case(case_dir, state)
    loaded = load_case(case_dir / STATE_FILENAME)
    notes = (case_dir / NOTES_FILENAME).read_text(encoding="utf-8")

    assert loaded.to_dict() == state.to_dict()
    for section in (
        "## Hosts",
        "## Ports and services",
        "## Findings",
        "## Domains and users",
        "## Credentials",
        "## Shares",
        "## Next actions",
        "## Manual notes",
    ):
        assert section in notes
    assert "Windows \\| Server" in notes
    assert "line<br>break" in notes
    assert "Engineering\\|Docs" in notes
    assert "pa\\|ss<br>word" in notes  # only the requested credentials table
    assert notes.count("pa\\|ss<br>word") == 1
    assert "[redacted]" in notes
    assert "Leaked pa|ss" not in notes


def test_save_preserves_manual_marker_content_exactly(tmp_path: Path) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path)
    notes_path = case_dir / NOTES_FILENAME
    original = notes_path.read_text(encoding="utf-8")
    manual = "\nKeep | this text.\n\n- [x] Hand-written item\n"
    edited = original.replace(
        f"{MANUAL_NOTES_START}\n\n{MANUAL_NOTES_END}",
        f"{MANUAL_NOTES_START}{manual}{MANUAL_NOTES_END}",
    )
    notes_path.write_text(edited, encoding="utf-8")

    state.findings.append(Finding("HTTP", "IIS detected", "nmap"))
    save_case(case_dir, state)
    rerendered = notes_path.read_text(encoding="utf-8")

    assert f"{MANUAL_NOTES_START}{manual}{MANUAL_NOTES_END}" in rerendered
    assert "IIS detected" in rerendered


def test_scanner_marker_injection_cannot_replace_manual_notes(tmp_path: Path) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path)
    injected = (
        f"IIS {MANUAL_NOTES_START} attacker-controlled {MANUAL_NOTES_END} Server"
    )
    state.services = [
        Service("10.10.11.123", 80, name="http", product=injected)
    ]
    state.findings = [Finding("HTTP", injected, "nmap")]
    save_case(case_dir, state)

    notes_path = case_dir / NOTES_FILENAME
    rendered = notes_path.read_text(encoding="utf-8")
    neutral_start = MANUAL_NOTES_START.replace("<", "&lt;").replace(">", "&gt;")
    neutral_end = MANUAL_NOTES_END.replace("<", "&lt;").replace(">", "&gt;")

    # Generated table cells never contain a live managed marker.
    assert rendered.count(MANUAL_NOTES_START) == 1
    assert rendered.count(MANUAL_NOTES_END) == 1
    assert rendered.count(neutral_start) == 2
    assert rendered.count(neutral_end) == 2

    manual = "\nKeep this exact manual content.\n\n- [x] analyst note\n"
    empty_manual_section = (
        f"## Manual notes\n\n{MANUAL_NOTES_START}\n\n{MANUAL_NOTES_END}"
    )
    populated_manual_section = (
        f"## Manual notes\n\n{MANUAL_NOTES_START}{manual}{MANUAL_NOTES_END}"
    )
    rendered = rendered.replace(empty_manual_section, populated_manual_section)

    # Simulate a notes file produced by an older version, where crafted nmap
    # evidence was written with live marker literals before the real section.
    legacy_notes = rendered.replace(neutral_start, MANUAL_NOTES_START).replace(
        neutral_end, MANUAL_NOTES_END
    )
    assert legacy_notes.find(MANUAL_NOTES_START) < legacy_notes.find("## Manual notes")
    notes_path.write_text(legacy_notes, encoding="utf-8")

    state.next_actions.append("Review HTTP evidence")
    save_case(case_dir, state)
    rerendered = notes_path.read_text(encoding="utf-8")

    assert f"{MANUAL_NOTES_START}{manual}{MANUAL_NOTES_END}" in rerendered
    assert "attacker-controlled" in rerendered
    assert rerendered.count(MANUAL_NOTES_START) == 1
    assert rerendered.count(MANUAL_NOTES_END) == 1


def test_render_notes_does_not_modify_state() -> None:
    state = CaseState("box", "created", "updated")
    state.credentials.append(Credential("alice", "secret"))
    before = state.to_dict()

    render_notes(state)

    assert state.to_dict() == before


def test_generated_notes_strip_terminal_controls_but_state_keeps_raw_evidence(
    tmp_path: Path,
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path)
    raw = "IIS\x1b[2J\x00 banner"
    state.findings.append(Finding("HTTP", raw, "nmap"))

    save_case(case_dir, state)
    notes = (case_dir / NOTES_FILENAME).read_text(encoding="utf-8")
    loaded = load_case(case_dir)

    assert "\x1b" not in notes
    assert "\x00" not in notes
    assert "IIS banner" in notes
    assert loaded.findings[0].detail == raw


def test_merge_scan_is_stable_and_preserves_existing_evidence() -> None:
    state = CaseState("10.0.0.8", "created", "updated")
    state.hosts = [Host("10.0.0.8", hostnames=["WEB01"])]
    state.services = [Service("10.0.0.8", 80, name="http", product="IIS")]
    state.findings = [Finding("manual", "Keep this", "manual")]
    state.credentials = [Credential("alice", "hunter2", source="manual")]

    hosts = [Host("10.0.0.8", hostnames=["web01", "web01.lab"], os_guess="Windows")]
    services = [
        Service(
            "10.0.0.8",
            80,
            name="unknown",
            version="10.0",
            scripts={"http-title": "Welcome"},
        ),
        Service("10.0.0.8", 445, name="microsoft-ds"),
    ]
    findings = [
        Finding("manual", "keep THIS", "scan"),
        Finding("HTTP", "IIS detected", "nmap"),
    ]

    merge_scan(
        state,
        hosts,
        services,
        findings=findings,
        next_actions=["Enumerate HTTP", "Enumerate HTTP"],
        scan_command=["nmap", "-sV", "10.0.0.8"],
    )
    merge_scan(state, hosts, services, findings=findings)

    assert state.hosts == [
        Host("10.0.0.8", hostnames=["WEB01", "web01.lab"], os_guess="Windows")
    ]
    assert [(item.port, item.name) for item in state.services] == [
        (80, "http"),
        (445, "microsoft-ds"),
    ]
    assert state.services[0].version == "10.0"
    assert state.services[0].scripts == {"http-title": "Welcome"}
    assert len(state.findings) == 2
    assert state.findings[0].source == "manual"
    assert state.credentials == [Credential("alice", "hunter2", source="manual")]
    assert state.next_actions == ["Enumerate HTTP"]
    assert state.scan_command == ["nmap", "-sV", "10.0.0.8"]


def test_merge_ingest_deduplicates_and_promotes_credentials() -> None:
    state = CaseState("10.0.0.8", "created", "updated")
    state.hosts = [Host("10.0.0.8", hostnames=["dc01"])]
    state.credentials = [Credential("alice", "Passw0rd!", "LAB", source="manual")]
    state.shares = [Share("10.0.0.8", "SYSVOL", "READ", source="manual")]

    result = IngestResult(
        target_ips=["10.0.0.8", "10.0.0.8"],
        hostnames=["DC01", "dc01.lab.test"],
        domains=["LAB", "lab.test"],
        usernames=["alice", "bob"],
        credentials=[
            Credential(
                "Alice",
                "Passw0rd!",
                "lab",
                status="successful (admin)",
                source="loot/nxc.txt",
            ),
            Credential("bob", "Winter2025", "LAB", source="loot/nxc.txt"),
        ],
        shares=[
            Share("10.0.0.8", "sysvol", "READ,WRITE", "Policies", "loot/nxc.txt"),
            Share("10.0.0.8", "NETLOGON", "READ", source="loot/nxc.txt"),
        ],
        findings=[
            Finding("SMB", "Signing disabled", "loot/nxc.txt"),
            Finding("smb", "SIGNING DISABLED", "another import"),
        ],
    )

    merge_ingest(state, result)
    merge_ingest(state, result)

    assert len(state.hosts) == 1
    assert state.hosts[0].hostnames == ["dc01", "dc01.lab.test"]
    assert state.domains == ["LAB", "lab.test"]
    assert state.usernames == ["alice", "bob"]
    assert len(state.credentials) == 2
    assert state.credentials[0].status == "successful (admin)"
    assert state.credentials[0].source == "manual"
    assert [(share.name, share.permissions) for share in state.shares] == [
        ("SYSVOL", "READ,WRITE"),
        ("NETLOGON", "READ"),
    ]
    assert len(state.findings) == 1


def test_find_case_for_ingest_prefers_ancestor_then_extracted_target(
    tmp_path: Path,
) -> None:
    cases_root = tmp_path / "cases"
    first, first_dir = create_case("10.10.11.123", cases_root)
    second, second_dir = create_case("10.10.11.124", cases_root)
    first.hosts.append(Host("10.10.11.123", hostnames=["dc01.lab.test"]))
    second.hosts.append(Host("10.10.11.124", hostnames=["web01.lab.test"]))
    save_case(first_dir, first)
    save_case(second_dir, second)

    nested_output = first_dir / "loot" / "nxc.txt"
    nested_output.write_text("unrelated output", encoding="utf-8")
    assert find_case_for_ingest(nested_output, "10.10.11.124", cases_root) == first_dir

    external = tmp_path / "capture.txt"
    external.write_text("SMB 10.10.11.124 445 WEB01", encoding="utf-8")
    assert find_case_for_ingest(external, "10.10.11.124", cases_root) == second_dir.resolve()
    assert find_case_for_ingest(external, cases_root=cases_root) == second_dir.resolve()
    assert find_case_for_ingest(external, ["missing", "10.10.11.124"], cases_root) == second_dir.resolve()

    ambiguous = tmp_path / "combined.txt"
    ambiguous.write_text("10.10.11.123 and 10.10.11.124", encoding="utf-8")
    assert find_case_for_ingest(ambiguous, cases_root=cases_root) is None


def test_find_case_for_ingest_returns_none_for_missing_root(tmp_path: Path) -> None:
    assert find_case_for_ingest(
        tmp_path / "some-output.txt", cases_root=tmp_path / "missing"
    ) is None


def test_find_case_for_ingest_does_not_match_an_ip_prefix(tmp_path: Path) -> None:
    cases_root = tmp_path / "cases"
    _short, short_dir = create_case("10.10.11.12", cases_root)
    _long, long_dir = create_case("10.10.11.123", cases_root)
    output = tmp_path / "nmap.txt"
    output.write_text("Nmap scan report for 10.10.11.123", encoding="utf-8")

    assert find_case_for_ingest(output, cases_root=cases_root) == long_dir.resolve()
    assert find_case_for_ingest(output, cases_root=cases_root) != short_dir.resolve()


def test_case_store_facade_and_invalid_state(tmp_path: Path) -> None:
    store = CaseStore.create("box.test", tmp_path)
    state = store.load()
    state.findings.append(Finding("note", "persisted"))
    store.save(state)
    assert store.load().findings[0].detail == "persisted"

    store.state_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        store.load()

    store.state_path.write_text(json.dumps({"target": "missing timestamps"}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid schema"):
        store.load()
