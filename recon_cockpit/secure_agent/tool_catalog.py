"""Read-only descriptions and recipes for bundled, reviewed owned profiles.

The catalog performs data transformations only. It does not inspect binaries,
read policies, restore evidence, grant authority or execute the displayed recipe.
The registry describes parameter syntax; each recipe's fixed actions describe
the narrower supported owned-lab example, not arbitrary target/tool support.
"""

from dataclasses import asdict, dataclass
from types import MappingProxyType

from . import tool_adapters as adapters


CATALOG_ID = "bundled-secure-tools-v1"
GATES = ("--owned-lab", "--isolated-audit", "--isolated-approvals",
         "--isolated-launch-admission", "--isolated-launcher",
         "--require-launch-audit", "--require-launch-approval")


@dataclass(frozen=True, slots=True)
class _Entry:
    program: str | None
    selector: str
    case: str
    policy: str
    runbook: str
    limitations: tuple[str, ...]


def _network(program, case, policy, runbook, *limitations):
    return _Entry(program, "--network-tool-assessment", case,
                  "examples/secure-agent-" + policy + "-policy.json",
                  "docs/" + runbook + ".md", limitations)


_ENTRIES = MappingProxyType({
    **{tool: _Entry(program, "--configurable-assessment", "examples/secure-agent-configurable-scope.json",
        "examples/secure-agent-configurable-policy.json", "docs/configurable-owned-lab.md",
        ("Two disconnected owned endpoint fixtures; declared addresses never attach to real internal networks.",
         "Nmap identification gates HTTP headers or public SSH host-key collection; no credentials or login."))
       for tool, program in ((adapters.CONFIGURABLE_NMAP_TOOL_ID, "nmap"),
                             (adapters.CONFIGURABLE_HEADERS_TOOL_ID, None),
                             (adapters.CONFIGURABLE_SSH_TOOL_ID, "ssh-keyscan"))},
    "tcp_connect": _Entry(None, "--workflow-assessment", "a",
        "examples/secure-agent-discovery-policy.json", "docs/workflow-assessment.md",
        ("One TCP connection establishes reachability only, not service identity.",
         "This example includes two separately authorized HTTP actions after discovery.")),
    "http_probe": _Entry(None, "--workflow-assessment", "a",
        "examples/secure-agent-discovery-policy.json", "docs/workflow-assessment.md",
        ("The example first performs TCP discovery, then two fixed HTTP GETs.",
         "Decoded fixture documents are not raw HTTP framing evidence or general vulnerability proof.")),
    adapters.NMAP_TOOL_ID: _Entry("nmap", "--nmap-assessment", "a",
        "examples/secure-agent-nmap-policy.json", "docs/tool-adapters.md",
        ("TCP-connect reachability only; no DNS, service identification, NSE scripts or raw scans.",
         "The example includes two separately authorized HTTP actions after Nmap.")),
    adapters.HTTP_HEADERS_TOOL_ID: _Entry(None, "--http-headers-assessment", "vulnerable",
        "examples/secure-agent-http-headers-policy.json", "docs/http-headers-assessment.md",
        ("The example first performs Nmap TCP discovery, then one fixed HTTP GET.",
         "Header gaps are hardening observations, not proof of exploitability; no redirects are followed.")),
    adapters.CURL_TOOL_ID: _Entry("curl", "--web-tool-assessment", "curl-ok",
        "examples/secure-agent-web-tools-policy.json", "docs/practical-web-tools.md",
        ("One fixed HTTPS GET with the synthetic fixture CA and hostname mapping.",
         "No caller URL, credentials, redirects or arbitrary certificate trust.")),
    adapters.FFUF_TOOL_ID: _Entry("ffuf", "--web-tool-assessment", "ffuf-normal",
        "examples/secure-agent-web-tools-policy.json", "docs/practical-web-tools.md",
        ("Eight compiled paths, serial requests and bounded rate; no caller dictionary or recursive crawling.",
         "Partial or wildcard-like responses cannot establish useful discovery; missing success does not prove absence.")),
    adapters.DIG_TOOL_ID: _network("dig", "dig-ok", "network-tools", "network-tools",
        "One fixed A query over TCP; no recursion, search, zone transfer or follow-up to returned addresses.",
        "An answer or NXDOMAIN describes the owned fixture response, not external DNS verification."),
    adapters.DIG_SRV_TOOL_ID: _network("dig", "dig-srv-ok", "dns-srv", "dns-srv-tools",
        "One fixed SRV query over TCP; no recursion, search, zone transfer or follow-up to advertised targets and ports.",
        "Results are untrusted service metadata. NODATA, NXDOMAIN and reported unavailability describe this response, not verified service absence."),
    adapters.RDP_TOOL_ID: _network(None, "rdp-tls", "rdp-negotiation", "rdp-negotiation-tools",
        "Repository-owned Ruby adapter sends one fixed offer, half-closes writes and reads one frame; no TLS, authentication or session.",
        "Untrusted protocol declarations only; does not verify encryption, identity, vulnerabilities or general real-server compatibility."),
    adapters.SMB2_TOOL_ID: _network(None, "smb2-21-optional", "smb2-negotiation", "smb2-negotiation-tools",
        "Repository-owned Ruby adapter sends one fixed SMB2 offer, half-closes writes and reads one frame; no authentication, session setup or share access.",
        "Untrusted dialect/signing/capability metadata only; opaque peer bytes remain uninterpreted in private raw evidence. Real-server compatibility and signing enforcement are not established."),
    adapters.OPENSSL_TOOL_ID: _network("openssl", "openssl-ok", "network-tools", "network-tools",
        "One TLS handshake with a fixed synthetic CA and hostname; no HTTP or client credentials.",
        "Negotiated protocol and cipher are observations, not a general TLS vulnerability assessment."),
    adapters.POSTGRESQL_TLS_TOOL_ID: _network("openssl", "postgresql-tls-ok", "database-tls", "database-tls-tools",
        "Fixed PostgreSQL SSLRequest then one verified TLS handshake; no startup/login message, SQL or plaintext downgrade.",
        "The selected wire profile and fixture CA/name verification do not establish database version, readiness or authenticated access."),
    adapters.MYSQL_TLS_TOOL_ID: _network("openssl", "mysql-tls-ok", "database-tls", "database-tls-tools",
        "Fixed public greeting/SSLRequest then one verified TLS handshake; no login, SQL, plugins or plaintext downgrade.",
        "A fragmented greeting may fail closed; advertised version and nonce are discarded. This is pre-auth TLS metadata only."),
    adapters.SMTP_TLS_TOOL_ID: _network("openssl", "smtp-tls-ok", "smtp-starttls", "smtp-starttls-tools",
        "Fixed EHLO/STARTTLS then fixture-CA/name-verified TLS and owner-witnessed clean close; no AUTH, mail, recipients or client credentials.",
        "OpenSSL attempts STARTTLS without advertisement and does not validate the ready reply; only TLS handshake facts are verified. Fragmented ready replies may be inconclusive; the complete SMTP dialogue is not retained."),
    adapters.LDAP_TLS_TOOL_ID: _network("openssl", "ldap-tls-ok", "ldap-starttls", "ldap-starttls-tools",
        "One fixed LDAP StartTLS request then fixture-CA/name-verified TLS and owner-witnessed clean close; no bind, search, referrals or client credentials.",
        "TLS facts only: OpenSSL does not match the response message ID or validate the complete LDAP response, which is not retained. Fragmented responses may be inconclusive; no LDAP identity or authenticated session is established."),
    adapters.FTP_TLS_TOOL_ID: _network("openssl", "ftp-tls-ok", "ftp-starttls", "ftp-starttls-tools",
        "One fixed FTP AUTH TLS request then fixture-CA/name-verified TLS and owner-witnessed clean close; no login, credentials, listing, transfer or data connection.",
        "TLS facts only: the native client does not validate FTP reply codes and discards the AUTH reply and earlier greeting lines. Fragmented readiness may fail; no FTP identity, readiness or authenticated session is established."),
    adapters.WHATWEB_TOOL_ID: _network("whatweb", "whatweb-ok", "whatweb", "whatweb-tools",
        "One fixed HTTP GET with five passive plugins and pinned Ruby runtime; no retries, redirects, crawling or credentials.",
        "Results are untrusted application hints; an empty hint set does not prove absence. No product identity or vulnerability is established."),
    adapters.SSH_TOOL_ID: _network("ssh-keyscan", "ssh-ok", "ssh-ldap", "ssh-ldap-tools",
        "One fixed RSA host-key collection; no login, credentials or authentication.",
        "A key and fingerprint do not establish host identity or trust."),
    adapters.LDAP_TOOL_ID: _network("ldapsearch", "ldap-ok", "ssh-ldap", "ssh-ldap-tools",
        "Anonymous base-scope RootDSE with fixed attributes; no user enumeration or credential search.",
        "Referrals and returned directory names never authorize follow-up queries."),
    adapters.SMB_TOOL_ID: _network("smbclient", "smb-ok", "smb", "smb-tools",
        "Anonymous bounded share metadata only; no share traversal, file reads, writes or remote execution.",
        "Native empty, denied and malformed reply ambiguity remains inconclusive, not verified absence."),
    adapters.RPCINFO_TOOL_ID: _network("rpcinfo", "rpc-ok", "rpc-nfs", "rpc-nfs-tools",
        "Fixed TCP RPC registration listing; advertised ports remain metadata with no follow-up.",
        "No RPC service operations beyond the reviewed registration query."),
    adapters.SHOWMOUNT_TOOL_ID: _network("showmount", "nfs-ok", "rpc-nfs", "rpc-nfs-tools",
        "Bounded export metadata at the predeclared endpoint; no mounting or export file access.",
        "Returned ports, paths and groups never authorize follow-up actions."),
    adapters.FTP_TOOL_ID: _network("curl", "ftp-ok", "ftp-smtp", "ftp-smtp-tools",
        "Fixed anonymous NLST; control and data connections stay on the same predeclared endpoint.",
        "Names only, including a validated empty result; no file transfer or credential use."),
    adapters.SMTP_TOOL_ID: _network("curl", "smtp-ok", "ftp-smtp", "ftp-smtp-tools",
        "Bounded banner, EHLO and QUIT; no mail submission, authentication or recipient probing.",
        "Advertised capabilities are not evidence that authentication or another mail operation works."),
    adapters.DOCKER_PING_TOOL_ID: _network("curl", "docker-ping-ok", "docker-winrm", "docker-winrm-tools",
        "One fixed GET /_ping; no Docker socket, container lifecycle, filesystem or command operations.",
        "The health response does not verify daemon identity; version metadata is a separate capability."),
    adapters.DOCKER_VERSION_TOOL_ID: _network("curl", "docker-version-ok", "docker-winrm", "docker-winrm-tools",
        "One fixed GET /version; no Docker socket, container lifecycle, filesystem or command operations.",
        "Bounded advertised metadata or a complete empty object does not verify daemon identity."),
    adapters.WINRM_TOOL_ID: _network("curl", "winrm-ok", "docker-winrm", "docker-winrm-tools",
        "One unauthenticated GET /wsman; no POST, SOAP, login or shell operations.",
        "Status and advertised authentication schemes do not establish WinRM identity or working authentication."),
    adapters.NMAP_SERVICE_TOOL_ID: _network("nmap", "nmap-service-http", "nmap-service", "nmap-service-tools",
        "One port with compiled NULL and HTTP GET probes; pinned no-op NSE entrypoint, no scripts or authentication.",
        "Unidentified means no match from these finite probes, not no service; product/version values are tool observations."),
    adapters.REDIS_TOOL_ID: _network("redis-cli", "redis-ok", "redis-snmp", "redis-snmp-tools",
        "One fixed RESP2 INFO server against an owned fixture; no authentication, key reads, writes or cluster redirects.",
        "Version, mode, architecture and advertised port are untrusted service metadata; they neither verify a vulnerability nor authorize follow-up."),
    adapters.SNMP_TOOL_ID: _network("snmpget", "snmp-ok", "redis-snmp", "redis-snmp-tools",
        "One SNMPv2c GET for three fixed numeric system OIDs over TCP with a public synthetic fixture community.",
        "No UDP, MIB/config imports, user-supplied community, walks, writes or retries; complete typed noSuchObject replies differ from missing evidence.",
        "System values are untrusted service reports, not authenticated device identity or authorization for follow-up."),
    adapters.KERBRUTE_TOOL_ID: _network("kerbrute", "kerberos-ok", "kerberos", "kerberos-tools",
        "Two compiled synthetic names against an owned error-only KDC; no passwords, spraying or tickets.",
        "Exists/unknown is tool_report_only, with authentication_verified=false; principal existence and absence are unverified, and error text can spoof an unknown report.",
        "The profile is not safe-for-general-KDC authorization: upstream AS-REP handling lies outside the owned error-only fixture."),
})


def _common():
    return {"schema_version": "1", "catalog_id": CATALOG_ID,
            "read_only": True, "live_calls_enabled": False,
            "runtime_availability": "not_checked",
            "notice": "Descriptions and recipes grant no authority and claim no execution or runtime availability."}


def _entry(tool_id):
    if type(tool_id) is not str or tool_id not in _ENTRIES:
        raise ValueError("unknown_catalog_tool")
    if set(_ENTRIES) != set(adapters.ADAPTERS):
        raise ValueError("catalog_registry_mismatch")
    return _ENTRIES[tool_id]


def _summary(tool_id, entry):
    adapter = adapters.ADAPTERS[tool_id]
    return {"tool_id": tool_id, "effect": adapter.effect,
            "implementation": "native" if entry.program is None else "external_program",
            "external_program": entry.program, "execution_profile": adapter.execution_profile,
            "parser_version": adapter.parser_version}


def list_tools():
    """List reviewed capabilities, without claiming their prerequisites exist."""
    tools = [_summary(tool_id, _entry(tool_id)) for tool_id in sorted(adapters.ADAPTERS)]
    return {**_common(), "capability_count": len(tools),
            "external_program_count": len({row["external_program"] for row in tools
                                           if row["external_program"] is not None}),
            "tools": tools}


def _recipe_actions(entry):
    """Reuse pure accepted action constructors, never executor/runtime modules."""
    if entry.selector == "--configurable-assessment":
        from . import configurable_contract as contract
        # Reviewed example data only: catalog commands never read scope files.
        scope = {"schema_version": "1", "scope_id": "owned-http-ssh-primary",
                 "http": {"target": "10.77.0.10", "port": 8080, "path": "/harbordesk/portal.html"},
                 "ssh": {"target": "10.77.0.20", "port": 2222}}
        return contract.WORKFLOW, dict(contract.LIMITS), [contract.action(scope, step) for step in range(1, 5)]
    if entry.selector == "--workflow-assessment":
        from .discovery_contract import discovery_action
        from .owned_lab_contract import capability_descriptor
        from .session_limits import SessionLimits

        actions = [discovery_action(entry.case, step) for step in (1, 2, 3)]
        return capability_descriptor()["workflow_id"], asdict(SessionLimits()), actions
    if entry.selector == "--nmap-assessment":
        from . import nmap_contract as contract
        steps = (1, 2, 3)
    elif entry.selector == "--http-headers-assessment":
        from . import http_headers_contract as contract
        steps = (1, 2)
    elif entry.selector == "--web-tool-assessment":
        from . import web_tools_contract as contract
        steps = (1,)
    elif entry.selector == "--network-tool-assessment":
        from . import network_tools_contract as contract
        steps = (1,)
    else:
        raise ValueError("invalid_catalog_recipe")
    return contract.WORKFLOW, dict(contract.LIMITS), [contract.action(entry.case, step) for step in steps]


def describe_tool(tool_id: str):
    """Describe one fixed example and every action its existing selector uses."""
    entry = _entry(tool_id)
    workflow_id, limits, raw_actions = _recipe_actions(entry)
    actions = [{"step": step, "tool_id": action["tool_id"], "target": action["target"],
                "parameters": dict(action["parameters"])}
               for step, action in enumerate(raw_actions, start=1)]
    selected = [action for action in actions if action["tool_id"] == tool_id]
    if not selected:
        raise ValueError("catalog_recipe_tool_mismatch")
    parameters = [dict(action["parameters"]) for action in selected]
    recipe = ["python", "-m", "recon_cockpit.secure_agent", entry.selector, entry.case,
              "--dry-run", "--policy", entry.policy, *GATES,
              "--audit", ".secure-agent/<NEW-AUDIT>.jsonl",
              "--assessment-dir", ".secure-agent/<NEW-ASSESSMENT>"]
    return {**_common(), **_summary(tool_id, entry),
            "adapter": adapters.ADAPTERS[tool_id].to_dict(),
            "parameter_schema_role": "syntax_only; fixed_parameters describes this owned example",
            "owned_scope": {"target": selected[0]["target"], "port": parameters[0]["port"],
                            "owned_lab_only": True},
            "fixed_parameters": parameters,
            "run": {"selector": entry.selector, "case": entry.case,
                    "policy": entry.policy, "runbook": entry.runbook,
                    "workflow_id": workflow_id, "action_count": len(actions),
                    "tool_ids": list(dict.fromkeys(action["tool_id"] for action in actions)),
                    "actions": actions, "session_limits": limits, "dry_run_argv": recipe,
                    "execution_note": "The listed sequence is conditional on predecessor evidence and fresh authority checks for each action. Dry-run records proposals only; later actions may remain unproposed without execution evidence.",
                    "recipe_note": "This catalog does not run the argv. Replace both NEW path placeholders with fresh private paths under an existing private parent. Running the recipe writes dry-run audit/evidence and needs the documented Linux isolation prerequisites."},
            "limitations": ["This example uses a disconnected owned namespace, not the host loopback or an external engagement.",
                            "No model credentials, paid calls or live-model evaluation are enabled.",
                            *entry.limitations]}
