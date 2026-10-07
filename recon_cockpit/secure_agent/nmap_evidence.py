"""Private, independently replayable evidence for the new Nmap workflow.

The legacy assessment contracts remain unchanged. Raw bounded XML and stderr
are retained privately; only validated enums and references enter the report.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from uuid import uuid4

from . import nmap_contract as contract, nmap_workflow as workflow
from .audit import AuditSink
from .evidence import (
    EvidenceStore, EvidenceUnavailable, MAX_JOURNAL_BYTES, MAX_REPORT_BYTES,
    _digest, _now, _observation_digest, _read_private, _result_metadata, _safe_action,
    _uuid, _workflow_observation,
)
from .models import load_json, parse_action
from .nmap_parser import PARSER_VERSION
from . import nmap_runtime


MAX_ARTIFACT_BYTES = 65_536
REPRESENTATION = "bounded-nmap-raw-and-http-result-json-v1"
HEADERS_REPRESENTATION = "bounded-nmap-raw-and-http-wire-json-v1"
STATUSES = {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled"}
_CHECKS = {"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
           "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
           "raw_sockets_blocked", "landlock_applied", "python_unreadable"}
_RECORD_FIELDS = {"execution_id", "session_step", "action", "action_digest", "policy_digest",
                  "backend", "started_at", "finished_at", "execution_status", "observation_id",
                  "observation", "artifact", "authority_observation_sha256", "result_metadata"}


def _profile(name):
    """Select only repository-reviewed contracts; never import a caller path."""
    if name == "nmap":
        return contract, workflow
    if name == "web":
        from . import web_assessment_contract, web_workflow

        return web_assessment_contract, web_workflow
    if name == "http_headers":
        from . import http_headers_contract, http_headers_workflow

        return http_headers_contract, http_headers_workflow
    if name == "web_tools":
        from . import web_tools_contract, web_tools_workflow
        return web_tools_contract, web_tools_workflow
    if name == "network_tools":
        from . import network_tools_contract, network_tools_workflow
        return network_tools_contract, network_tools_workflow
    if name == "service_web":
        from . import service_web_contract, service_web_workflow
        return service_web_contract, service_web_workflow
    raise ValueError("unsupported_evidence_workflow_profile")


def _manifest_profile(manifest):
    if type(manifest) is not dict:
        raise ValueError("invalid_evidence_manifest")
    if "planning_origin" in manifest and (manifest.get("workflow") != "owned-web-assessment-v1"
            or manifest["planning_origin"] not in ("model_owned", "model_live")):
        raise ValueError("invalid_evidence_planning_origin")
    if manifest.get("workflow") == contract.WORKFLOW:
        return _profile("nmap")
    if manifest.get("workflow") == "owned-web-assessment-v1":
        return _profile("web")
    if manifest.get("workflow") == "owned-http-headers-assessment-v1":
        return _profile("http_headers")
    if manifest.get("workflow") == "owned-web-tool-assessment-v1":
        return _profile("web_tools")
    if manifest.get("workflow") == "owned-network-tool-assessment-v1":
        return _profile("network_tools")
    if manifest.get("workflow") == "owned-service-web-assessment-v1":
        from .service_web_evidence import validate_runtime_bindings
        validate_runtime_bindings(manifest.get("runtime_bindings"), manifest.get("runtime_sha256"))
        return _profile("service_web")
    raise ValueError("unsupported_evidence_workflow")


def _representation(workflow_id):
    if workflow_id == "owned-service-web-assessment-v1":
        return "bounded-service-web-tool-output-and-http-wire-json-v1"
    if workflow_id == "owned-network-tool-assessment-v1":
        return "bounded-network-tool-output-json-v1"
    if workflow_id == "owned-web-tool-assessment-v1":
        return "bounded-web-tool-output-json-v1"
    return (HEADERS_REPRESENTATION if workflow_id == "owned-http-headers-assessment-v1"
            else REPRESENTATION)


def _validated_result(record, result, manifest, previous, *, deadline=None):
    """Recompute observations from retained bytes, including on read-only replay."""
    contract, _ = _manifest_profile(manifest)
    status = record["execution_status"]
    if type(result) is not dict or result.get("status") != status:
        raise ValueError("invalid_nmap_result_status")
    context = contract.validate_result_context(
        result, manifest["owned_lab"], previous=previous,
        tool_id=record["action"]["tool_id"], execution_status=status,
    )
    if contract.WORKFLOW == "owned-service-web-assessment-v1":
        from .service_web_evidence import replay_result
        replay_result(record, result, manifest, deadline=deadline)
    elif contract.WORKFLOW == "owned-network-tool-assessment-v1":
        if not _digest(manifest["runtime_sha256"]):
            raise ValueError("network_tool_runtime_commitment_missing")
        tool_id = record["action"]["tool_id"]
        stdout, stderr = contract.validate_tool_result(result, tool_id=tool_id,
            execution_status=status, runtime_sha256=manifest["runtime_sha256"])
        if status == "succeeded":
            from .network_tools_parser_runtime import parse_isolated_tool
            try:
                parsed = parse_isolated_tool(tool_id, stdout, stderr, deadline=deadline)
            except ValueError:
                parsed = None
            if contract.encode(parsed) != contract.encode(result["tool_observation"]):
                raise ValueError("network_tool_parsed_result_mismatch")
    elif contract.WORKFLOW == "owned-web-tool-assessment-v1":
        # None is valid for a dry-run manifest, but any execution receipt must
        # bind to the runtime committed before execution, including failures.
        if not _digest(manifest["runtime_sha256"]):
            raise ValueError("web_tool_runtime_commitment_missing")
        tool_id = record["action"]["tool_id"]
        raw, _ = contract.validate_tool_result(result, tool_id=tool_id,
            execution_status=status, runtime_sha256=manifest["runtime_sha256"])
        if status == "succeeded":
            from .web_tools_parser_runtime import parse_isolated_tool
            try:
                parsed = parse_isolated_tool(tool_id, raw, deadline=deadline)
            except ValueError:
                parsed = None
            if contract.encode(parsed) != contract.encode(result["tool_observation"]):
                raise ValueError("web_tool_parsed_result_mismatch")
    elif record["action"]["tool_id"] == contract.TOOL_ID:
        if set(result) != {"status", "results", "bytes_received", "truncated", "boundary_checks",
                           "raw_xml_base64", "raw_stderr_base64", "provenance", "backend", "owned_lab"}:
            raise ValueError("invalid_nmap_result_fields")
        decoded = []
        for field in ("raw_xml_base64", "raw_stderr_base64"):
            value = result[field]
            if type(value) is not str or len(value) > 21848:
                raise ValueError("invalid_nmap_raw_artifact")
            raw = base64.b64decode(value, validate=True)
            if base64.b64encode(raw).decode("ascii") != value:
                raise ValueError("invalid_nmap_raw_artifact")
            decoded.append(raw)
        xml, stderr = decoded
        if (len(xml) + len(stderr) > 16384 or type(result["bytes_received"]) is not int
                or result["bytes_received"] != len(xml) + len(stderr)
                or type(result["truncated"]) is not bool):
            raise ValueError("invalid_nmap_capture_bounds")
        checks, provenance = result["boundary_checks"], result["provenance"]
        if (type(checks) is not dict or set(checks) != _CHECKS
                or any(value is not True for value in checks.values())
                or type(provenance) is not dict or set(provenance) != {
                    "runtime_sha256", "runtime_manifest", "xml_sha256", "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
                or not _digest(provenance["runtime_sha256"])
                or provenance["runtime_sha256"] != manifest["runtime_sha256"]
                or nmap_runtime.manifest_digest(provenance["runtime_manifest"]) != provenance["runtime_sha256"]
                or provenance["xml_sha256"] != hashlib.sha256(xml).hexdigest()
                or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
                or provenance["parser_version"] != PARSER_VERSION
                or type(provenance["exit_code"]) is not int
                or not -255 <= provenance["exit_code"] <= 255
                or provenance["stop_reason"] not in {None, "timeout", "output_limit", "invalid_xml"}):
            raise ValueError("invalid_nmap_provenance")
        if result["truncated"] != (provenance["stop_reason"] == "output_limit"):
            raise ValueError("inconsistent_nmap_truncation")
        if status == "succeeded":
            if provenance["exit_code"] != 0 or provenance["stop_reason"] is not None:
                raise ValueError("incomplete_nmap_execution")
            if contract.encode(nmap_runtime.parse_isolated_xml(xml, deadline=deadline)) != contract.encode(result["results"]):
                raise ValueError("nmap_parsed_result_mismatch")
        elif result["results"] != []:
            raise ValueError("failed_nmap_has_findings")
    elif contract.WORKFLOW == "owned-http-headers-assessment-v1":
        # First check only closed metadata/bounds. Raw HTTP parsing stays in the
        # separate networkless worker both at capture and read-only inspection.
        raw = contract.validate_http_result(result, execution_status=status)
        if status == "succeeded" and not result["truncated"]:
            from .http_headers_parser_runtime import parse_isolated_headers

            try:
                parsed = parse_isolated_headers(raw, deadline=deadline)
            except ValueError:
                parsed = None  # Unsupported HTTP stays inconclusive.
            if contract.encode(parsed) != contract.encode(result["http_headers"]):
                raise ValueError("http_headers_parsed_result_mismatch")
    observation = contract.parse_observation(record["action"], result, execution_status=status)
    return context, observation


def _summary(value, manifest, records, decisions):
    contract, _ = _manifest_profile(manifest)
    keys = {"session_id", "session_status", "stop_reason", "steps_attempted",
            "actions_succeeded", "output_reserved_bytes", "mode"}
    result = {key: value[key] for key in keys}
    if (result["session_id"] != manifest["session_id"]
            or result["session_status"] not in {"completed", "stopped"}
            or result["mode"] not in {"execute", "dry_run"}
            or type(result["stop_reason"]) is not str
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", result["stop_reason"])):
        raise ValueError("invalid_nmap_summary")
    for field, maximum in (("steps_attempted", contract.LIMITS["max_steps"]),
                            ("actions_succeeded", contract.LIMITS["max_steps"]),
                            ("output_reserved_bytes", contract.LIMITS["max_output_bytes"])):
        if type(result[field]) is not int or not 0 <= result[field] <= maximum:
            raise ValueError("invalid_nmap_summary")
    if (result["steps_attempted"] < max(len(records), len(decisions))
            or result["actions_succeeded"] != sum(row["execution_status"] == "succeeded" for row in records)
            or result["output_reserved_bytes"] < sum(row["action"]["parameters"]["max_output_bytes"] for row in records)
            or (result["mode"] == "dry_run" and records)):
        raise ValueError("inconsistent_nmap_summary")
    return result


def _report(manifest, records, decisions, summary, terminal, closure, issues):
    contract, _ = _manifest_profile(manifest)
    issues = sorted(set(issues))
    reason = "assessment_incomplete" if terminal is None else terminal["reason"]
    outcome = {"seeded_diagnostic_metadata_exposed": "validated",
               "diagnostic_endpoint_not_found": "not_demonstrated",
               "http_hardening_gaps_observed": "gaps_observed",
               "http_hardening_headers_present": "reviewed_headers_present",
               "https_response_observed": "response_observed",
               "dns_answer_observed": "answer_observed",
               "dns_name_not_found": "name_not_found",
               "dns_no_answer_observed": "no_answer_observed",
               "dns_srv_observed": "dns_srv_observed",
               "dns_srv_no_data": "dns_srv_no_data",
               "dns_srv_name_not_found": "dns_srv_name_not_found",
               "dns_srv_service_unavailable": "dns_srv_service_unavailable",
               "rdp_protocol_selected": "rdp_protocol_selected",
               "rdp_legacy_confirmation": "rdp_legacy_confirmation",
               "rdp_negotiation_failure": "rdp_negotiation_failure",
               "smb2_dialect_selected": "smb2_dialect_selected",
               "smb2_negotiation_refused": "smb2_negotiation_refused",
               "tls_handshake_verified": "handshake_verified",
               "database_tls_verified": "database_tls_verified",
               "http_fingerprint_observed": "http_fingerprint_observed",
               "http_fingerprint_no_hints": "http_fingerprint_no_hints",
               "ssh_host_key_observed": "host_key_observed",
               "ldap_rootdse_observed": "rootdse_observed",
               "ldap_empty_rootdse_observed": "empty_rootdse_observed",
               "smb_shares_observed": "shares_observed",
               "rpc_registrations_observed": "rpc_registrations_observed",
               "rpc_empty_registrations_observed": "rpc_empty_registrations_observed",
               "nfs_exports_observed": "nfs_exports_observed",
               "nfs_empty_exports_observed": "nfs_empty_exports_observed",
               "ftp_names_observed": "ftp_names_observed",
               "ftp_empty_listing_observed": "ftp_empty_listing_observed",
               "smtp_capabilities_observed": "smtp_capabilities_observed",
               "smtp_no_extensions_observed": "smtp_no_extensions_observed",
               "kerberos_principal_reports_observed": "kerberos_principal_reports_observed",
               "redis_server_info_observed": "redis_server_info_observed",
               "snmp_system_metadata_observed": "snmp_system_metadata_observed",
               "nmap_service_identified": "nmap_service_identified",
               "nmap_service_unidentified": "nmap_service_unidentified",
               "docker_ping_observed": "docker_ping_observed",
               "docker_version_metadata_observed": "docker_version_metadata_observed",
               "docker_no_version_metadata_observed": "docker_no_version_metadata_observed",
               "winrm_auth_schemes_observed": "winrm_auth_schemes_observed",
               "winrm_no_auth_schemes_observed": "winrm_no_auth_schemes_observed",
               "content_paths_observed": "paths_observed",
               "no_successful_content_paths_observed": "no_successful_paths_observed"}.get(reason, "inconclusive")
    if issues:
        outcome, reason = "inconclusive", "evidence_integrity_incomplete"
    report = {
        "schema_version": "1", "assessment_id": manifest["assessment_id"],
        "session_id": manifest["session_id"], "workflow": contract.WORKFLOW,
        "fixture_case": manifest["fixture_case"], "workflow_card": manifest["workflow_card"],
        "outcome": outcome, "reason": reason, "live_calls_enabled": False,
        "planning": "deterministic offline workflow with evidence-gated proposals",
        "capability": (contract.capability_descriptor(manifest["fixture_case"])
                       if contract.WORKFLOW == "owned-network-tool-assessment-v1"
                       else contract.capability_descriptor()),
        "runtime_sha256": manifest["runtime_sha256"],
        "records": copy.deepcopy(records), "decisions": copy.deepcopy(decisions),
        "terminal_decision": copy.deepcopy(terminal), "summary": copy.deepcopy(summary),
        "owned_lab": {"identity": manifest["owned_lab"], "closure": copy.deepcopy(closure)},
        "integrity_issues": issues,
        "finding": {"title": "Seeded diagnostic metadata available without authentication",
                    "evidence": [{"execution_id": row["execution_id"], "observation_id": row["observation_id"],
                                  "artifact": row["artifact"]} for row in records if row["artifact"]]},
        "limitations": [
            "The workflow uses deterministic proposals and an owned seeded fixture; no real-model or professional engagement evaluation is claimed.",
            "An open TCP port establishes reachability only; service identity and findings require separate HTTP evidence.",
            "Private raw XML and stderr are untrusted tool output. Hashes support local reconciliation, not external authenticity.",
            "Lab counters are last acknowledged totals; connection counts are lower bounds and cannot identify every attempt.",
            "No execution or authority is resumed by inspecting these files.",
        ],
    }
    if contract.WORKFLOW == "owned-web-assessment-v1":
        report["finding"]["title"] = "Synthetic HarborDesk diagnostic metadata available without authentication"
        report["limitations"].extend([
            "The injected variant retains hostile operator_note text as untrusted evidence; deterministic planning ignores it.",
            "No model susceptibility, induced out-of-scope proposal, or paired adversarial comparison is demonstrated by this workflow.",
            "HTTP observations use bounded decoded responses; they do not establish complete HTTP framing integrity or authenticate server content.",
        ])
    elif contract.WORKFLOW in ("owned-http-headers-assessment-v1", "owned-service-web-assessment-v1"):
        report["finding"]["title"] = "Observed HTTP response hardening headers"
        report["finding"]["headers"] = next((copy.deepcopy(row["observation"]["headers"])
            for row in reversed(records) if type(row.get("observation")) is dict
            and row["observation"].get("kind") == "http_headers"), None) if not issues else None
        report["limitations"].extend([
            "Header presence or absence is a configuration observation, not evidence of an exploitable XSS or clickjacking vulnerability.",
            "CSP is checked for presence only, not policy strength. Framing controls can overlap; a missing X-Frame-Options header alone proves no vulnerability.",
            "The strict HTTP/1.x subset requires complete bounded Content-Length framing. Unsupported encodings, ambiguous headers and incomplete responses are inconclusive.",
            "Raw HTTP is independently parsed in a networkless worker on capture and replay. This checks local consistency, not server authenticity.",
            "The injected header/body remains untrusted data; deterministic planning makes no model susceptibility or adversarial blocking-rate claim.",
            "The fixture uses plaintext HTTP. TLS, HSTS effectiveness, authentication, redirects and browser behavior are not evaluated.",
        ])
    if contract.WORKFLOW == "owned-web-tool-assessment-v1":
        report["planning"] = "one deterministic offline tool action; no cross-tool planning"
        report["finding"]["title"] = "Bounded owned web-tool observation"
        report["finding"]["tool_observation"] = (copy.deepcopy(records[0]["observation"])
            if not issues and len(records) == 1 else None)
        report["limitations"] = [
            "This trial runs one real executable against a disconnected synthetic owned fixture; it is not professional engagement or real-model validation.",
            "curl verifies the fixed fixture hostname and CA. It does not assess general TLS configuration, certificate inventories or browsers.",
            "ffuf checks only eight pinned paths. A non-404 control response is inconclusive; a differing status does not establish a vulnerability or defeat every soft-404 pattern.",
            "Tool output is independently parsed in a networkless worker on capture and replay; retained hashes establish local consistency, not external authenticity.",
            "Injected response text is untrusted data; this deterministic single-action trial does not measure model susceptibility.",
            "Request counters are last acknowledged totals and connections are lower bounds. Inspection never resumes execution or restores authority.",
        ]
    if contract.WORKFLOW == "owned-network-tool-assessment-v1":
        report["planning"] = "one deterministic offline tool action; no cross-tool planning"
        report["finding"]["title"] = "Bounded owned network-tool observation"
        report["finding"]["tool_observation"] = (copy.deepcopy(records[0]["observation"])
            if not issues and len(records) == 1 else None)
        report["limitations"] = [
            "This single executable trial uses a disconnected synthetic fixture; it is not professional engagement or real-model validation.",
            "DNS queries use one fixed name, record type and TCP server. No recursive lookup, search, zone transfer or address follow-up is authorized.",
            "TLS records one verified handshake against a fixed fixture hostname and CA; it is not a general certificate inventory or protocol/cipher weakness scan.",
            "Both output channels are bounded and independently parsed without network on capture and replay. Hashes reconcile local evidence, not external authenticity.",
            "Normalized observations cannot select a new target or tool. No model susceptibility or comparative performance claim is made.",
            "Protocol counters are last acknowledged totals and connections are lower bounds. Inspection never resumes execution or restores authority.",
        ]
        if manifest["fixture_case"].startswith(("ssh-", "ldap-")):
            report["limitations"] = [
                "This single executable trial uses a disconnected synthetic fixture; it is not professional engagement or real-model validation.",
                "SSH collects one RSA host key and computes its SHA256 fingerprint. The key is untrusted; collection does not establish server identity, login or SSH session support.",
                "LDAP uses one anonymous base-scope RootDSE search with fixed attributes; it does not authenticate, enumerate accounts or follow referrals.",
                "Both output channels are bounded and independently parsed without network on capture and replay. Hashes reconcile local evidence, not external authenticity.",
                "Normalized observations cannot select a new target or tool. No model susceptibility or comparative performance claim is made.",
                "Protocol counters count completed SSH key replies or validated LDAP RootDSE searches, not authenticated sessions. Connections are lower bounds; inspection never restores authority.",
            ]
        if manifest["fixture_case"].startswith("smb-"):
            report["limitations"] = [
                "This single executable trial uses a disconnected synthetic fixture; it is not professional engagement or real-model validation.",
                "SMB collects a finite anonymous share list through the fixed IPC metadata endpoint. Share names do not establish file access or authorize traversal, transfers, writes or remote execution.",
                "The fixture implements only the reviewed anonymous SMB protocol exchange; no real account, credential testing, domain discovery or external target is involved.",
                "Both output channels are bounded and independently parsed without network on capture and replay. Share comments remain untrusted raw evidence and are excluded from normalized findings.",
                "The native client can emit identical output for empty, denied or malformed listings; these remain inconclusive. Normalized results cannot select another target, share or tool.",
                "Counters record validated share-enumeration requests; connections are acknowledged lower bounds. Hashes reconcile local evidence, and inspection never restores authority.",
            ]
        if manifest["fixture_case"].startswith(("rpc-", "nfs-")):
            report["limitations"] = [
                "This single executable trial uses a disconnected synthetic RPC/NFS fixture; it is not professional engagement or real-model validation.",
                "RPC registrations and NFS exports are metadata only. Advertised endpoints, paths and access groups never grant permission to connect, mount, traverse or read files.",
                "The fixed TCP endpoint and transport configuration are authorized before execution. Native service discovery cannot expand that network scope.",
                "Both raw output channels are bounded and independently reparsed without network. Unsupported formats, malformed or partial results remain inconclusive.",
                "The owned fixture supports only reviewed registration discovery and export metadata operations; it is not a general rpcbind, MOUNT or NFS filesystem service.",
                "Request counters count validated registration dumps or export queries; bounded discovery exchanges are excluded. Connections are acknowledged lower bounds. Inspection never restores authority.",
            ]
        if manifest["fixture_case"].startswith(("ftp-", "smtp-")):
            report["limitations"] = [
                "This single executable trial uses a disconnected synthetic FTP/SMTP fixture; it is not professional engagement or real-model validation.",
                "FTP lists only fixed synthetic root names with a public anonymous identity. Names and passive advertisements never authorize transfers, traversal or new network endpoints.",
                "SMTP records advertised capabilities from a fixed greeting and EHLO query, then quits. No authentication, mail, recipient or account probing is authorized.",
                "Both bounded raw channels are independently reparsed without network. Complete native success framing is required; process exit alone does not establish useful or empty results.",
                "The service has no filesystem or mail backend. Unsupported names, extensions or diagnostic formats remain inconclusive; normalized observations cannot select follow-up work.",
                "Counters record validated NLST or EHLO queries. Accepted connections are acknowledged lower bounds; read-only inspection never restores authority.",
            ]
        if manifest["fixture_case"].startswith("smb2-"):
            report["limitations"] = [
                "This one-action SMB2 negotiation trial uses a disconnected synthetic owned fixture, not a professional engagement or live-model evaluation.",
                "One fixed SMB2 NEGOTIATE request offers SMB 2.1 and 3.0.2 with client capabilities zero. Only the first bounded Direct TCP frame is collected before closing the connection.",
                "Dialect, signing mode, capability bits and refusal status are untrusted peer reports. Signing, encryption, authentication policy, service identity and vulnerabilities are not verified.",
                "Capability bits depend on the fixed client offer; absent bits do not establish that the server lacks a capability. This trial does not offer SMB 3.1.1 or negotiate contexts.",
                "Selected offered dialects and three known refusal statuses are completed metadata observations. Malformed, incomplete, oversized, unsupported or unoffered responses remain inconclusive.",
                "No SESSION_SETUP, credentials, login, NTLM challenge collection, share access, SMB1 fallback, retry or follow-up is authorized. The opaque peer security buffer is never decoded or used for authentication.",
                "Raw negotiation bytes include opaque peer security or error data. Supported metadata allows at most 256 bytes of opaque data; only its length is released for successful negotiation. The total first-frame capture is at most 4100 bytes, so rejected frames can retain larger opaque data within that raw bound; arbitrary server compatibility is not established.",
                "Trailing peer data is not retained. Its absence from evidence is not injection detection or proof that no trailing data was sent. The 256-byte opaque-buffer limit intentionally excludes larger responses.",
                "Counters record the exact fixed request and a client write-half-close witnessed before the fixture response. This owned-profile constraint prevents further client bytes; compatibility with arbitrary real SMB servers is not established.",
                "Retained bytes are independently reparsed without network; read-only inspection restores no approval or authority. No real-model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith("rdp-"):
            report["limitations"] = [
                "This one-action RDP negotiation trial uses a disconnected synthetic owned fixture, not a professional engagement or live-model evaluation.",
                "One fixed X.224 connection request offers TLS on one TCP connection. Only its first bounded connection-confirm frame is collected, then the client closes without a security handshake or session setup.",
                "Selected protocols, flags and failure codes are untrusted peer reports. They do not verify TLS support, security policy, authentication requirements, service identity or vulnerability.",
                "An explicit standard-RDP or TLS selection, a legacy confirmation and known negotiation failures are completed metadata observations. Malformed, incomplete, oversized or unsupported frames remain inconclusive.",
                "No TLS, CredSSP, Entra authentication, credentials, MCS exchange, desktop session, retry or follow-up is authorized. Reported failures do not authorize another attempt or different security protocol.",
                "Only the first 11- or 19-byte frame is retained. Any trailing peer bytes are outside this capture; their absence from evidence is not injection detection or proof that no trailing data was sent.",
                "Counters record the exact fixed request and a client write-half-close witnessed before the fixture response. This owned-profile constraint prevents further client bytes; compatibility with arbitrary real RDP servers is not established.",
                "Retained bytes are independently reparsed without network; read-only inspection restores no approval or authority. No real-model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith("dig-srv-"):
            report["limitations"] = [
                "This one-action DNS SRV trial uses a disconnected synthetic owned fixture, not a professional engagement or live-model evaluation.",
                "One fixed nonrecursive SRV question is sent over TCP. No UDP, search domains, retries, recursion, zone transfers or additional questions are authorized.",
                "Priority, weight, port, target and TTL are untrusted DNS advertisements, not verified service identity, reachability, availability or authorization to resolve or connect to an advertised endpoint.",
                "NOERROR with no SRV records is a completed no-data observation; NXDOMAIN is a reported name-not-found response; a sole zero-valued root target reports service unavailability. These statements describe only this response, not independently verified absence or availability.",
                "Only four unique bounded records with lowercase absolute ASCII hostname targets are supported. Other records, referrals, malformed/partial transcripts, refused replies and output pressure remain inconclusive.",
                "One bounded additional TXT record may be counted and discarded from normalized metadata. Its hostile text stays in raw evidence and cannot select another query, tool or destination.",
                "Counters record one validated question on one connection. Bounded native bytes are independently reparsed without network; read-only inspection restores no approval or authority. No real-model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith("whatweb-"):
            report["limitations"] = [
                "This one-action passive fingerprint trial uses a disconnected synthetic owned HTTP fixture, not a professional engagement or live-model evaluation.",
                "WhatWeb receives one fixed HTTP response with five reviewed passive plugins: Title, HTTPServer, X-Powered-By, MetaGenerator and JQuery. It does not fetch linked scripts, follow redirects or run aggressive plugins.",
                "All strings, versions and plugin matches are untrusted application hints. They do not prove software identity/version, authentication, exploitability or a vulnerability; forged hints may match.",
                "A complete HTTP 200 response with no reviewed hints is useful task completion, not proof that technologies are absent. Redirects, denied, incomplete, unsupported and oversized responses remain inconclusive.",
                "The initial parser accepts bounded printable ASCII hints, discards bounded OS guesses and Title warnings, and fails closed on other plugin or diagnostic shapes. This is not an exhaustive fingerprint catalog or universal page compatibility.",
                "Hostile metadata remains inert evidence; it cannot choose a target, URL or follow-up action. This deterministic trial does not measure real-model injection susceptibility or comparative overhead.",
                "Owner counters record the validated fixed GET on at most one connection. Bounded raw output is reparsed independently; read-only inspection restores no approval, budget or authority.",
            ]
        if manifest["fixture_case"].startswith(("postgresql-tls-", "mysql-tls-")):
            report["limitations"] = [
                "This single-action database TLS trial uses a disconnected synthetic owned fixture, not a real database engagement or live-model evaluation.",
                "OpenSSL sends only the fixed PostgreSQL SSLRequest or MySQL SSLRequest after a public synthetic greeting, then negotiates one verified TLS 1.3 handshake and closes without database application data.",
                "The selected wire profile and public fixture CA/hostname verification do not establish database product/version, readiness, authenticated access or a vulnerability.",
                "No database username, password, startup/login message, SQL, authentication plugin or plaintext downgrade is permitted. Refused, untrusted, incomplete and malformed handshakes remain inconclusive.",
                "The installed OpenSSL MySQL preface reader may reject fragmented greetings. Unsupported native diagnostic formats fail closed; this is not universal database compatibility or an exhaustive TLS assessment.",
                "Counters record completed TLS plus clean closure without application data on at most one TCP connection. Bounded raw channels are independently replayed; inspection restores no approval or authority.",
            ]
        if manifest["fixture_case"].startswith(("redis-", "snmp-")):
            report["limitations"] = [
                "This single-action metadata trial uses a disconnected synthetic fixture, not a professional engagement or real-model evaluation.",
                "Redis sends one RESP2 INFO server command without authentication, key access, writes or cluster redirection. Only bounded version, mode, architecture and advertised port fields are retained.",
                "SNMP sends one v2c GetRequest over TCP for three fixed system scalar OIDs using a public synthetic community. UDP, host MIB/config files, walks, writes, retries and corrective resubmission are excluded.",
                "Values are untrusted service reports, not authenticated identity, vulnerability proof or authorization for a follow-up destination. Explicit typed noSuchObject replies differ from missing or malformed evidence.",
                "Both bounded raw output channels are independently reparsed without network. Empty Redis metadata, rejected queries, partial output and unsupported native formats remain inconclusive.",
                "Counters record one validated query on at most one accepted TCP connection. Hashes reconcile local evidence; inspection never restores authority. No model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith("kerberos-"):
            report["limitations"] = [
                "This fixed two-name Kerbrute trial uses a disconnected synthetic error-only KDC, not a real directory or professional engagement.",
                "Results are tool reports, not verified principal existence, absence or authentication. Kerbrute can turn hostile error text containing KDC_ERR_C_PRINCIPAL_UNKNOWN into an ordinary unknown-user report; stdout cannot distinguish that case.",
                "The fixture validates initial AS-REQ messages and returns bounded KRB-ERROR responses or the declared malformed/silent test behavior. No password, preauthentication credential, ticket issuance, extraction or spraying is available in this owned profile.",
                "Stock Kerbrute attempts UDP before TCP. The unchanged TCP-only syscall filter rejects UDP; the fixed TCP fallback reaches only the approved numeric endpoint.",
                "The complete two-principal log and matching completion summary are independently reparsed without network. Partial, unsupported, denied and generic hostile logs remain inconclusive; output never authorizes follow-up work.",
                "Counters record validated initial AS-REQ messages, at most two; connections are acknowledged lower bounds. Hashes reconcile local evidence, inspection never restores authority, and no model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith("nmap-service-"):
            report["limitations"] = [
                "This finite service-identification trial uses a disconnected synthetic endpoint; it is not general Nmap coverage, authenticated identity or professional engagement validation.",
                "Only a TCP connect scan, NULL banner wait and one compiled HTTP GET probe are available. Pinned data and a no-op NSE entrypoint exclude host probe databases, version scripts, plugins, TLS upgrades and RPC follow-ups.",
                "An identified service is a match to reviewed response patterns. Advertised product/version values are untrusted metadata, not verified software inventory or vulnerability evidence.",
                "Unidentified means no match from this finite probe set. Silent, hostile, malformed and unfamiliar service replies may have the same native result; it does not prove service absence or benign behavior.",
                "Complete singleton XML is independently reparsed without network. Port-table guesses and raw fingerprints are excluded from findings; output never grants another target, port or action.",
                "Counters distinguish the empty connect scan from a sent banner or validated fixed GET. Connections are acknowledged lower bounds; inspection never restores execution authority. No model or comparative overhead claim is made.",
            ]
        if manifest["fixture_case"].startswith(("docker-", "winrm-")):
            report["limitations"] = [
                "This single fixed GET uses a disconnected synthetic HTTP fixture; it does not establish a real Docker or WinRM service, general compatibility or professional engagement readiness.",
                "Docker health and version are separate capabilities. An OK reply or version fields are endpoint observations, not authority to access a Docker socket, inspect containers or perform lifecycle operations.",
                "WinRM records only the fixed endpoint response status and reviewed advertised authentication schemes. It does not test authentication, send SOAP or create a remote session.",
                "Both raw channels are independently reparsed without network. Complete bounded HTTP framing is required; empty version metadata and missing authentication advertisements describe only this response, not service-wide absence or disabled authentication.",
                "Redirect locations and hostile output remain untrusted raw evidence. They cannot choose targets, paths, methods, credentials or follow-up actions; unsupported or partial replies remain inconclusive.",
                "The fixture has no Docker or WinRM backend. Counters record one validated fixed GET; accepted connections are acknowledged lower bounds, and inspection never restores execution authority.",
            ]
    if contract.WORKFLOW == "owned-service-web-assessment-v1":
        report["runtime_bindings"] = copy.deepcopy(manifest["runtime_bindings"])
        report["finding"]["title"] = "Owned HTTP service, fixed paths and response hardening headers"
        report["limitations"] = [
            "This three-action deterministic workflow uses a disconnected synthetic fixture; it is not real-model or professional engagement validation.",
            "Nmap identifies only reviewed HTTP response patterns. Advertised service metadata is untrusted and is not authenticated software inventory or vulnerability evidence.",
            "ffuf checks eight compiled paths. Only a complete non-wildcard result with the fixed portal at status 200 permits the next fixed action; discovered values cannot select a target, URL or tool.",
            "Header presence or absence is a configuration observation, not proof of exploitability. CSP strength, browser behavior, TLS and authenticated sessions are not assessed.",
            "The injected fixture retains hostile metadata in raw ffuf output and HTTP evidence. Deterministic normalized gating is not evidence of model susceptibility, an induced out-of-scope proposal or comparative blocking overhead.",
            "Both executable manifests are committed before execution; raw tool and HTTP results are independently reparsed in networkless workers. Hashes establish local consistency, not server authenticity or host-owner tamper resistance.",
            "Counters are acknowledged totals from one owned lab. Inspection never resumes execution, restores grants or authorizes follow-up activity.",
        ]
    if "planning_origin" in manifest:
        report["planning_origin"] = manifest["planning_origin"]
        report["live_calls_enabled"] = manifest["planning_origin"] == "model_live"
        report["planning"] = ("bounded model proposals; deterministic workflow evidence validation; "
                              + ("live provider" if report["live_calls_enabled"] else "owned synthetic provider"))
        report["limitations"][0] = "Only the owned synthetic HarborDesk workflow is evaluated; no professional engagement readiness is claimed."
        report["limitations"][5:7] = [
            "The injected note remains untrusted data. Model decisions and call accounting are recorded in the enclosing pilot report.",
            "This evidence replay validates tool results and workflow eligibility, not model quality, cost or latency by itself.",
        ]
    return report


def _metadata_literal(value):
    # JSON quoting plus escaped Markdown/HTML delimiters keeps service strings
    # inside one inert inline-code table cell, even for malicious output.
    text = json.dumps(value, ensure_ascii=True)
    for character in "`|<>&":
        text = text.replace(character, "\\u" + format(ord(character), "04x"))
    return "`" + text + "`"


def _markdown(report):
    title = ("# Owned service discovery and HTTP header workflow" if report["workflow"] == "owned-service-web-assessment-v1"
             else "# Owned single network-tool trial" if report["workflow"] == "owned-network-tool-assessment-v1"
             else "# Owned single web-tool trial" if report["workflow"] == "owned-web-tool-assessment-v1"
             else "# Owned HarborDesk web assessment" if report["workflow"] == "owned-web-assessment-v1"
             else "# Owned HTTP response-header assessment" if report["workflow"] == "owned-http-headers-assessment-v1"
             else "# Owned Nmap and HTTP assessment")
    lines = [title, "", "Outcome: **" + report["outcome"] + "**", "",
             "Reason: `" + report["reason"] + "`", "",
             ("Planning: " + report["planning"] + "." if "planning_origin" in report
              else "Planning: deterministic and offline."), "",
             "## Evidence", ""]
    for item in report["finding"]["evidence"]:
        lines.append("- Execution `" + item["execution_id"] + "`: [private result](" + item["artifact"]["filename"] + ")")
    if report["workflow"] in ("owned-http-headers-assessment-v1", "owned-service-web-assessment-v1") and report["finding"]["headers"] is not None:
        headers = report["finding"]["headers"]
        lines.extend(["", "## Observed response", "", "| Check | Observation |", "| --- | --- |"])
        for field, label in (("status_code", "HTTP status"), ("content_type", "Content type"),
                             ("csp", "Content-Security-Policy presence"),
                             ("x_frame_options", "X-Frame-Options"),
                             ("x_content_type_options", "X-Content-Type-Options")):
            lines.append("| " + label + " | " + str(headers[field]) + " |")
    if report["workflow"] == "owned-web-tool-assessment-v1":
        observation = report["finding"].get("tool_observation")
        details = observation.get("details") if type(observation) is dict else None
        if type(details) is dict and details.get("kind") == "curl_https":
            lines.extend(["", "## HTTPS response", "",
                          "| Check | Observation |", "| --- | --- |"])
            for name in ("status_code", "content_type", "csp", "x_frame_options", "x_content_type_options"):
                lines.append("| " + name + " | " + str(details["headers"][name]) + " |")
        elif type(details) is dict and details.get("kind") == "ffuf_content":
            lines.extend(["", "## Finite path coverage", "",
                          "Baseline: `" + details["baseline"] + "`.", "",
                          "| Path | HTTP status | Reported bytes |", "| --- | --- | --- |"])
            for row in details["responses"]:
                lines.append("| `" + row["path"] + "` | " + str(row["status_code"])
                             + " | " + str(row["bytes"]) + " |")
    if report["workflow"] == "owned-network-tool-assessment-v1":
        observation = report["finding"].get("tool_observation")
        details = observation.get("details") if type(observation) is dict else None
        if type(details) is dict and details.get("kind") == "dns_query":
            lines.extend(["", "## DNS observation", "", "Query: `" + details["query_name"]
                          + "` / `" + details["query_type"] + "` over TCP.", "",
                          "Status: `" + details["status"] + "`.", "",
                          "| Answer | TTL |", "| --- | --- |"])
            for row in details["answers"]:
                lines.append("| `" + row["address"] + "` | " + str(row["ttl"]) + " |")
        elif type(details) is dict and details.get("kind") == "smb2_negotiate_metadata":
            lines.extend(["", "## SMB2 negotiation metadata", "",
                "Untrusted peer report only. No SESSION_SETUP or authenticated session was performed; signing and service identity are not verified.",
                "", "| Field | Reported metadata |", "| --- | --- |"])
            for field in ("response_type", "status_code", "status_name", "dialect_revision", "security_mode",
                    "signing_required", "capabilities", "security_buffer_length"):
                lines.append("| " + field + " | " + _metadata_literal(details[field]) + " |")
            if details["response_type"] == "failure":
                lines.extend(["", "The peer reports negotiation refusal. The status does not verify the cause or its authentication requirements."])
            else:
                lines.extend(["", "The selected dialect and signing mode are claims from this response, not a verified security channel.",
                    "Capability bits depend on the zero-capability client offer; absent bits do not establish lack of server support."])
            lines.extend(["", "Capture ends at the first complete frame; trailing peer data is not retained. Opaque security bytes remain only in raw evidence and are never decoded."])
        elif type(details) is dict and details.get("kind") == "rdp_initial_negotiation":
            lines.extend(["", "## Initial RDP negotiation", "",
                "Untrusted peer report only. No security handshake or authenticated session was performed; service identity is not verified.",
                "", "| Field | Reported metadata |", "| --- | --- |"])
            for field in ("response_type", "selected_protocol", "response_flags", "failure_code", "failure_name"):
                lines.append("| " + field + " | " + _metadata_literal(details[field]) + " |")
            if details["response_type"] == "legacy":
                lines.extend(["", "The confirmation omits negotiation data and therefore implies a standard-RDP selection only."])
            elif details["response_type"] == "failure":
                lines.extend(["", "The peer reports a negotiation failure. This does not verify its authentication or security requirements."])
            else:
                lines.extend(["", "The reported protocol selection does not establish a working or verified security channel."])
            lines.extend(["", "Capture ends at the first complete confirmation frame; trailing peer data is not retained."])
        elif type(details) is dict and details.get("kind") == "dns_service_metadata":
            lines.extend(["", "## DNS service advertisements", "",
                "Untrusted DNS metadata only; advertised endpoints are not verified or authorized for follow-up.",
                "", "Query: `" + details["query_name"] + "` / `SRV` over TCP.",
                "", "Reported status: `" + details["status"] + "`.", "",
                "| Priority | Weight | Port | Untrusted target | TTL |", "| --- | --- | --- | --- | --- |"])
            for row in details["records"]:
                lines.append("| " + str(row["priority"]) + " | " + str(row["weight"]) + " | "
                    + str(row["port"]) + " | " + _metadata_literal(row["target"]) + " | " + str(row["ttl"]) + " |")
            if details["status"] == "NXDOMAIN":
                lines.extend(["", "The response reports name not found; absence is not independently verified."])
            elif not details["records"]:
                lines.extend(["", "The query completed with no SRV data; this does not prove service absence."])
            elif details["records"][0]["target"] == ".":
                lines.extend(["", "The root target reports service unavailable; availability is not independently verified."])
            lines.extend(["", "Additional TXT records ignored: " + str(details["additional_txt_count"]) + "."])
        elif type(details) is dict and details.get("kind") == "http_fingerprint":
            lines.extend(["", "## Passive HTTP application hints", "",
                "Untrusted response hints only; software identity, version and vulnerabilities are not verified.",
                "", "| Reviewed plugin | Untrusted strings | Untrusted version hints |", "| --- | --- | --- |"])
            for row in details["hints"]:
                lines.append("| " + row["plugin"] + " | " + _metadata_literal(row["strings"])
                             + " | " + _metadata_literal(row["versions"]) + " |")
            if not details["hints"]:
                lines.extend(["", "The fixed request completed with no reviewed hints. This does not establish technology absence."])
        elif type(details) is dict and details.get("kind") == "database_tls_handshake":
            lines.extend(["", "## Database TLS handshake", "",
                "Verified TLS under the selected wire profile and public fixture CA; no database login, readiness or product identity is established.",
                "", "| Check | Observation |", "| --- | --- |"])
            for field in ("service", "protocol", "cipher", "verification", "peer_name", "authenticated_database_session"):
                lines.append("| " + field + " | " + _metadata_literal(details[field]) + " |")
        elif type(details) is dict and details.get("kind") == "tls_handshake":
            lines.extend(["", "## TLS observation", "", "| Check | Observation |", "| --- | --- |"])
            for field in ("protocol", "cipher", "verification", "peer_name"):
                lines.append("| " + field + " | `" + details[field] + "` |")
        elif type(details) is dict and details.get("kind") == "ssh_host_keys":
            lines.extend(["", "## Observed SSH host key", "", "| Field | Observation |", "| --- | --- |"])
            for field in ("key_type", "key_bits", "fingerprint_sha256", "trust"):
                lines.append("| " + field + " | `" + str(details[field]) + "` |")
        elif type(details) is dict and details.get("kind") == "ldap_rootdse":
            lines.extend(["", "## Anonymous LDAP RootDSE", "", "| Attribute | Observation |", "| --- | --- |"])
            for field in ("naming_contexts", "supported_ldap_versions", "supported_sasl_mechanisms"):
                lines.append("| " + field + " | `" + (", ".join(details[field]) or "not advertised") + "` |")
            lines.append("| vendor_name | `" + (details["vendor_name"] or "not advertised") + "` |")
        elif type(details) is dict and details.get("kind") == "ftp_listing":
            lines.extend(["", "## FTP name listing", "", "| Name |", "| --- |"])
            lines.extend("| " + row["name"] + " |" for row in details["entries"])
            if not details["entries"]:
                lines.extend(["", "The complete validated listing contains no names."])
        elif type(details) is dict and details.get("kind") == "smtp_capabilities":
            lines.extend(["", "## SMTP advertised capabilities", "", "| Capability |", "| --- |"])
            lines.extend("| " + capability + " |" for capability in details["capabilities"])
            if not details["capabilities"]:
                lines.extend(["", "The complete validated EHLO reply advertises no extensions."])
        elif type(details) is dict and details.get("kind") == "redis_server_info":
            lines.extend(["", "## Redis server metadata", "",
                "Untrusted service reports; no authenticated identity or vulnerability is established.",
                "", "| Field | Reported value |", "| --- | --- |"])
            for field in ("version", "mode", "arch_bits", "tcp_port"):
                lines.append("| " + field + " | " + _metadata_literal(details["metadata"][field]) + " |")
        elif type(details) is dict and details.get("kind") == "snmp_system_metadata":
            lines.extend(["", "## SNMP system metadata over TCP", "",
                "Untrusted service reports from three fixed scalar OIDs; a missing object is an explicit response, not missing evidence.",
                "", "| OID | Reported type | Reported value |", "| --- | --- | --- |"])
            for row in details["variables"]:
                lines.append("| " + row["oid"] + " | " + row["type"] + " | " + _metadata_literal(row["value"]) + " |")
        elif type(details) is dict and details.get("kind") == "kerberos_principal_reports":
            lines.extend(["", "## Kerberos tool reports", "",
                "Tool reports only; principal existence, absence and authentication are not verified.",
                "Hostile error text can cause an ordinary unknown report; see the limitations below.",
                "", "| Synthetic principal | Kerbrute reported status |", "| --- | --- |"])
            lines.extend("| `" + row["principal"] + "` | `" + row["reported_status"] + "` |"
                         for row in details["principals"])
        elif type(details) is dict and details.get("kind") == "service_identification":
            lines.extend(["", "## Finite service identification", "", "Result: `" + details["identification"] + "`."])
            service = details["service"]
            if service is not None:
                lines.extend(["", "| Field | Observed match |", "| --- | --- |"])
                for field in ("name", "product", "version"):
                    lines.append("| " + field + " | `" + (service[field] or "not retained") + "` |")
            else:
                lines.extend(["", "The completed finite probe set produced no reviewed service match; this does not establish absence."])
        elif type(details) is dict and details.get("kind") == "docker_ping":
            lines.extend(["", "## Docker health endpoint response", "",
                          "The fixed endpoint returned a complete HTTP 200 response with `OK`."])
        elif type(details) is dict and details.get("kind") == "docker_version":
            lines.extend(["", "## Docker version endpoint metadata", "", "| Field | Observation |", "| --- | --- |"])
            for field, value in details["metadata"].items():
                lines.append("| " + field + " | `" + value + "` |")
            if not details["metadata"]:
                lines.extend(["", "The complete JSON response contains no reviewed version fields."])
        elif type(details) is dict and details.get("kind") == "winrm_metadata":
            lines.extend(["", "## WinRM endpoint response", "", "HTTP status: `" + str(details["status_code"]) + "`.",
                          "", "| Advertised authentication scheme |", "| --- |"])
            lines.extend("| " + scheme + " |" for scheme in details["auth_schemes"])
            if not details["auth_schemes"]:
                lines.extend(["", "This response advertises no reviewed authentication schemes; authentication was not attempted."])
        elif type(details) is dict and details.get("kind") == "rpc_registrations":
            lines.extend(["", "## RPC registration metadata", "", "| Program | Version | Transport | Port |",
                          "| --- | --- | --- | --- |"])
            for entry in details["registrations"]:
                lines.append("| " + " | ".join(str(entry[key]) for key in ("program", "version", "transport", "port")) + " |")
            if not details["registrations"]:
                lines.extend(["", "No registrations were returned by the validated listing."])
        elif type(details) is dict and details.get("kind") == "nfs_exports":
            lines.extend(["", "## NFS export metadata", "", "| Export | Advertised groups |", "| --- | --- |"])
            for entry in details["exports"]:
                lines.append("| `" + entry["path"] + "` | `" + (", ".join(entry["groups"]) or "everyone") + "` |")
            if not details["exports"]:
                lines.extend(["", "No exports were returned by the validated listing."])
        elif type(details) is dict and details.get("kind") == "smb_share_list":
            lines.extend(["", "## Anonymous SMB share metadata", "", "Status: `" + details["status"] + "`.",
                          "", "| Share | Type |", "| --- | --- |"])
            for share in details["shares"]:
                lines.append("| `" + share["name"] + "` | `" + share["type"] + "` |")
    lines.extend(["", "## Limits", "", *["- " + value for value in report["limitations"]]])
    if report["integrity_issues"]:
        lines.extend(["", "## Reconciliation required", "", *["- `" + value + "`" for value in report["integrity_issues"]]])
    return ("\n".join(lines) + "\n").encode("ascii")


class NmapEvidenceStore(EvidenceStore):
    """Reuse private file lifecycle only; all semantic contracts are versioned."""

    def __init__(self, directory, *, session_id, policy, case, owned_lab, runtime_sha256=None, deadline=None,
                 workflow_profile="nmap", planning_origin=None, runtime_bindings=None):
        self.directory = Path(directory)
        self._fd = self._journal = None
        self._failed = self._finalized = False
        self._records, self._decisions = [], []
        self._terminal = self._lab_closure = self._lab_context = None
        self._lock = threading.Lock()
        self._deadline = deadline
        try:
            contract, workflow = _profile(workflow_profile)
            if planning_origin is not None and (workflow_profile != "web"
                    or planning_origin not in ("model_owned", "model_live")):
                raise ValueError("invalid_evidence_planning_origin")
            if workflow_profile == "service_web":
                from .service_web_evidence import validate_runtime_bindings
                runtime_bindings = validate_runtime_bindings(runtime_bindings, runtime_sha256)
            elif runtime_bindings is not None:
                raise ValueError("unexpected_runtime_bindings")
            self._contract, self._workflow_contract = contract, workflow
            if not _uuid(session_id) or (runtime_sha256 is not None and not _digest(runtime_sha256)):
                raise ValueError("invalid_nmap_evidence_configuration")
            contract.action(case, 1)
            self._owned_lab = contract.validate_identity(owned_lab, case=case)
            self._manifest = {
                "schema_version": "1", "assessment_id": str(uuid4()), "session_id": session_id,
                "workflow": contract.WORKFLOW, "fixture_case": case, "policy_digest": policy.digest,
                "created_at": _now(), "artifact_representation": _representation(contract.WORKFLOW),
                "workflow_card": (workflow.card_identity(case) if workflow_profile == "network_tools"
                                  else workflow.card_identity()), "owned_lab": self._owned_lab,
                "runtime_sha256": runtime_sha256,
            }
            if workflow_profile == "service_web":
                self._manifest["runtime_bindings"] = runtime_bindings
            if planning_origin is not None:
                self._manifest["planning_origin"] = planning_origin
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._write_new("manifest.json", contract.encode(self._manifest), MAX_REPORT_BYTES)
            parent_fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self._journal = AuditSink(self.directory / "evidence.jsonl")
        except (OSError, RuntimeError, ValueError, TypeError):
            self._failed = True
            self.close()
            raise EvidenceUnavailable("evidence_unavailable") from None

    def record_decision(self, step, observation):
        workflow = self._workflow_contract
        with self._lock:
            try:
                self._check()
                if (self._lab_closure is not None or type(step) is not int or step != len(self._decisions) + 1
                        or type(observation) is not bytes or len(observation) > 8192
                        or any(row["artifact"] is None for row in self._records)
                        or (self._decisions and self._decisions[-1]["decision_kind"] != "propose")):
                    raise ValueError("invalid_nmap_decision_order")
                frame = load_json(observation)
                if (set(frame) != {"step", "untrusted_observation"} or type(frame["step"]) is not int
                        or frame["step"] != step or (step == 1 and frame["untrusted_observation"] is not None)):
                    raise ValueError("invalid_nmap_observation")
                decision = workflow.decide(self._manifest["fixture_case"], step, self._records, observation)
                value = {"decision_id": str(uuid4()), **decision.to_dict()}
                self._emit({"event_type": "assessment_workflow_decision", "decision": value})
                self._decisions.append(value)
                return decision
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def start(self, action, policy, *, session_id, session_step, backend):
        contract = self._contract
        with self._lock:
            try:
                self._check()
                expected = parse_action(contract.action(self._manifest["fixture_case"], session_step))
                if (session_id != self._manifest["session_id"] or policy.digest != self._manifest["policy_digest"]
                        or backend != contract.BACKEND or self._lab_closure is not None
                        or type(session_step) is not int or session_step != len(self._records) + 1
                        or action.digest != expected.digest or action.to_dict() != expected.to_dict()
                        or any(row["artifact"] is None for row in self._records)
                        or not self._decisions or self._decisions[-1]["step"] != session_step
                        or self._decisions[-1]["action_digest"] != action.digest
                        or self._decisions[-1]["decision_kind"] != "propose"):
                    raise ValueError("invalid_nmap_evidence_start")
                record = {"execution_id": str(uuid4()), "session_step": session_step,
                          "action": _safe_action(action), "action_digest": action.digest,
                          "policy_digest": policy.digest, "backend": backend, "started_at": _now(),
                          "finished_at": None, "execution_status": "started", "observation_id": None,
                          "observation": None, "artifact": None, "authority_observation_sha256": None,
                          "result_metadata": None}
                self._emit({"event_type": "assessment_execution_started", "record": record})
                self._records.append(record)
                return record["execution_id"]
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finish(self, execution_id, result, *, execution_status):
        with self._lock:
            try:
                self._check()
                if (not self._records or self._records[-1]["execution_id"] != execution_id
                        or self._records[-1]["artifact"] is not None or execution_status not in STATUSES):
                    raise ValueError("invalid_nmap_evidence_completion")
                record = {**self._records[-1], "execution_status": execution_status}
                context, observation = _validated_result(record, result, self._manifest, self._lab_context,
                                                         deadline=self._deadline)
                raw = contract.encode(result)
                filename = "result-" + execution_id + ".json"
                self._write_new(filename, raw, MAX_ARTIFACT_BYTES)
                record.update(finished_at=_now(), observation_id=str(uuid4()), observation=observation,
                              result_metadata=_result_metadata(result),
                              artifact={"filename": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                                        "bytes": len(raw), "representation": self._manifest["artifact_representation"]},
                              authority_observation_sha256=_observation_digest(record["session_step"], execution_status, result))
                self._emit({"event_type": "assessment_execution_finished", "record": record})
                self._records[-1], self._lab_context = record, context
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def record_lab_closed(self, receipt):
        """Persist the selected reviewed lab's teardown receipt before findings."""
        with self._lock:
            try:
                self._check()
                if (self._lab_closure is not None
                        or any(row["artifact"] is None for row in self._records)):
                    raise ValueError("invalid_owned_lab_closure_order")
                closure = self._contract.validate_closure(receipt, self._owned_lab, previous=self._lab_context)
                self._emit({"event_type": "assessment_owned_lab_closed", "receipt": closure})
                self._lab_closure = closure
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None

    def finalize(self, summary):
        workflow = self._workflow_contract
        with self._lock:
            try:
                self._check()
                if self._lab_closure is None or any(row["artifact"] is None for row in self._records):
                    raise ValueError("nmap_closure_missing")
                safe = _summary(summary, self._manifest, self._records, self._decisions)
                self._terminal = {"decision_id": str(uuid4()), **workflow.terminal_decision(
                    self._manifest["fixture_case"], self._records, safe).to_dict()}
                self._emit({"event_type": "assessment_workflow_terminal", "decision": self._terminal, "summary": safe})
                report = _report(self._manifest, self._records, self._decisions, safe,
                                 self._terminal, self._lab_closure, [])
                self._emit({"event_type": "assessment_finished", "summary": safe})
                self._write_new("report.json", contract.encode(report), MAX_REPORT_BYTES)
                self._write_new("report.md", _markdown(report), MAX_REPORT_BYTES)
                self._finalized = True
                return report
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError):
                self._failed = True
                raise EvidenceUnavailable("evidence_unavailable") from None


def inspect_evidence(directory):
    """Rebuild decisions and findings read-only; never restore a running session."""
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid_nmap_directory")
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 12:
                    raise ValueError("nmap_evidence_file_limit")
        manifest = load_json(_read_private(fd, "manifest.json", 8192))
        contract, workflow = _manifest_profile(manifest)
        extra_fields = {"runtime_bindings"} if contract.WORKFLOW == "owned-service-web-assessment-v1" else set()
        if (not extra_fields <= set(manifest) or set(manifest) - {"planning_origin"} - extra_fields != {"schema_version", "assessment_id", "session_id", "workflow", "fixture_case",
                             "policy_digest", "created_at", "artifact_representation", "workflow_card",
                             "owned_lab", "runtime_sha256"}
                or manifest["schema_version"] != "1" or manifest["workflow"] != contract.WORKFLOW
                or manifest["artifact_representation"] != _representation(contract.WORKFLOW)
                or not _uuid(manifest["assessment_id"]) or not _uuid(manifest["session_id"])
                or not _digest(manifest["policy_digest"])
                or (manifest["runtime_sha256"] is not None and not _digest(manifest["runtime_sha256"]))
                or manifest["workflow_card"] != (workflow.card_identity(manifest["fixture_case"])
                    if contract.WORKFLOW == "owned-network-tool-assessment-v1" else workflow.card_identity())
                or type(manifest["created_at"]) is not str or len(manifest["created_at"]) > 64):
            raise ValueError("invalid_nmap_manifest")
        contract.validate_identity(manifest["owned_lab"], case=manifest["fixture_case"])
        records, decisions, issues = [], [], []
        summary = terminal = terminal_summary = context = closure = latest_result = None
        referenced = {"manifest.json", "evidence.jsonl", "report.json", "report.md"}
        try:
            lines = _read_private(fd, "evidence.jsonl", MAX_JOURNAL_BYTES).splitlines(keepends=True)
        except (OSError, ValueError):
            lines = []
            issues.append("journal_unavailable")
        if len(lines) > 12:
            issues.append("journal_event_limit")
            lines = lines[:12]
        for line in lines:
            try:
                if not line.endswith(b"\n") or summary is not None:
                    raise ValueError("invalid_nmap_event_order")
                event = load_json(line)
                if event["assessment_id"] != manifest["assessment_id"] or event["session_id"] != manifest["session_id"]:
                    raise ValueError("wrong_nmap_session")
                kind = event["event_type"]
                if kind == "assessment_finished":
                    candidate = _summary(event["summary"], manifest, records, decisions)
                    if terminal is None or closure is None or candidate != terminal_summary:
                        raise ValueError("missing_nmap_closure")
                    summary = candidate
                    continue
                if terminal is not None:
                    raise ValueError("nmap_already_terminated")
                if kind == "assessment_owned_lab_closed":
                    if closure is not None or any(row["artifact"] is None for row in records):
                        raise ValueError("invalid_nmap_closure_order")
                    closure = contract.validate_closure(event["receipt"], manifest["owned_lab"], previous=context)
                    continue
                if kind == "assessment_workflow_terminal":
                    candidate = _summary(event["summary"], manifest, records, decisions)
                    if closure is None:
                        raise ValueError("missing_nmap_closure")
                    expected = workflow.terminal_decision(manifest["fixture_case"], records, candidate)
                    _decision_matches(event["decision"], expected, decisions)
                    terminal, terminal_summary = event["decision"], candidate
                    continue
                if closure is not None:
                    raise ValueError("nmap_lab_already_closed")
                if kind == "assessment_workflow_decision":
                    step = event["decision"]["step"]
                    if (type(step) is not int or step != len(decisions) + 1
                            or any(row["artifact"] is None for row in records)
                            or (decisions and decisions[-1]["decision_kind"] != "propose")):
                        raise ValueError("invalid_nmap_decision_order")
                    expected = workflow.decide(manifest["fixture_case"], step, records,
                                               _workflow_observation(step, records, latest_result))
                    _decision_matches(event["decision"], expected, decisions)
                    decisions.append(event["decision"])
                    continue
                record = event["record"]
                if (type(record) is not dict or set(record) != _RECORD_FIELDS
                        or not _uuid(record["execution_id"]) or record["policy_digest"] != manifest["policy_digest"]
                        or record["backend"] != contract.BACKEND or type(record["started_at"]) is not str
                        or len(record["started_at"]) > 64):
                    raise ValueError("invalid_nmap_execution")
                expected = parse_action(contract.action(manifest["fixture_case"], record["session_step"]))
                if record["action"] != _safe_action(expected) or record["action_digest"] != expected.digest:
                    raise ValueError("unexpected_nmap_action")
                if kind == "assessment_execution_started":
                    if (record["session_step"] != len(records) + 1 or record["execution_status"] != "started"
                            or record["execution_id"] in {row["execution_id"] for row in records}
                            or any(row["artifact"] is None for row in records)
                            or any(record[key] is not None for key in ("finished_at", "observation_id", "observation",
                                                                      "artifact", "authority_observation_sha256", "result_metadata"))
                            or not decisions or decisions[-1]["decision_kind"] != "propose"
                            or decisions[-1]["step"] != record["session_step"]
                            or decisions[-1]["action_digest"] != record["action_digest"]):
                        raise ValueError("invalid_nmap_start")
                    records.append(record)
                elif kind == "assessment_execution_finished":
                    if (not records or records[-1]["artifact"] is not None
                            or any(record[key] != records[-1][key] for key in (
                                "execution_id", "session_step", "action", "action_digest", "policy_digest", "backend", "started_at"))
                            or record["execution_status"] not in STATUSES or not _uuid(record["observation_id"])
                            or record["observation_id"] in {row["observation_id"] for row in records[:-1]}
                            or type(record["finished_at"]) is not str or len(record["finished_at"]) > 64):
                        raise ValueError("invalid_nmap_completion")
                    artifact = record["artifact"]
                    if (type(artifact) is not dict or set(artifact) != {"filename", "bytes", "sha256", "representation"}
                            or artifact["filename"] != "result-" + record["execution_id"] + ".json"
                            or artifact["representation"] != manifest["artifact_representation"] or not _digest(artifact["sha256"])
                            or type(artifact["bytes"]) is not int or not 1 <= artifact["bytes"] <= MAX_ARTIFACT_BYTES):
                        raise ValueError("invalid_nmap_artifact")
                    raw = _read_private(fd, artifact["filename"], MAX_ARTIFACT_BYTES)
                    if len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                        raise ValueError("nmap_artifact_mismatch")
                    result = load_json(raw)
                    new_context, observation = _validated_result(record, result, manifest, context)
                    if (contract.encode(observation) != contract.encode(record["observation"])
                            or contract.encode(_result_metadata(result)) != contract.encode(record["result_metadata"])
                            or _observation_digest(record["session_step"], record["execution_status"], result)
                            != record["authority_observation_sha256"]):
                        raise ValueError("nmap_observation_mismatch")
                    records[-1], context, latest_result = record, new_context, result
                    referenced.add(artifact["filename"])
                else:
                    raise ValueError("unknown_nmap_event")
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
                issues.append("journal_or_artifact_incomplete")
                break
        if summary is None:
            issues.append("assessment_closure_missing")
        if closure is None:
            issues.append("owned_lab_closure_missing")
        if terminal is None:
            issues.append("workflow_terminal_missing")
        if any(row["artifact"] is None for row in records):
            issues.append("execution_completion_unknown")
        if set(names) - referenced:
            issues.append("orphan_artifacts_present")
        report = _report(manifest, records, decisions, summary, terminal, closure, issues)
        if summary is not None:
            try:
                if (contract.encode(load_json(_read_private(fd, "report.json", MAX_REPORT_BYTES))) != contract.encode(report)
                        or _read_private(fd, "report.md", MAX_REPORT_BYTES) != _markdown(report)):
                    raise ValueError("nmap_report_mismatch")
            except (OSError, ValueError):
                issues.append("report_missing_or_mismatched")
                report = _report(manifest, records, decisions, summary, terminal, closure, issues)
        return report
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
        raise EvidenceUnavailable("evidence_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _decision_matches(value, expected, previous):
    if (type(value) is not dict or not _uuid(value.get("decision_id"))
            or value["decision_id"] in {row["decision_id"] for row in previous}
            or contract.encode({key: item for key, item in value.items() if key != "decision_id"})
            != contract.encode(expected.to_dict())):
        raise ValueError("nmap_decision_mismatch")


inspect_assessment = inspect_evidence
