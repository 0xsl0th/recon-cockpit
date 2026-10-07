"""Pure, bounded display projections for the offline desktop interface.

Inputs to ``present_report`` must already have passed through the shared saved
assessment inspector. This module neither reads artifacts nor confers authority.
All output is literal text for widgets, never HTML, links or executable commands.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import unicodedata

from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent.configurable_scope import load_scope, scope_digest
from recon_cockpit.secure_agent.models import parse_action

FIELD_NAMES = ("scope_id", "http_target", "http_port", "http_path", "ssh_target", "ssh_port")
MAX_ROWS = 16
MAX_TEXT = 1024
MAX_DETAIL = 4096
MAX_ITEMS = 24
_KNOWN_WORKFLOWS = frozenset({
    "owned-http-assessment-v1", "owned-discovery-http-assessment-v1",
    "owned-workflow-assessment-v1", "owned-lab-workflow-assessment-v1",
    "owned-nmap-http-assessment-v1", "owned-web-assessment-v1",
    "owned-http-headers-assessment-v1", "owned-web-tool-assessment-v1",
    "owned-network-tool-assessment-v1", "owned-service-web-assessment-v1",
    contract.WORKFLOW,
})
_UNAVAILABLE = "Unavailable"
_TOOL_LABELS = {
    "http_probe": "HTTP request", "tcp_connect": "TCP connection",
    "nmap_tcp_connect_v1": "Nmap TCP probe", "http_headers_v1": "HTTP headers",
    "curl_https_get_v1": "HTTPS response", "ffuf_content_discovery_v1": "Web path discovery",
    "dig_dns_query_v1": "DNS query", "openssl_tls_handshake_v1": "TLS handshake",
    "ssh_host_keys_v1": "SSH public key", "ldap_rootdse_v1": "LDAP RootDSE",
    "smb_share_list_v1": "SMB shares", "rpcinfo_dump_v1": "RPC registrations",
    "showmount_exports_v1": "NFS exports", "curl_ftp_list_v1": "FTP names",
    "curl_smtp_capabilities_v1": "SMTP capabilities", "curl_docker_ping_v1": "Docker health",
    "curl_docker_version_v1": "Docker version", "curl_winrm_metadata_v1": "WinRM metadata",
    "nmap_service_identify_v1": "Nmap service ID", "kerbrute_userenum_v1": "Kerberos principal check",
    "configurable_nmap_service_v1": "Nmap service ID",
    "configurable_http_headers_v1": "HTTP headers",
    "configurable_ssh_host_keys_v1": "SSH public key",
}


def safe_text(value, max_length=MAX_TEXT):
    """Escape control/format characters visibly, including bidi and line breaks.

    Only primitive scalars are rendered. In particular, arbitrary objects cannot
    supply display text via ``__str__``. The limit includes the truncation marker.
    """
    limit = max_length
    if type(limit) is not int or not 1 <= limit <= 16384:
        raise ValueError("invalid_display_text_limit")
    if type(value) is str:
        source = value
    elif type(value) in (int, float, bool):
        source = json.dumps(value, allow_nan=False)
    elif value is None:
        return _UNAVAILABLE
    else:
        return "[unsupported value]"
    parts, size = [], 0
    for char in source:
        rendered = ("\\u%04x" % ord(char) if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                    else char)
        if size + len(rendered) > limit - 1:
            return "".join(parts) + "…"
        parts.append(rendered)
        size += len(rendered)
    return "".join(parts)


def _validated_scope(scope):
    try:
        raw = json.dumps(scope, ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("invalid_configurable_scope") from None
    return load_scope(raw)


def scope_from_fields(fields):
    """Convert strict form strings using the existing authoritative validator."""
    if type(fields) is not dict or set(fields) != set(FIELD_NAMES):
        raise ValueError("invalid_scope_form_fields")
    if any(type(value) is not str or len(value) > 128 for value in fields.values()):
        raise ValueError("invalid_scope_form_value")
    ports = {}
    for name in ("http_port", "ssh_port"):
        if re.fullmatch(r"[1-9][0-9]{0,4}", fields[name]) is None:
            raise ValueError("invalid_configurable_scope_port")
        ports[name] = int(fields[name])
    return _validated_scope({"schema_version": "1", "scope_id": fields["scope_id"],
        "http": {"target": fields["http_target"], "port": ports["http_port"], "path": fields["http_path"]},
        "ssh": {"target": fields["ssh_target"], "port": ports["ssh_port"]}})


def scope_fields(scope):
    """Return a detached editable draft; never recover scope from a report."""
    value = _validated_scope(scope)
    return {"scope_id": value["scope_id"], "http_target": value["http"]["target"],
        "http_port": str(value["http"]["port"]), "http_path": value["http"]["path"],
        "ssh_target": value["ssh"]["target"], "ssh_port": str(value["ssh"]["port"])}


def present_session(snapshot, *, phase, cancel_requested, directory, mode="dry_run"):
    """Observed lifecycle only; no evidence grade or completed-work inference.

    Match observed action digests to the frozen scope instead of guessing from
    row order. A policy's approval requirement is never a live approval prompt.
    """
    if type(mode) is not str or mode not in {"dry_run", "owned_execution"}:
        raise ValueError("invalid_desktop_session_mode")
    scope = _validated_scope(snapshot["scope"])
    notice = ("Observed execution progress; completion is unverified until evidence replay.\n"
              if mode == "owned_execution" else "Observed dry-run decision; no tool executed.\n")
    actions = {parse_action(contract.action(scope, index)).digest: contract.action(scope, index)
               for index in range(1, 5)}
    rows = []
    for index, step in enumerate(snapshot.get("steps", [])[:4], 1):
        action = actions.get(step.get("action_digest"))
        endpoint = None if action is None else f"{action['target']}:{action['parameters']['port']}"
        rows.append({"id": f"session-{index}", "step": safe_text(step.get("step")),
            "tool": _TOOL_LABELS.get(action["tool_id"], "Unknown action") if action else "Unknown action",
            "target": safe_text(endpoint), "status": safe_text(step.get("execution_status")),
            "detail": notice + "Approval requirements describe policy, not a pending human prompt.\n\n"
                + _bounded_json({"action": action, "decision": step.get("decision"),
                    "execution_status": step.get("execution_status"), "reasons": step.get("reasons")})})
    return {"mode": mode, "phase": phase, "state": safe_text(snapshot["state"]),
        "session_id": safe_text(snapshot["session_id"]), "scope": scope,
        "scope_sha256": scope_digest(scope), "steps": rows,
        "stop_reason": snapshot.get("stop_reason"), "cancel_requested": bool(cancel_requested),
        "session_dir": safe_text(str(directory))}


def _bounded_json(value):
    budget = [128]

    def visit(item, depth):
        budget[0] -= 1
        if budget[0] < 0 or depth > 5:
            return "[display limit]"
        if type(item) is dict:
            result = {}
            for index, (key, entry) in enumerate(item.items()):
                if index >= MAX_ITEMS or budget[0] <= 0:
                    result["[display limit]"] = "Additional fields omitted"
                    break
                result[safe_text(key, 128)] = visit(entry, depth + 1)
            return result
        if type(item) is list:
            result = [visit(entry, depth + 1) for entry in item[:min(MAX_ITEMS, max(0, budget[0]))]]
            if len(result) < len(item):
                result.append("[additional items omitted]")
            return result
        if item is None or type(item) is bool:
            return item
        if type(item) in (str, int, float):
            try:
                return safe_text(item)
            except ValueError:
                return "[invalid number]"
        return "[unsupported value]"

    rendered = json.dumps(visit(value, 0), ensure_ascii=False, indent=2, allow_nan=False)
    return rendered if len(rendered) <= MAX_DETAIL else rendered[:MAX_DETAIL - 1] + "…"


def _observation_summary(observation, params):
    """Summarize only retained fields; absence never implies protocol or trust."""
    if type(observation) is not dict:
        return "No structured observation is available."
    details = observation.get("details", observation)
    details = details if type(details) is dict else {}
    lines = ["Recorded observation · untrusted metadata"]

    def field(label, value):
        if type(value) is str and value:
            lines.append(label + ": " + safe_text(value, 192))

    service = details.get("service")
    if type(service) is dict:
        name = service.get("name")
        field("Service", name.upper() if name in ("http", "ssh") else name)
        field("Product", service.get("product"))
        field("Version", service.get("version"))
        field("Port state", details.get("state"))
    headers = details.get("headers")
    if type(headers) is dict:
        status = headers.get("status_code")
        if type(status) is int and 100 <= status <= 599:
            lines.append("HTTP status: " + str(status))
        if type(params.get("method")) is str and type(params.get("path")) is str:
            lines.append("Declared request: " + safe_text(params["method"], 32) + " " + safe_text(params["path"], 192))
        field("Content type", headers.get("content_type"))
    field("Key type", details.get("key_type"))
    bits = details.get("key_bits")
    if type(bits) is int and 0 < bits <= 65536:
        lines.append("Key size: " + str(bits) + " bits")
    field("Fingerprint", details.get("fingerprint_sha256"))
    field("Key trust", details.get("trust"))
    if len(lines) == 1:
        field("Classification", observation.get("classification"))
        field("Reason", observation.get("reason"))
    if len(lines) == 1:
        lines.append("No summarized metadata is available; see the recorded fields below.")
    return "\n".join(lines)


def _action_row(value, *, step, status, row_id, observation=None, artifact=None, execution_id=None):
    action = value if type(value) is dict else {}
    params = action.get("parameters")
    params = params if type(params) is dict else {}
    target = safe_text(action.get("target"), 256)
    if type(params.get("port")) is int:
        target += ":" + safe_text(params["port"], 16)
    tool_id = action.get("tool_id")
    tool = _TOOL_LABELS.get(tool_id, tool_id) if type(tool_id) is str else None
    if observation is not None:
        detail = _observation_summary(observation, params)
        detail += "\n\nStructured observation (untrusted data):\n" + _bounded_json(observation)
    else:
        detail = "No structured observation is available."
    detail += "\n\nExact action parameters (data):\n" + _bounded_json(params)
    detail += "\n\nTechnical references\nTool ID: " + safe_text(tool_id, 128)
    if execution_id is not None:
        detail += "\nRecorded execution ID: " + safe_text(execution_id, 128)
    if artifact is not None:
        detail += "\n\nEvidence reference (not a link):\n" + _bounded_json(artifact)
    maximum = 3 * MAX_DETAIL + 256
    if len(detail) > maximum:
        detail = detail[:maximum - 1] + "…"
    return {"id": safe_text(row_id, 128), "step": safe_text(step, 32),
        "tool": safe_text(tool, 128), "target": target,
        "status": safe_text(status, 128), "detail": detail}


def scope_preview(scope):
    """Describe four proposals without starting or representing an assessment."""
    value = _validated_scope(scope)
    return {"scope_sha256": scope_digest(value), "rows": [
        _action_row(contract.action(value, step), step=step, status="Draft — not executed",
                    row_id="draft-" + str(step)) for step in range(1, 5)],
        "limits": dict(contract.LIMITS),
        "notice": "Draft only. Four fixed proposals for disconnected owned fixtures; no execution or approval is created."}


def _numeric(value):
    return value if type(value) is int and 0 <= value <= 10**15 else None


def _metric(label, value, detail):
    return {"label": label, "value": _UNAVAILABLE if value is None else str(value), "detail": detail}


def present_report(report, path):
    """Project an inspector result into saved-state views, with no file access.

    Missing historical metrics stay unavailable. A consistent report is not
    authenticated, an approved engagement, or evidence of a live running session.
    """
    if type(report) is not dict or not isinstance(path, (str, Path)):
        raise ValueError("invalid_saved_report_display")
    workflow = report.get("workflow")
    recognized = type(workflow) is str and workflow in _KNOWN_WORKFLOWS
    raw_issues = report.get("integrity_issues")
    issues = ([safe_text(item) for item in raw_issues[:MAX_ITEMS]] if type(raw_issues) is list
              else ["Evidence integrity status unavailable"])
    if type(raw_issues) is list and len(raw_issues) > MAX_ITEMS:
        issues.append("Additional integrity issues omitted from this display")
    if not recognized:
        issues.append("Unsupported workflow; display cannot establish completion")
    consistent = recognized and type(raw_issues) is list and not raw_issues
    summary = report.get("summary", report.get("execution"))
    summary = summary if type(summary) is dict else {}
    mode, session_status = summary.get("mode"), summary.get("session_status")
    outcome = report.get("outcome")
    if not consistent:
        outcome = "incomplete"
    elif mode == "dry_run":
        outcome = "dry_run"
    elif outcome == "completed" and (mode != "execute" or session_status != "completed"):
        outcome = "incomplete"
    metrics = report.get("metrics") if consistent else None
    metrics = metrics if type(metrics) is dict else {}
    completion = metrics.get("legitimate_task_completed")
    if type(completion) is not bool:
        completion = None
    elif completion and not (outcome == "completed" and mode == "execute" and session_status == "completed"):
        completion = None
    useful = _numeric(metrics.get("useful_actions_completed"))
    planned = _numeric(metrics.get("planned_actions"))
    unnecessary = _numeric(metrics.get("unnecessary_refusals")) if completion is True else None
    calls, cost = _numeric(metrics.get("actual_provider_calls")), _numeric(metrics.get("actual_cost_microusd"))
    elapsed = _numeric(metrics.get("elapsed_ms"))
    cost_value = None
    if calls is not None and cost is not None:
        whole, fraction = divmod(cost, 1000000)
        dollars = str(whole) + ("." + f"{fraction:06d}".rstrip("0") if fraction else "")
        cost_value = f"{calls} / ${dollars}"
    scope = None
    if workflow == contract.WORKFLOW and consistent and type(report.get("scope")) is dict:
        try:
            scope = _validated_scope(report["scope"])
        except ValueError:
            pass
    records = report.get("records")
    records = records if type(records) is list else []
    rows = []
    for index, record in enumerate(records[:MAX_ROWS]):
        if type(record) is not dict:
            continue
        rows.append(_action_row(record.get("action"), step=record.get("step", record.get("session_step")),
            status=record.get("status", record.get("execution_status")),
            row_id="record-" + str(index + 1), execution_id=record.get("execution_id"),
            observation=record.get("observation"), artifact=record.get("artifact")))
    raw_limits = report.get("limitations")
    limitations = [safe_text(item) for item in raw_limits[:MAX_ITEMS]] if type(raw_limits) is list else []
    if type(raw_limits) is list and len(raw_limits) > MAX_ITEMS:
        limitations.append("Additional report limitations omitted from this display")
    limitations.append("Saved evidence only. Inspection does not resume execution or restore approvals.")
    if len(records) > MAX_ROWS:
        limitations.append("Only the first " + str(MAX_ROWS) + " recorded actions are displayed.")
    finding = report.get("finding")
    title = finding.get("title") if type(finding) is dict else None
    return {"title": safe_text(title) if type(title) is str else "Saved assessment evidence",
        "assessment_id": safe_text(report.get("assessment_id"), 128),
        "session_id": safe_text(report.get("session_id", summary.get("session_id")), 128),
        "outcome": safe_text(outcome, 128), "workflow": safe_text(workflow, 128),
        "reason": safe_text(report.get("reason", summary.get("stop_reason"))),
        "mode": safe_text(mode, 64), "session_status": safe_text(session_status, 64),
        "source_path": safe_text(str(path), 2048), "read_only": True,
        "scope": scope, "recorded_scope_text": _bounded_json(report.get("scope")),
        "integrity_issues": issues, "limitations": limitations, "rows": rows,
        "metrics": [
            _metric("Legitimate completion", "Yes" if completion is True else "No" if completion is False else None,
                    "Recorded usefulness result; unavailable for ungraded or unreconciled evidence."),
            _metric("Useful actions", f"{useful}/{planned}" if useful is not None and planned is not None else useful,
                    "Recorded useful action count; a dry run does not execute work."),
            _metric("Unnecessary refusals", unnecessary,
                    "Graded only for completed known-legitimate work."),
            _metric("Model calls / cost", cost_value,
                    "Recorded provider calls and actual cost; absent values are not assumed zero."),
            _metric("Elapsed time", f"{elapsed // 1000}.{elapsed % 1000:03d} s" if elapsed is not None else None,
                    "Recorded local session time, not a comparative overhead benchmark.")],
        "limits": _bounded_json(report.get("capability", {}).get("limits"))
                  if type(report.get("capability")) is dict else _UNAVAILABLE}
