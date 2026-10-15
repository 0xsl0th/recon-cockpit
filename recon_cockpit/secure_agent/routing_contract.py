"""Finite disconnected routing commitments; none of these values authorizes launch."""

import base64
from copy import deepcopy
import hashlib
import re
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from . import stock_http_production_contract as http
from . import stock_http_spec
from . import stock_ssh_spec
from . import stock_ssh_contract as ssh
from . import routing_topology_spec as topology
from .models import Action, parse_policy

PROFILE = "disconnected_routing_v1"
BACKEND = "linux-authorized-disconnected-routing-v1"
BOUNDARY_REVISION = "five-namespaces-single-lifetime-ledger-v1"
DEPLOYMENT_BOUNDARY_REVISION = "five-namespaces-single-lifetime-ledger-apache-one-use-handoff-v2"
MATRIX_BOUNDARY_REVISION = "five-namespaces-fixed-case-matrix-owner-enforcement-v3"
DEPLOYMENTS = ("nginx-A", "nginx-B", "apache-A", "apache-B")
SELECTORS = ("http_nmap", "http_headers", "ssh_nmap", "ssh_keys")
BUDGET_CASES = ("ordinary", "connection_one", "http_one", "ssh_zero")
SELECTION_FIELDS = ("configuration", "budget_case", "selection_sha256")
DEPLOYMENT_SELECTION_FIELDS = ("selection_version", "implementation", *SELECTION_FIELDS)
MATRIX_SELECTION_FIELDS = (*DEPLOYMENT_SELECTION_FIELDS, "case_profile")
_BASELINE_CASES = {"http_nmap": "O5", "http_headers": "O1", "ssh_nmap": "O1", "ssh_keys": "O2"}
_SELECTOR_CASES = {
    "http_nmap": ("O5", "O6"),
    "http_headers": ("O1", "O2", "O3", "O4", "R1", "R2", "N1", "N2", "N3", "N4", "N5"),
    "ssh_nmap": ("O1", "N1"),
    "ssh_keys": ("O2", "R1", "R2", "N2", "N3", "N4", "N5", "N6"),
}
CASE_PROFILES = ("baseline", *(name + "_" + case for name in SELECTORS
                              for case in _SELECTOR_CASES[name] if case != _BASELINE_CASES[name]))
BOOTSTRAP_MAX_BYTES = 131072
EVIDENCE_BOUNDS = {"max_files": 15, "max_total_bytes": 2097152,
                   "max_json_bytes": 524288, "max_json_depth": 64}
OWNER_BOUNDS = {"processes": 1, "address_space_bytes": 268435456,
                "file_descriptors": 128, "retained_bytes": 1048576}
ACTION_BOUNDS = {
    "http_nmap": {"connections": 3, "http_requests": 1, "kex_exchanges": 0,
                  "request_bytes": 18, "response_bytes": 4096, "output_bytes": 8192, "timeout_seconds": 5},
    "http_headers": {"connections": 1, "http_requests": 1, "kex_exchanges": 0,
                     "request_bytes": 256, "response_bytes": 2048, "output_bytes": 2048, "timeout_seconds": 1},
    "ssh_nmap": {"connections": 3, "http_requests": 0, "kex_exchanges": 0,
                 "request_bytes": 0, "response_bytes": 255, "output_bytes": 8192, "timeout_seconds": 5},
    "ssh_keys": {"connections": 1, "http_requests": 0, "kex_exchanges": 1,
                 "request_bytes": 8192, "response_bytes": 8192, "output_bytes": 8192, "timeout_seconds": 5},
}
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def digest(value):
    return hashlib.sha256(stock_http_spec.encode(value)).hexdigest()


def validate_selector(value):
    if type(value) is not str or value not in SELECTORS:
        raise ValueError("invalid_routing_selector")
    return value


def selector_role(selector):
    return "http_frontend" if validate_selector(selector).startswith("http_") else "ssh_frontend"


def _case_map(profile):
    cases = dict(_BASELINE_CASES)
    if profile is None:
        return cases
    if type(profile) is not str or profile not in CASE_PROFILES:
        raise ValueError("invalid_routing_case_profile")
    if profile != "baseline":
        selector, case = profile.rsplit("_", 1)
        cases[selector] = case
    return cases


def _underlying_selection(selector, implementation, configuration, profile=None):
    selector = validate_selector(selector)
    case = _case_map(profile)[selector]
    if selector.startswith("http_"):
        return http.selection(implementation, configuration, case)
    return ssh.selection(configuration, case)


def underlying_selection(selector, selected=None):
    if selected is None:
        return _underlying_selection(selector, "nginx", "A")
    chosen = validate_selection(selected)
    return _underlying_selection(selector, chosen.get("implementation", "nginx"), chosen["configuration"],
                                 chosen.get("case_profile"))


def case_profile(selected):
    return validate_selection(selected).get("case_profile")


def selected_case(selector, selected=None):
    return underlying_selection(selector, selected)["case"]


def case_is_negative(selector, selected):
    chosen = underlying_selection(selector, selected)
    spec = stock_http_spec if selector.startswith("http_") else stock_ssh_spec
    return chosen["case"] in spec.NEGATIVE_CASES


def _case_expectation(selector, case, *, matrix):
    spec = stock_http_spec if selector.startswith("http_") else stock_ssh_spec
    native = spec.expectation(case)
    negative = case in spec.NEGATIVE_CASES
    value = {"category": native["category"], "expected_negative": negative,
             "allowed_classifications": list(native.get("allowed_outcomes", ["useful"])),
             "classification_basis": None, "native_expectation": native, "requirements": {}}
    if selector == "http_headers" and case == "N4" and matrix:
        value.update(allowed_classifications=["expected_response_budget_refusal"],
            classification_basis="routing_owner_response_budget_before_delivery",
            requirements={"proposed_response_bytes": 2049, "delivered_response_bytes": 0,
                "accepted_response_reservation_bytes": 0, "delivered_validated_requests": 1,
                "terminal_reason": "action_response_bytes_limit"})
    elif selector == "ssh_keys" and case == "N3":
        value.update(classification_basis="withheld_response_and_native_two_second_timeout",
            requirements={"minimum_action_elapsed_ms": 1900, "allowed_native_statuses": ["failed", "timeout"],
                "delivered_response_bytes": 0})
    elif selector == "ssh_keys" and case == "N4":
        value["classification_basis"] = "independent_recorder_wire_cap"
    return value


def case_expectation(selector, selected):
    selected = validate_selection(selected)
    selector = validate_selector(selector)
    return _case_expectation(selector, _case_map(selected.get("case_profile"))[selector],
                             matrix=selected.get("selection_version") == "3")


def http_implementation(selected):
    return validate_selection(selected).get("implementation", "nginx")


def underlying_contract(selector):
    return http if selector_role(selector) == "http_frontend" else ssh


def _budgets(budget_case):
    if type(budget_case) is not str or budget_case not in BUDGET_CASES:
        raise ValueError("invalid_routing_budget_case")
    return {"actions": 4, "session_seconds": 60,
            "connections": 1 if budget_case == "connection_one" else 8,
            "http_requests": 1 if budget_case == "http_one" else 2,
            "kex_exchanges": 0 if budget_case == "ssh_zero" else 1,
            "concurrent_connections": 1, "minimum_admission_interval_ms": 250,
            "request_bytes": 8466, "response_bytes": 14591, "output_bytes": 26624}


def selection(budget_case="ordinary", *, deployment=None, case_profile=None):
    caps = _budgets(budget_case)
    cases = _case_map(case_profile)
    if case_profile is not None and (deployment is None or case_profile != "baseline" and budget_case != "ordinary"):
        raise ValueError("invalid_routing_case_profile_combination")
    if deployment is not None and (type(deployment) is not str or deployment not in DEPLOYMENTS):
        raise ValueError("invalid_routing_deployment")
    implementation, configuration = ("nginx", "A") if deployment is None else deployment.split("-")
    commitment = {"profile": PROFILE, "boundary_revision": BOUNDARY_REVISION,
        "configuration": configuration, "budget_case": budget_case, "budgets": caps,
        "actions": {name: _underlying_selection(name, implementation, configuration, case_profile) for name in SELECTORS},
        "per_action_bounds": ACTION_BOUNDS, "owner_bounds": OWNER_BOUNDS,
        "bootstrap_max_bytes": BOOTSTRAP_MAX_BYTES, "evidence_bounds": EVIDENCE_BOUNDS,
        "topology_sha256": topology.digest() if deployment is None else topology.digest(configuration=configuration),
        "topology": "two-clients-router-two-frontends-four-veth-pairs-static-routes",
        "excluded_endpoint": {"target": "10.77.0.99", "port": 8080},
        "external_routes": False, "operator_selected_independent_actions": True}
    if deployment is None:
        return {"configuration": "A", "budget_case": budget_case, "selection_sha256": digest(commitment)}
    commitment.update(selection_version="2", implementation=implementation, deployment=deployment,
        boundary_revision=DEPLOYMENT_BOUNDARY_REVISION,
        http_private_transport="unix-socket" if implementation == "nginx" else "one-use-unconnected-tcp-descriptor",
        apache_handoff="daemon-to-launcher-to-frontend-exact-custody-before-reserved-delivery")
    if case_profile is not None:
        commitment.update(selection_version="3", boundary_revision=MATRIX_BOUNDARY_REVISION,
            case_profile=case_profile, case_map=cases,
            expected={name: _case_expectation(name, cases[name], matrix=True) for name in SELECTORS},
            declared_negative_stops_sequence="after-attempt-even-if-native-status-succeeded")
    return {"selection_version": "2" if case_profile is None else "3", "implementation": implementation,
            "configuration": configuration, "budget_case": budget_case, "selection_sha256": digest(commitment),
            **({} if case_profile is None else {"case_profile": case_profile})}


def validate_selection(value):
    if type(value) is not dict:
        raise ValueError("invalid_routing_selection")
    if set(value) == set(SELECTION_FIELDS):
        expected = selection(value["budget_case"])
    elif (set(value) == set(DEPLOYMENT_SELECTION_FIELDS) and value["selection_version"] == "2"
            and type(value["implementation"]) is str and type(value["configuration"]) is str):
        expected = selection(value["budget_case"], deployment=value["implementation"] + "-" + value["configuration"])
    elif (set(value) == set(MATRIX_SELECTION_FIELDS) and value["selection_version"] == "3"
            and type(value["implementation"]) is str and type(value["configuration"]) is str
            and type(value["case_profile"]) is str):
        expected = selection(value["budget_case"], deployment=value["implementation"] + "-" + value["configuration"],
                             case_profile=value["case_profile"])
    else:
        raise ValueError("invalid_routing_selection")
    if stock_http_spec.encode(value) != stock_http_spec.encode(expected):
        raise ValueError("invalid_routing_selection")
    return deepcopy(value)


def selection_from_identity(value):
    if type(value) is not dict:
        raise ValueError("invalid_routing_identity_selection")
    fields = (MATRIX_SELECTION_FIELDS if value.get("selection_version") == "3"
              else DEPLOYMENT_SELECTION_FIELDS if "selection_version" in value else SELECTION_FIELDS)
    if (any(key not in value for key in fields) or fields == SELECTION_FIELDS and "implementation" in value
            or fields != MATRIX_SELECTION_FIELDS and "case_profile" in value):
        raise ValueError("invalid_routing_identity_selection")
    return validate_selection({key: value[key] for key in fields})


def budgets(selected):
    return _budgets(validate_selection(selected)["budget_case"])


def action_bounds(selector):
    return dict(ACTION_BOUNDS[validate_selector(selector)])


def action(selected, selector):
    selected = validate_selection(selected)
    selector = validate_selector(selector)
    chosen = _underlying_selection(selector, selected.get("implementation", "nginx"), selected["configuration"],
                                   selected.get("case_profile"))
    value = underlying_contract(selector).action(chosen)
    value["action_id"] = str(uuid5(NAMESPACE_URL, PROFILE + ":" + selected["selection_sha256"] + ":" + selector))
    return value


def actions(selected):
    return {name: action(selected, name) for name in SELECTORS}


def action_selector(value, selected):
    if type(value) is Action:
        value = value.to_dict()
    if type(value) is not dict:
        raise ValueError("invalid_routing_action")
    for name, expected in actions(selected).items():
        # Canonical encoding also excludes bool-as-int and other loose equality.
        if value == expected and stock_http_spec.encode(value) == stock_http_spec.encode(expected):
            return name
    raise ValueError("invalid_routing_action")


def profile_allows(value, selected):
    try:
        if type(value) is not Action:
            return False
        action_selector(value, selected)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def scope(selected):
    selected = validate_selection(selected)
    return stock_http_spec._scope(selected["configuration"])


def limits(selected):
    validate_selection(selected)
    return {"max_steps": 4, "max_runtime_seconds": 60, "max_output_bytes": 26624}


def validate_limits(value, selected):
    expected = limits(selected)
    if (type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not int or value[key] != item for key, item in expected.items())):
        raise ValueError("invalid_routing_limits")
    return dict(value)


def policy_for_selection(selected, *, require_approval=True):
    selected = validate_selection(selected)
    values = list(actions(selected).values())
    version = "routing-" + base64.b32encode(bytes.fromhex(selected["selection_sha256"])).decode("ascii").rstrip("=").lower()
    return parse_policy({"schema_version": "1", "policy_version": version,
        "allowed_targets": list(dict.fromkeys(row["target"] for row in values)),
        "allowed_tools": list(dict.fromkeys(row["tool_id"] for row in values)),
        "allowed_ports": list(dict.fromkeys(row["parameters"]["port"] for row in values)), "allowed_methods": ["GET"],
        "max_timeout_seconds": 5, "max_output_bytes": 8192, "max_targets": 1,
        "require_approval": require_approval, "approval_ttl_seconds": 60})


def validate_policy(value, selected):
    policy = parse_policy(value)
    if policy.to_dict() != policy_for_selection(selected, require_approval=policy.require_approval).to_dict():
        raise ValueError("routing_policy_binding_changed")
    return policy


def validate_runtime(value, selected):
    selected = validate_selection(selected)
    if type(value) is not dict or set(value) != set(SELECTORS):
        raise ValueError("invalid_routing_runtime")
    # Case commitments differ even if the native daemon files happen to match.
    return {name: underlying_contract(name).validate_runtime(value[name],
                _underlying_selection(name, selected.get("implementation", "nginx"), selected["configuration"],
                                      selected.get("case_profile")))
            for name in SELECTORS}


def runtime_digests(value, selected):
    selected = validate_selection(selected)
    value = validate_runtime(value, selected)
    per_action = {name: underlying_contract(name).runtime_digests(value[name],
                    _underlying_selection(name, selected.get("implementation", "nginx"), selected["configuration"],
                                          selected.get("case_profile")))
                  for name in SELECTORS}
    return {"runtime_sha256": digest(value), "runtimes": per_action}


def validate_runtime_digests(value):
    if type(value) is not dict or set(value) != set(SELECTORS):
        raise ValueError("invalid_routing_runtime_digests")
    for selector, row in value.items():
        if type(row) is not dict or set(row) != {"daemon_runtime_sha256", "client_runtime_sha256"}:
            raise ValueError("invalid_routing_runtime_digests")
        for name, item in row.items():
            if selector == "http_headers" and name == "client_runtime_sha256":
                if item is not None:
                    raise ValueError("invalid_routing_header_runtime")
            elif type(item) is not str or not _HASH.fullmatch(item):
                raise ValueError("invalid_routing_runtime_digest")
    return deepcopy(value)


def runtime_source_mounts(value, selected):
    selected = validate_selection(selected)
    value = validate_runtime(value, selected)
    mounts = set()
    for name in SELECTORS:
        chosen = _underlying_selection(name, selected.get("implementation", "nginx"), selected["configuration"],
                                       selected.get("case_profile"))
        mounts.update(underlying_contract(name).runtime_source_mounts(value[name], chosen))
    destinations = {}
    for source, destination in mounts:
        if destination in destinations and destinations[destination] != source:
            raise ValueError("routing_runtime_mount_collision")
        destinations[destination] = source
    return sorted(mounts)


def inspect_runtime(selected, control):
    from . import stock_ssh_runtime
    from . import stock_http_client_runtime, stock_ssh_client_runtime
    selected = validate_selection(selected)
    result = {}
    for name in SELECTORS:
        control.check()
        chosen = underlying_selection(name, selected)
        daemon = http.implementation_runtime(http_implementation(selected)) if name.startswith("http_") else stock_ssh_runtime
        client = stock_http_client_runtime if name.startswith("http_") else stock_ssh_client_runtime
        result[name] = {"daemon": daemon.inspect_runtime(selected["configuration"], chosen["case"], control),
                        "client": client.inspect_client_runtime(chosen, control)}
    return validate_runtime(result, selected)


def identity(selected, session_id, runtime, *, instance_id=None):
    value = {"version": "1", "profile": PROFILE, "instance_id": str(uuid4()) if instance_id is None else instance_id,
             "session_id": session_id, **validate_selection(selected), **runtime_digests(runtime, selected)}
    return validate_identity(value, selection=selected, session_id=session_id, runtime=runtime)


def validate_identity(value, *, selection=None, session_id=None, runtime=None):
    chosen = selection_from_identity(value)
    fields = {"version", "profile", "instance_id", "session_id", *chosen, "runtime_sha256", "runtimes"}
    if type(value) is not dict or set(value) != fields or value["version"] != "1" or value["profile"] != PROFILE:
        raise ValueError("invalid_routing_identity")
    for key in ("instance_id", "session_id"):
        if type(value[key]) is not str or str(UUID(value[key])) != value[key]:
            raise ValueError("invalid_routing_identity")
    if ((selection is not None and chosen != validate_selection(selection))
            or (session_id is not None and value["session_id"] != session_id)):
        raise ValueError("routing_identity_binding_changed")
    if type(value["runtime_sha256"]) is not str or not _HASH.fullmatch(value["runtime_sha256"]):
        raise ValueError("invalid_routing_runtime_digest")
    validate_runtime_digests(value["runtimes"])
    if runtime is not None and any(value[key] != item for key, item in runtime_digests(runtime, chosen).items()):
        raise ValueError("routing_identity_runtime_changed")
    return deepcopy(value)
