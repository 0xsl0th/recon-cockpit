"""Finite name-binding proposals and commitments; none is execution authority."""

from copy import deepcopy
import base64
import hashlib
import re
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

from . import name_tls_public as public
from .models import Action, parse_action, parse_policy

PROFILE = public.PROFILE
BACKEND = "linux-authorized-owned-name-tls-v1"
BOUNDARY_REVISION = "six-networks-independent-dns-http-tls-owner-v1"
SLOTS = ("dns_1", "dns_2", "http", "tls")
SELECTORS = SLOTS
TOOL_IDS = {"dns": "owned_name_dns_v1", "http": "owned_name_http_v1", "tls": "owned_name_tls_v1"}
_HASH = re.compile(r"[a-f0-9]{64}\Z")
encode = public.encode
digest = public.digest
BOOTSTRAP_MAX_BYTES = 262144
EVIDENCE_BOUNDS = {"max_files": 24, "max_total_bytes": 4194304,
                   "max_json_bytes": 1048576, "max_json_depth": 64}
OWNER_BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 128,
                "retained_bytes": 524288}
ACTION_BOUNDS = {
    "dns": {"connections": 1, "dns_queries": 1, "http_requests": 0, "tls_handshakes": 0,
            "request_bytes": 512, "response_bytes": 4096, "output_bytes": 8192,
            "timeout_seconds": 3, "hard_action_seconds": 10},
    "http": {"connections": 1, "dns_queries": 0, "http_requests": 1, "tls_handshakes": 0,
             "request_bytes": 256, "response_bytes": 2048, "output_bytes": 2048,
             "timeout_seconds": 1, "hard_action_seconds": 8},
    "tls": {"connections": 1, "dns_queries": 0, "http_requests": 0, "tls_handshakes": 1,
            "request_bytes": 8192, "response_bytes": 16384, "output_bytes": 8192,
            "timeout_seconds": 5, "hard_action_seconds": 12},
}
_BUDGETS = {"actions": 3, "session_seconds": 60, "connections": 3,
            "dns_queries": 2, "http_requests": 1, "tls_handshakes": 1,
            "concurrent_connections": 1, "minimum_admission_interval_ms": 250,
            "request_bytes": 8960, "response_bytes": 22528, "output_bytes": 18432}
_PLANS = {
    "O1": ("dns_1",), "O2": ("dns_1", "http"), "O3": ("dns_1", "tls"),
    "O4": ("dns_1", "http", "tls"), "O5": ("dns_1", "http"),
    "R1": ("dns_1", "http"), "R2": ("dns_1",), "N1": ("dns_1", "dns_2"),
    "N2": ("dns_1",), "N3": ("dns_1",), "N4": (), "N5": ("dns_1",),
    "N6": ("dns_1",), "N7": ("dns_1",), "N8": ("dns_1",),
    "N9": ("dns_1",), "N10": ("dns_1",), "N11": ("dns_1", "tls"),
    "N12": ("dns_1", "tls"), "N13": ("dns_1", "tls"), "N14": ("dns_1",),
    "N15": ("dns_1",), "N16": ("dns_1", "tls"),
}
PROBE_CASES = ("N1", "N4", "N9", "N10", "N14", "N15")
BINDING_FIELDS = {"version", "owner_id", "owner_identity_sha256", "session_id",
    "configuration", "case", "selection_sha256", "runtime_identity_sha256",
    "observation_generation", "observation_sha256", "canonical_question",
    "original_answer_sha256", "delivered_answer_sha256", "singleton_allowed_ipv4",
    "observed_ttl_seconds", "observed_at_us", "expires_at_us", "binding_sha256"}


def operation(slot):
    if type(slot) is not str or slot not in SLOTS:
        raise ValueError("invalid_name_tls_slot")
    return "dns" if slot.startswith("dns_") else slot


def selector_role(slot):
    return operation(slot) + "_frontend"


def action_bounds(slot):
    return dict(ACTION_BOUNDS[operation(slot) if slot in SLOTS else slot])


def selection(configuration="A", case="O4", order="default"):
    public.validate_selection(configuration, case)
    if type(order) is not str or order not in ("default", "tls_first") or order == "tls_first" and case != "O4":
        raise ValueError("invalid_name_tls_order")
    fields = {"version": "1", "configuration": configuration, "case": case, "order": order}
    plan = ("dns_1", "tls", "http") if order == "tls_first" else _PLANS[case]
    commitment = {"profile": PROFILE, "boundary_revision": BOUNDARY_REVISION, **fields,
                  "preparation_sha256": public.PREPARATION_DIGESTS[configuration + "/" + case],
                  "native_contract_sha256": public.NATIVE_CONTRACT_SHA256,
                  "native_gates_sha256": public.NATIVE_GATES_SHA256,
                  "plan": plan, "attempt_slots": ("http", "tls") if case == "N14" else (),
                  "endpoints": public.endpoints(configuration), "budgets": _BUDGETS,
                  "action_bounds": ACTION_BOUNDS, "public_ca_sha256": public.PUBLIC_CA_SHA256,
                  "dns_argv": public.dns_argv(configuration, case),
                  "tls_argv": public.tls_argv(configuration, case),
                  "http_request_sha256": hashlib.sha256(public.request_bytes(configuration, case)).hexdigest()}
    return {**fields, "selection_sha256": digest(commitment)}


def validate_selection(value):
    if type(value) is not dict or set(value) != {"version", "configuration", "case", "order", "selection_sha256"}:
        raise ValueError("invalid_name_tls_selection")
    expected = selection(value["configuration"], value["case"], value["order"])
    if encode(value) != encode(expected):
        raise ValueError("invalid_name_tls_selection")
    return deepcopy(value)


def operation_plan(selected):
    selected = validate_selection(selected)
    return ("dns_1", "tls", "http") if selected["order"] == "tls_first" else _PLANS[selected["case"]]


def attempt_slots(selected):
    """Only typed negative probes; these never enter the owner's execute plan."""
    return ("http", "tls") if validate_selection(selected)["case"] == "N14" else ()


def budgets(selected):
    validate_selection(selected)
    return dict(_BUDGETS)


def limits(selected):
    validate_selection(selected)
    return {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18432}


def validate_limits(value, selected):
    if encode(value) != encode(limits(selected)):
        raise ValueError("invalid_name_tls_limits")
    return dict(value)


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value
    except ValueError:
        return False


def _hash(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def runtime_digest(runtime):
    if _hash(runtime):
        return runtime
    if type(runtime) is not dict:
        raise ValueError("invalid_name_tls_runtime_identity")
    return hashlib.sha256(public.encode(runtime, max_bytes=BOOTSTRAP_MAX_BYTES)).hexdigest()


def identity(selected, session_id, runtime, *, owner_id=None, instance_id=None):
    if owner_id is not None and instance_id is not None:
        raise ValueError("ambiguous_name_tls_owner_identity")
    value = {"version": "1", "profile": PROFILE, "owner_id": owner_id or instance_id or str(uuid4()),
             "session_id": session_id, "selection": validate_selection(selected),
             "runtime_identity_sha256": runtime_digest(runtime)}
    value["owner_identity_sha256"] = digest(value)
    return validate_identity(value, selection=selected, session_id=session_id, runtime=runtime)


new_identity = identity


def validate_identity(value, *, selection=None, session_id=None, runtime=None):
    fields = {"version", "profile", "owner_id", "session_id", "selection",
              "runtime_identity_sha256", "owner_identity_sha256"}
    if type(value) is not dict or set(value) != fields or value["version"] != "1" or value["profile"] != PROFILE:
        raise ValueError("invalid_name_tls_identity")
    chosen = validate_selection(value["selection"])
    if (not _uuid(value["owner_id"]) or not _uuid(value["session_id"])
            or not _hash(value["runtime_identity_sha256"]) or not _hash(value["owner_identity_sha256"])
            or digest({k: v for k, v in value.items() if k != "owner_identity_sha256"}) != value["owner_identity_sha256"]
            or selection is not None and chosen != validate_selection(selection)
            or session_id is not None and session_id != value["session_id"]
            or runtime is not None and runtime_digest(runtime) != value["runtime_identity_sha256"]):
        raise ValueError("name_tls_identity_binding_changed")
    return deepcopy(value)


def validate_binding(value, *, selected=None, identity=None):
    if type(value) is not dict or set(value) != BINDING_FIELDS or value["version"] != "1":
        raise ValueError("invalid_name_tls_binding")
    public.validate_selection(value["configuration"], value["case"])
    for key in ("owner_id", "session_id"):
        if not _uuid(value[key]):
            raise ValueError("invalid_name_tls_binding_identity")
    for key in ("owner_identity_sha256", "selection_sha256", "runtime_identity_sha256",
                "observation_sha256", "original_answer_sha256", "delivered_answer_sha256", "binding_sha256"):
        if not _hash(value[key]):
            raise ValueError("invalid_name_tls_binding_digest")
    ttl = 1 if value["case"] == "N14" else 60
    if (type(value["observation_generation"]) is not int or not 1 <= value["observation_generation"] <= 2
            or type(value["observed_ttl_seconds"]) is not int or value["observed_ttl_seconds"] != ttl
            or type(value["observed_at_us"]) is not int or not 0 <= value["observed_at_us"] < 60000000
            or type(value["expires_at_us"]) is not int
            or value["expires_at_us"] != min(60000000, value["observed_at_us"] + ttl * 1000000)
            or value["canonical_question"] != public.DNS_NAME + " IN A"
            or value["singleton_allowed_ipv4"] != public.endpoints(value["configuration"])["http"]["target"]
            or value["binding_sha256"] != digest({k: v for k, v in value.items() if k != "binding_sha256"})):
        raise ValueError("invalid_name_tls_binding_commitment")
    if selected is not None:
        chosen = validate_selection(selected)
        if any(value[k] != chosen[k] for k in ("configuration", "case", "selection_sha256")):
            raise ValueError("name_tls_binding_selection_changed")
    if identity is not None:
        owner = validate_identity(identity, selection=selected)
        if any(value[k] != owner[k] for k in ("owner_id", "owner_identity_sha256", "session_id", "runtime_identity_sha256")):
            raise ValueError("name_tls_binding_owner_changed")
    return deepcopy(value)


def _parameters(selected, owner, slot):
    selected = validate_selection(selected)
    owner = validate_identity(owner, selection=selected)
    op = operation(slot)
    endpoint = public.endpoints(selected["configuration"])["resolver" if op == "dns" else op]
    cap = action_bounds(slot)
    return {"port": endpoint["port"], "timeout_seconds": cap["timeout_seconds"],
            "max_output_bytes": cap["output_bytes"], "configuration": selected["configuration"],
            "case": selected["case"], "selection_sha256": selected["selection_sha256"],
            **{key: owner[key] for key in ("runtime_identity_sha256", "owner_id", "owner_identity_sha256", "session_id")},
            "operation_slot": slot}


def _action(selected, owner, slot, parameters):
    op = operation(slot)
    target = public.endpoints(selected["configuration"])["resolver" if op == "dns" else op]["target"]
    action_id = str(uuid5(NAMESPACE_URL, PROFILE + ":" + digest(parameters)))
    return parse_action({"schema_version": "1", "action_id": action_id, "tool_id": TOOL_IDS[op],
                         "target": target, "parameters": parameters,
                         "rationale": "One separately reviewed owned " + op + " operation."}).to_dict()


def dns_action(selected, owner, slot="dns_1"):
    if operation(slot) != "dns":
        raise ValueError("invalid_name_tls_dns_slot")
    p = _parameters(selected, owner, slot)
    p.update(question_name=public.DNS_NAME, question_class="IN", question_type="A")
    return _action(selected, owner, slot, p)


def service_action(selected, owner, slot, binding):
    if operation(slot) not in ("http", "tls"):
        raise ValueError("invalid_name_tls_service_slot")
    binding = validate_binding(binding, selected=selected, identity=owner)
    p = _parameters(selected, owner, slot)
    p.update({key: binding[key] for key in ("binding_sha256", "observation_sha256", "observation_generation",
                                           "observed_ttl_seconds", "observed_at_us", "expires_at_us")})
    p.update(observed_answer_sha256=binding["delivered_answer_sha256"], canonical_name=public.LOGICAL_NAME)
    if slot == "http":
        endpoint = public.endpoints(selected["configuration"])["http"]
        p.update(method="GET", path=endpoint["path"], host=f"{public.LOGICAL_NAME}:{endpoint['port']}")
    else:
        p.update(sni=public.LOGICAL_NAME, expected_certificate_name=public.LOGICAL_NAME,
                 public_ca_sha256=public.PUBLIC_CA_SHA256, tls_version="TLSv1.3",
                 cipher_suite="TLS_AES_256_GCM_SHA384", group="P-256")
    return _action(selected, owner, slot, p)


def action_selector(value, selected):
    chosen = validate_selection(selected)
    value = parse_action(value.to_dict() if type(value) is Action else value)
    p = value.parameters.to_dict()
    if value.tool_id not in TOOL_IDS.values():
        raise ValueError("invalid_name_tls_tool")
    slot = p["operation_slot"]
    if any(p[key] != chosen[key] for key in ("configuration", "case", "selection_sha256")):
        raise ValueError("name_tls_action_selection_changed")
    op = operation(slot)
    endpoint = public.endpoints(chosen["configuration"])["resolver" if op == "dns" else op]
    if value.tool_id != TOOL_IDS[op] or value.target != endpoint["target"] or value.action_id != str(uuid5(NAMESPACE_URL, PROFILE + ":" + digest(p))):
        raise ValueError("name_tls_action_binding_changed")
    return slot


def validate_action(value, selected, identity, binding=None):
    owner = validate_identity(identity, selection=selected)
    slot = action_selector(value, selected)
    raw = value.to_dict() if type(value) is Action else value
    expected = dns_action(selected, owner, slot) if operation(slot) == "dns" else service_action(selected, owner, slot, binding)
    if encode(raw) != encode(expected):
        raise ValueError("name_tls_action_binding_changed")
    return deepcopy(raw)


def profile_allows(value, selected, *, session_id=None):
    try:
        slot = action_selector(value, selected)
        raw = value.to_dict() if type(value) is Action else value
        if session_id is not None and raw["parameters"]["session_id"] != session_id:
            return False
        return slot in operation_plan(selected) + attempt_slots(selected)
    except (ValueError, TypeError, KeyError):
        return False


def policy_for_selection(selected, *, require_approval=True):
    selected = validate_selection(selected)
    endpoints = public.endpoints(selected["configuration"])
    version = "name-tls-" + base64.b32encode(bytes.fromhex(selected["selection_sha256"])).decode("ascii").rstrip("=").lower()
    return parse_policy({"schema_version": "1", "policy_version": version,
        "allowed_targets": [endpoints["resolver"]["target"], endpoints["http"]["target"]],
        "allowed_tools": list(TOOL_IDS.values()),
        "allowed_ports": [endpoints[k]["port"] for k in ("resolver", "http", "tls")],
        "allowed_methods": ["GET"], "max_timeout_seconds": 5, "max_output_bytes": 8192,
        "max_targets": 1, "require_approval": require_approval, "approval_ttl_seconds": 60})


policy = policy_for_selection


def validate_policy(value, selected):
    policy = parse_policy(value.to_dict() if hasattr(value, "to_dict") else value)
    if encode(policy.to_dict()) != encode(policy_for_selection(selected, require_approval=policy.require_approval).to_dict()):
        raise ValueError("name_tls_policy_binding_changed")
    return policy
