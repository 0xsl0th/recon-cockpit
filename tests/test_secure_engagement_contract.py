"""The 18 pinned offline contract gates; no store or execution authority."""

import copy
from datetime import datetime, timedelta
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import engagement_contract as contract


ENGAGEMENT = "c89351e7-2092-43de-845c-a91da43229af"


def roe():
    return {
        "schema_version": "1", "mode": "disconnected_owned",
        "scope": {"schema_version": "1", "scope_id": "owned-example",
                  "http": {"target": "10.77.0.10", "port": 8080, "path": "/"},
                  "ssh": {"target": "10.77.0.20", "port": 2222}},
        "allowed_profiles": ["configurable_http_headers_v1", "configurable_nmap_service_v1",
                             "configurable_ssh_host_keys_v1"],
        "excluded_services": [],
        "window": {"start_utc": "2026-10-20T00:00:00Z", "end_utc": "2026-10-21T00:00:00Z"},
        "limits": {"max_actions": 64, "max_connections": 256, "max_request_bytes": 1048576,
                   "max_response_bytes": 1048576, "max_action_ms": 60000,
                   "max_engagement_ms": 86400000},
    }


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def identifier(number):
    return f"00000000-0000-4000-8000-{number:012x}"


def request(operation="create", *, event=1, revision=None, generation=None, value=None):
    return {"schema_version": "1", "engagement_id": ENGAGEMENT, "event_id": identifier(event),
            "operation": operation, "expected_revision": revision, "expected_generation": generation,
            "roe": None if operation == "revoke" else (roe() if value is None else value)}


def export(revisions=2, revoked=True):
    """Independent example builder: plain JSON/hashlib, no production helpers."""
    rows = []
    events = []
    for number in range(1, revisions + 1):
        value = roe()
        value["scope"]["scope_id"] = f"revision-{number}"
        digest = hashlib.sha256(b"recon-engagement-roe-v1\0" + wire(value)).hexdigest()
        rows.append({"revision": number, "roe": value, "roe_sha256": digest})
        mutation = request("create" if number == 1 else "revise", event=number,
                           revision=None if number == 1 else number - 1,
                           generation=None if number == 1 else number - 2, value=value)
        events.append({"schema_version": "1", "engagement_id": ENGAGEMENT,
                       "event_id": identifier(number), "sequence": number,
                       "operation": mutation["operation"], "expected_revision": mutation["expected_revision"],
                       "expected_generation": mutation["expected_generation"], "revision": number,
                       "generation": number - 1, "status": "recorded", "roe_sha256": digest,
                       "request_sha256": hashlib.sha256(b"recon-engagement-request-v1\0" + wire(mutation)).hexdigest()})
    if revoked:
        mutation = request("revoke", event=revisions + 1, revision=revisions, generation=revisions - 1)
        events.append({"schema_version": "1", "engagement_id": ENGAGEMENT,
                       "event_id": identifier(revisions + 1), "sequence": revisions + 1,
                       "operation": "revoke", "expected_revision": revisions,
                       "expected_generation": revisions - 1, "revision": revisions,
                       "generation": revisions, "status": "revoked", "roe_sha256": rows[-1]["roe_sha256"],
                       "request_sha256": hashlib.sha256(b"recon-engagement-request-v1\0" + wire(mutation)).hexdigest()})
    return {"schema_version": "1", "kind": "engagement-record-export", "engagement_id": ENGAGEMENT,
            "state": {"revision": revisions, "generation": revisions - 1 + int(revoked),
                      "status": "revoked" if revoked else "recorded", "last_sequence": len(events)},
            "revisions": rows, "events": events}


def refused(function, value, code=None):
    with pytest.raises(contract.EngagementError) as error:
        function(value)
    assert error.value.code in contract.ERROR_CODES
    assert str(error.value) == error.value.code
    if code is not None:
        assert error.value.code == code


def mutate(value, path, replacement):
    result = copy.deepcopy(value)
    current = result
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = replacement
    return result


def test_valid_canonical_detached_roe(monkeypatch):
    original = roe()
    validated = contract.validate_roe(original)
    assert validated == original
    assert contract.canonical(validated) == wire(original)
    assert contract.decode_roe(wire(original).decode("ascii")) == original
    original["scope"]["http"]["target"] = "10.77.0.11"
    original["allowed_profiles"].clear()
    original["limits"]["max_actions"] = 1
    assert validated == roe()
    validated["window"]["start_utc"] = "changed"
    assert contract.validate_roe(roe()) == roe()
    original = roe()
    scope_validator = contract.validate_scope
    def mutate_during_validation(value):
        result = scope_validator(value)
        original["window"]["start_utc"] = "changed-during-validation"
        original["limits"].clear()
        return result
    monkeypatch.setattr(contract, "validate_scope", mutate_during_validation)
    assert contract.validate_roe(original) == roe()


def test_strict_json_forms():
    raw = wire(roe())
    for bad in (b"\xff", raw + b"{}", b"\xef\xbb\xbf" + raw,
                raw.replace(b'"schema_version":"1"', b'"schema_version":"1","schema_version":"1"', 1),
                raw.replace(b'"max_actions":64', b'"max_actions":64.0'),
                raw.replace(b'"max_actions":64', b'"max_actions":NaN'),
                raw.replace(b'"max_actions":64', b'"max_actions":Infinity'),
                raw.replace(b'"max_actions":64', b'"max_actions":-Infinity'),
                raw.replace(b'"owned-example"', b'"\\ud800"'), b"[" * 13 + b"0" + b"]" * 13):
        refused(contract.decode_roe, bad)
    assert contract.decode_roe(b" \n" + raw + b"\t") == roe()
    for bad in (None, bytearray(raw), memoryview(raw), 1):
        refused(contract.decode_roe, bad)


def test_exact_fields_and_types():
    value = roe()
    objects = [(), ("scope",), ("scope", "http"), ("scope", "ssh"), ("window",), ("limits",)]
    for path in objects:
        target = value
        for key in path:
            target = target[key]
        for key in target:
            bad = copy.deepcopy(value)
            nested = bad
            for part in path:
                nested = nested[part]
            del nested[key]
            refused(contract.validate_roe, bad, "engagement_invalid_roe")
        bad = copy.deepcopy(value)
        nested = bad
        for part in path:
            nested = nested[part]
        nested["unexpected"] = "must-not-echo"
        refused(contract.validate_roe, bad, "engagement_invalid_roe")
    for path, bad_values in [
        (("schema_version",), [1, True, None]),
        (("mode",), [True, "attached"]),
        (("scope", "http", "port"), [True, "8080", 8080.0]),
        (("limits", "max_actions"), [True, False, "1", 1.0]),
        (("allowed_profiles",), [("configurable_http_headers_v1",), "configurable_http_headers_v1"]),
        (("scope",), [[], None]),
    ]:
        for bad in bad_values:
            refused(contract.validate_roe, mutate(value, path, bad), "engagement_invalid_roe")
    class Mapping(dict):
        pass
    refused(contract.validate_roe, Mapping(value))


def test_uuid_canonical_forms():
    value = request()
    assert contract.validate_request(value) == value
    variants = [ENGAGEMENT.upper(), ENGAGEMENT.replace("-", ""), "urn:uuid:" + ENGAGEMENT,
                "{" + ENGAGEMENT + "}", ENGAGEMENT[:14] + "1" + ENGAGEMENT[15:],
                ENGAGEMENT[:19] + "7" + ENGAGEMENT[20:], "", True, 0, None]
    for field in ("engagement_id", "event_id"):
        for bad in variants:
            refused(contract.validate_request, mutate(value, (field,), bad))


def test_byte_and_depth_limits(monkeypatch):
    raw = wire(roe())
    padded = raw + b" " * (4096 - len(raw))
    assert contract.decode_roe(padded) == roe()
    refused(contract.decode_roe, padded + b" ", "engagement_limit_exceeded")
    nested = 0
    for _ in range(12):
        nested = [nested]
    assert contract.canonical(nested) == b"[" * 12 + b"0" + b"]" * 12
    refused(contract.canonical, [nested], "engagement_limit_exceeded")
    for validator, value, maximum, malformed in [
        (contract.validate_request, request(), 8192, "engagement_invalid_input"),
        (contract.validate_export, export(), 524288, "engagement_invalid_export"),
    ]:
        value["padding"] = ""
        value["padding"] = "a" * (maximum - len(wire(value)))
        assert len(wire(value)) == maximum
        refused(validator, value, malformed)
        value["padding"] += "a"
        refused(validator, value, "engagement_limit_exceeded")
    largest = export(64, True)
    assert len(wire(largest)) < 524288
    assert contract.validate_export(largest) == largest
    # A late nested validator must stop before doing work, not receive a fresh
    # two-second allowance and only fail at the outer return boundary.
    clock = [100.0]
    scope_calls = []
    validate_roe, validate_scope = contract.validate_roe, contract.validate_scope
    def delayed_roe(value):
        clock[0] = 102.1
        return validate_roe(value)
    def tracked_scope(value):
        scope_calls.append(True)
        return validate_scope(value)
    with monkeypatch.context() as patch:
        patch.setattr(contract.time, "monotonic", lambda: clock[0])
        patch.setattr(contract, "validate_roe", delayed_roe)
        patch.setattr(contract, "validate_scope", tracked_scope)
        refused(contract.validate_request, request(), "engagement_timeout")
        assert scope_calls == []
        # Error exits must reset the ContextVar for a later independent call.
        patch.setattr(contract, "validate_roe", validate_roe)
        clock[0] = 200.0
        assert contract.validate_request(request()) == request()
        assert scope_calls == [True]
        # A copied parent context must not govern a fresh child's operation.
        parent_pid = contract.os.getpid()
        clock[0] = 100.0
        with contract._using_deadline(102.0):
            patch.setattr(contract.os, "getpid", lambda: parent_pid + 1)
            clock[0] = 200.0
            assert contract.validate_roe(roe()) == roe()
            patch.setattr(contract.os, "getpid", lambda: parent_pid)
            clock[0] = 100.0


def test_disconnected_scope_targets():
    for service in ("http", "ssh"):
        for target in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "100.64.0.1", "172.32.0.1",
                       "example.test", "10.077.0.10", "::1", "::ffff:10.77.0.10", True):
            refused(contract.validate_roe, mutate(roe(), ("scope", service, "target"), target))
        for port in (0, 1023, 65535, True, "2222"):
            refused(contract.validate_roe, mutate(roe(), ("scope", service, "port"), port))
        for target in ("10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"):
            value = mutate(roe(), ("scope", service, "target"), target)
            assert contract.validate_roe(value) == value
        for port in (1024, 65534):
            value = mutate(roe(), ("scope", service, "port"), port)
            assert contract.validate_roe(value) == value


def test_scope_path_and_endpoint_collision():
    for path in ("", "status", "/../status", "/./status", "/a//b", "/a/..", "/%2e%2e/a",
                 "/?x=1", "/a#b", "/" + "x" * 128):
        refused(contract.validate_roe, mutate(roe(), ("scope", "http", "path"), path))
    for path in ("/", "/api/status", "/" + "x" * 127, "/a._~-/"):
        value = mutate(roe(), ("scope", "http", "path"), path)
        assert contract.validate_roe(value) == value
    value = roe()
    value["scope"]["ssh"] = {"target": "10.77.0.10", "port": 8080}
    refused(contract.validate_roe, value)
    for scope_id in ("UPPER", "-start", "end-", "two--parts", "x" * 49, "a b", "a/b"):
        refused(contract.validate_roe, mutate(roe(), ("scope", "scope_id"), scope_id))


def test_closed_profile_declarations():
    profiles = roe()["allowed_profiles"]
    for mask in range(1, 8):
        value = roe()
        value["allowed_profiles"] = [item for index, item in enumerate(profiles) if mask & (1 << index)]
        assert contract.validate_roe(value) == value
    for bad in ([], list(reversed(profiles)), [profiles[0], profiles[0]], ["*"], ["owned_name_http_v1"],
                ["http"], [1], profiles + ["extra"]):
        refused(contract.validate_roe, mutate(roe(), ("allowed_profiles",), bad))


def test_whole_service_exclusions():
    for selected in ([], ["http"], ["ssh"]):
        value = mutate(roe(), ("excluded_services",), selected)
        # Declaration retains profile membership; exclusion is an explicit override
        # for later runtime integration, not a new dispatch decision here.
        assert contract.validate_roe(value) == value
        assert contract.validate_roe(value)["allowed_profiles"] == roe()["allowed_profiles"]
    for bad in (["http", "ssh"], ["http", "http"], ["HTTP"], ["10.77.0.10"], [True], "http"):
        refused(contract.validate_roe, mutate(roe(), ("excluded_services",), bad))


def test_utc_window_grammar():
    for invalid in ("1999-12-31T00:00:00Z", "2100-01-01T00:00:00Z", "2026-02-29T00:00:00Z",
                    "2026-10-20T00:00:60Z", "2026-10-20T24:00:00Z", "2026-10-20T00:00:00+00:00",
                    "2026-10-20T00:00:00.0Z", "2026-10-20 00:00:00Z", "2026-1-20T00:00:00Z",
                    "２０２６-10-20T00:00:00Z", True, None):
        refused(contract.validate_roe, mutate(roe(), ("window", "start_utc"), invalid))
    for start, end in (("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z"),
                       ("2024-02-29T00:00:00Z", "2024-03-01T00:00:00Z"),
                       ("2099-12-30T00:00:00Z", "2099-12-31T00:00:00Z")):
        value = roe()
        value["window"] = {"start_utc": start, "end_utc": end}
        assert contract.validate_roe(value) == value


def test_window_duration_boundaries():
    origin = datetime(2026, 10, 20)
    for seconds in (1, 86400):
        value = roe()
        value["window"]["end_utc"] = (origin + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        value["limits"]["max_action_ms"] = min(60000, seconds * 1000)
        value["limits"]["max_engagement_ms"] = seconds * 1000
        assert contract.validate_roe(value) == value
    for seconds in (-1, 0, 86401):
        value = roe()
        value["window"]["end_utc"] = (origin + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        refused(contract.validate_roe, value)


def test_declared_limit_boundaries():
    maxima = roe()["limits"]
    for field, maximum in maxima.items():
        for invalid in (0, -1, maximum + 1, True, "1", 1.0):
            refused(contract.validate_roe, mutate(roe(), ("limits", field), invalid))
    value = roe()
    value["limits"] = dict.fromkeys(maxima, 1)
    assert contract.validate_roe(value) == value
    refused(contract.validate_roe, mutate(roe(), ("limits", "max_engagement_ms"), 59999))
    value = roe()
    value["window"]["end_utc"] = "2026-10-20T00:01:00Z"
    refused(contract.validate_roe, value)
    value["limits"]["max_engagement_ms"] = 60000
    assert contract.validate_roe(value) == value


def test_digest_domains_and_field_binding():
    value = roe()
    expected = hashlib.sha256(b"recon-engagement-roe-v1\0" + wire(value)).hexdigest()
    assert contract.roe_digest(value) == expected
    assert contract.ROE_DOMAIN.hex() == "7265636f6e2d656e676167656d656e742d726f652d763100"
    assert contract.REQUEST_DOMAIN.hex() == "7265636f6e2d656e676167656d656e742d726571756573742d763100"
    changes = [(('scope', 'scope_id'), 'other'), (('scope', 'http', 'target'), '10.77.0.11'),
               (('scope', 'http', 'port'), 8081), (('scope', 'http', 'path'), '/status'),
               (('scope', 'ssh', 'target'), '10.77.0.21'), (('scope', 'ssh', 'port'), 2223),
               (('allowed_profiles',), ['configurable_http_headers_v1']),
               (('excluded_services',), ['http'])]
    changes.extend((("limits", field), maximum - 1) for field, maximum in value["limits"].items())
    for path, replacement in changes:
        assert contract.roe_digest(mutate(value, path, replacement)) != expected
    shifted = copy.deepcopy(value)
    shifted["window"] = {"start_utc": "2026-10-21T00:00:00Z", "end_utc": "2026-10-22T00:00:00Z"}
    assert contract.roe_digest(shifted) != expected
    for path in (("schema_version",), ("mode",), ("scope", "schema_version")):
        refused(contract.roe_digest, mutate(value, path, "2"))
    mutation = request("revise", event=2, revision=1, generation=0)
    request_hash = hashlib.sha256(b"recon-engagement-request-v1\0" + wire(mutation)).hexdigest()
    assert contract.request_digest(mutation) == request_hash
    for path, replacement in [(('engagement_id',), identifier(44)), (('event_id',), identifier(45)),
                              (('expected_revision',), 2), (('expected_generation',), 1),
                              (('roe', 'limits', 'max_actions'), 1)]:
        assert contract.request_digest(mutate(mutation, path, replacement)) != request_hash
    assert contract.request_digest(request("revoke", event=2, revision=1, generation=0)) != request_hash


def test_normalized_request_shapes():
    for value in (request(), request("revise", event=2, revision=1, generation=0),
                  request("revoke", event=3, revision=64, generation=63)):
        assert contract.validate_request(value) == value
        output = contract.validate_request(value)
        if value["roe"] is not None:
            output["roe"]["limits"]["max_actions"] = 1
            assert value["roe"]["limits"]["max_actions"] == 64
        for field in value:
            bad = copy.deepcopy(value)
            del bad[field]
            refused(contract.validate_request, bad)
    for bad in (request("revise"), request("revoke"), request("create", revision=1),
                request("create", generation=0), request("unknown"),
                request("revise", revision=True, generation=0),
                request("revise", revision=1, generation=False),
                request("revise", revision=65, generation=0)):
        refused(contract.validate_request, bad)
    refused(contract.validate_request, mutate(request(), ("roe",), None))
    refused(contract.validate_request, mutate(request("revoke", revision=1, generation=0), ("roe",), roe()))


def test_export_reconstructs_history():
    for count, revoked in ((1, False), (1, True), (2, False), (2, True), (64, True)):
        value = export(count, revoked)
        assert contract.validate_export(value) == value
        assert contract.decode_export(wire(value)) == value
        detached = contract.validate_export(value)
        value["events"][0]["request_sha256"] = "0" * 64
        value["revisions"][0]["roe"]["scope"]["scope_id"] = "changed"
        assert detached == export(count, revoked)
    for raw in (wire(export()) + b"\n", b" " + wire(export()), json.dumps(export()).encode()):
        refused(contract.decode_export, raw, "engagement_invalid_export")


def test_export_hash_and_transition_tampering():
    value = export()
    changes = [(('revisions', 0, 'roe_sha256'), '0' * 64),
               (('revisions', 0, 'roe', 'scope', 'scope_id'), 'changed'),
               (('events', 0, 'request_sha256'), '0' * 64),
               (('events', 1, 'roe_sha256'), 'f' * 64),
               (('events', 1, 'expected_revision'), 2),
               (('events', 1, 'expected_generation'), 1),
               (('events', 0, 'revision'), True), (('events', 0, 'generation'), False),
               (('events', 0, 'sequence'), True), (('events', 1, 'status'), 'revoked'),
               (('events', 2, 'operation'), 'revise'),
               (('state', 'revision'), 1), (('state', 'generation'), 1),
               (('state', 'status'), 'recorded'), (('state', 'last_sequence'), 2)]
    for path, replacement in changes:
        refused(contract.validate_export, mutate(value, path, replacement), "engagement_invalid_export")
    # Even a recomputed request hash cannot make stale CAS a legal transition.
    bad = copy.deepcopy(value)
    bad["events"][1]["expected_revision"] = 2
    stale = request("revise", event=2, revision=2, generation=0, value=bad["revisions"][1]["roe"])
    bad["events"][1]["request_sha256"] = hashlib.sha256(b"recon-engagement-request-v1\0" + wire(stale)).hexdigest()
    refused(contract.validate_export, bad)


def test_export_order_identity_and_caps():
    value = export()
    for field in ("revisions", "events"):
        for items in ([], value[field][:-1], value[field] + [value[field][-1]], list(reversed(value[field]))):
            refused(contract.validate_export, mutate(value, (field,), items))
    for path in (("engagement_id",), ("events", 0, "engagement_id"), ("events", 1, "event_id")):
        refused(contract.validate_export, mutate(value, path, identifier(1)))
    for path in (("state", "revision"), ("state", "generation"), ("state", "last_sequence")):
        refused(contract.validate_export, mutate(value, path, True))
    maximum = export(64, True)
    refused(contract.validate_export, mutate(maximum, ("revisions",), maximum["revisions"] + [maximum["revisions"][-1]]))
    refused(contract.validate_export, mutate(maximum, ("events",), maximum["events"] + [maximum["events"][-1]]))
    for path in ((), ("state",), ("revisions", 0), ("events", 0)):
        bad = copy.deepcopy(value)
        target = bad
        for key in path:
            target = target[key]
        target["extra"] = None
        refused(contract.validate_export, bad)


def test_closed_safe_error_codes():
    for code in contract.ERROR_CODES:
        error = contract.EngagementError(code)
        assert error.code == code
        assert str(error) == code
        assert error.args == (code,)
    for unsafe in ("secret-marker", "/private/path", "sqlite: detail", "", True, [], None):
        with pytest.raises(ValueError) as error:
            contract.EngagementError(unsafe)
        assert str(error.value) == "engagement_invalid_error_code"
    for bad in (float("nan"), float("inf"), 1.0, {"x": object()}, {1: "value"}, "\ud800", {"\ud800": "x"}):
        refused(contract.canonical, bad)
    cyclic = []
    cyclic.append(cyclic)
    refused(contract.canonical, cyclic, "engagement_limit_exceeded")
