"""Operator scope is literal, detached and closed before owned execution."""

import copy
import hashlib
import ipaddress
import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import configurable_scope as scope
from recon_cockpit.secure_agent import models


def manifest():
    return {"schema_version": "1", "scope_id": "owned-http-ssh-test",
            "http": {"target": "10.77.0.10", "port": 8080, "path": "/portal/index.html"},
            "ssh": {"target": "10.77.0.20", "port": 2222}}


@pytest.mark.parametrize("filename", ["secure-agent-configurable-scope.json",
                                     "secure-agent-configurable-scope-alternate.json"])
def test_shipped_scopes_are_canonical_and_remain_offline_data(filename):
    raw = (Path(__file__).parents[1] / "examples" / filename).read_bytes()
    value = scope.load_scope(raw)
    assert scope.load_scope(scope.encode(value)) == value
    assert scope.scope_digest(value) == hashlib.sha256(scope.encode(value)).hexdigest()
    assert set(value) == {"schema_version", "scope_id", "http", "ssh"}
    assert len(raw) < scope.MAX_SCOPE_BYTES


def test_validation_and_endpoint_access_do_not_share_mutable_caller_state():
    original = manifest()
    expected = copy.deepcopy(original)
    validated = scope.validate_scope(original)
    http = scope.endpoint(original, "http")
    ssh = scope.endpoint(original, "ssh")
    original["http"]["path"] = "/changed"
    original["ssh"]["target"] = "10.77.0.99"
    assert validated == expected
    assert http == expected["http"] and ssh == expected["ssh"]
    validated["http"]["port"] = 8081
    http["path"] = "/other"
    ssh["port"] = 2223
    assert original["http"]["port"] == 8080 and original["ssh"]["port"] == 2222
    assert expected["http"]["path"] == "/portal/index.html"


def test_reordered_and_whitespace_json_has_one_canonical_digest():
    value = manifest()
    reordered = dict(reversed(list(value.items())))
    reordered["http"] = dict(reversed(list(value["http"].items())))
    assert scope.encode(value) == scope.encode(reordered)
    assert scope.scope_digest(value) == scope.scope_digest(scope.load_scope(json.dumps(reordered, indent=4)))
    assert scope.encode(value) == json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.mark.parametrize("field,value", [("scope_id", "changed"), ("http.target", "10.77.0.11"),
                                        ("http.port", 8081), ("http.path", "/changed"),
                                        ("ssh.target", "10.77.0.21"), ("ssh.port", 2223)])
def test_each_operator_field_is_bound_to_scope_digest(field, value):
    before = manifest()
    after = copy.deepcopy(before)
    parts = field.split(".")
    destination = after if len(parts) == 1 else after[parts[0]]
    destination[parts[-1]] = value
    assert scope.scope_digest(before) != scope.scope_digest(after)


@pytest.mark.parametrize("value", [None, [], (), "scope", True, 1])
def test_scope_must_be_an_exact_object(value):
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("field", ["schema_version", "scope_id", "http", "ssh"])
def test_each_scope_field_is_required(field):
    value = manifest()
    del value[field]
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("field", ["credentials", "argv", "capabilities", "limits", "live_calls_enabled",
                                  "approved", "allowed_targets", "policy", "metadata"])
def test_scope_cannot_carry_extra_authority_or_tool_configuration(field):
    value = manifest()
    value[field] = True
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("version", [None, True, 1, 1.0, "01", "2"])
def test_schema_version_has_no_coercion(version):
    value = manifest()
    value["schema_version"] = version
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("name", ["http", "ssh"])
@pytest.mark.parametrize("value", [None, [], True, "10.77.0.10:8080"])
def test_endpoints_must_be_objects(name, value):
    document = manifest()
    document[name] = value
    with pytest.raises(ValueError):
        scope.validate_scope(document)


@pytest.mark.parametrize("name,field", [("http", "target"), ("http", "port"), ("http", "path"),
                                        ("ssh", "target"), ("ssh", "port")])
def test_each_endpoint_field_is_required(name, field):
    value = manifest()
    del value[name][field]
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("name", ["http", "ssh"])
@pytest.mark.parametrize("field", ["url", "method", "timeout_seconds", "username", "password", "argv"])
def test_endpoint_extra_fields_are_rejected(name, field):
    value = manifest()
    value[name][field] = "untrusted"
    with pytest.raises(ValueError):
        scope.validate_scope(value)


def test_ssh_cannot_smuggle_http_path():
    value = manifest()
    value["ssh"]["path"] = "/"
    with pytest.raises(ValueError):
        scope.validate_scope(value)


@pytest.mark.parametrize("value", ["", "a" * 49, "UPPER", "has space", "has_under", "-prefix", "suffix-",
                                   "two--hyphens", ".", "../scope", "scope\n", "á", "０", True, 1, None])
def test_scope_id_is_a_bounded_ascii_slug(value):
    document = manifest()
    document["scope_id"] = value
    with pytest.raises(ValueError):
        scope.validate_scope(document)


@pytest.mark.parametrize("value", ["a", "0", "lab-1", "a" * 48])
def test_scope_slug_boundaries_are_accepted(value):
    document = manifest()
    document["scope_id"] = value
    assert scope.validate_scope(document)["scope_id"] == value


@pytest.mark.parametrize("name", ["http", "ssh"])
@pytest.mark.parametrize("target", ["127.0.0.1", "0.0.0.0", "169.254.1.2", "100.64.0.1", "192.0.2.1",
                                    "8.8.8.8", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                                    "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0",
                                    "10.77.0.10/32", "10.77.0.0/24", "host.local", "http://10.77.0.10",
                                    "10.77.0.10:8080", "::1", "::ffff:10.77.0.10", "fd00::1",
                                    "10.077.0.10", "010.77.0.10", "10.77.10", "0x0a4d000a", "172818442",
                                    " 10.77.0.10", "10.77.0.10\n", "10.77.0.10%eth0", "１０.77.0.10",
                                    172818442, True, None])
def test_only_literal_canonical_rfc1918_ipv4_targets_are_accepted(name, target):
    document = manifest()
    document[name]["target"] = target
    with pytest.raises(ValueError):
        scope.validate_scope(document)


@pytest.mark.parametrize("target", ["10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
                                    "192.168.0.0", "192.168.255.255"])
def test_private_network_boundaries_are_literal_host_selections(target):
    document = manifest()
    document["http"]["target"] = target
    assert scope.endpoint(document, "http")["target"] == target


@pytest.mark.parametrize("name", ["http", "ssh"])
@pytest.mark.parametrize("port", [None, False, True, 0, -1, 22, 1023, 65535, 65536, 8080.0, "8080", []])
def test_ports_are_unprivileged_bounded_integers_without_coercion(name, port):
    document = manifest()
    document[name]["port"] = port
    with pytest.raises(ValueError):
        scope.validate_scope(document)


@pytest.mark.parametrize("port", [1024, 65534])
def test_port_boundaries_are_accepted(port):
    document = manifest()
    document["http"]["port"] = port
    assert scope.endpoint(document, "http")["port"] == port


@pytest.mark.parametrize("path", ["", "portal", "//host/path", "/a//b", "http://10.77.0.10/path", "/?x=1",
                                  "/a#b", "/%2e%2e/x", "/%41", "/./", "/../", "/a/../b", "/a/.",
                                  "/a/..", "/a\\b", "/a;b", "/a:b", "/a@b", "/a b", "/a\tb", "/a\r\nb",
                                  "/a\x00b", "/é", "/" + "x" * 128, True, 1, None])
def test_http_paths_are_bounded_unambiguous_origin_form(path):
    document = manifest()
    document["http"]["path"] = path
    with pytest.raises(ValueError):
        scope.validate_scope(document)


@pytest.mark.parametrize("path", ["/", "/index.html", "/.well-known/security.txt", "/a_b-1/~name/",
                                  "/" + "x" * 127])
def test_safe_http_path_boundaries_are_accepted(path):
    document = manifest()
    document["http"]["path"] = path
    assert scope.endpoint(document, "http")["path"] == path


def test_duplicate_endpoints_are_rejected_but_shared_host_or_port_is_valid():
    value = manifest()
    value["ssh"] = {"target": value["http"]["target"], "port": value["http"]["port"]}
    with pytest.raises(ValueError, match="^configurable_scope_endpoints_collide$"):
        scope.validate_scope(value)
    value["ssh"]["port"] += 1
    assert scope.validate_scope(value) == value
    value["ssh"] = {"target": "10.77.0.20", "port": value["http"]["port"]}
    assert scope.validate_scope(value) == value


@pytest.mark.parametrize("name", ["http", "ssh"])
@pytest.mark.parametrize("http,ssh", [
    (("10.77.0.10", 8080), ("10.77.0.20", 2222)),
    (("10.77.0.10", 8080), ("10.77.0.10", 8081)),
    (("10.77.0.10", 8080), ("10.77.0.20", 8080)),
    (("10.255.255.254", 65534), ("172.31.255.254", 1024)),
    (("10.255.255.254", 1024), ("192.168.255.254", 1025)),
])
def test_witnesses_are_unique_and_forbidden_to_current_action_even_at_collisions(name, http, ssh):
    value = manifest()
    for label, pair in (("http", http), ("ssh", ssh)):
        value[label].update(target=pair[0], port=pair[1])
    current = http if name == "http" else ssh
    other = ssh if name == "http" else http
    witnesses = scope.witness_addresses(value, name)
    assert type(witnesses) is tuple and all(type(row) is tuple for row in witnesses)
    assert len(witnesses) == len(set(witnesses)) == 3
    assert current not in witnesses
    assert witnesses[0] == other
    assert witnesses[1][0] not in {http[0], ssh[0]} and witnesses[1][1] == current[1]
    assert witnesses[2][0] == current[0] and witnesses[2][1] not in {http[1], ssh[1]}
    assert all(ipaddress.IPv4Address(target).is_private and 1024 <= port <= 65534
               for target, port in witnesses)
    value[name]["port"] = 12345
    assert witnesses[1][1] == current[1]


@pytest.mark.parametrize("name", ["HTTP", "smtp", "", True, None, [], {}])
@pytest.mark.parametrize("function", [scope.endpoint, scope.witness_addresses])
def test_service_selectors_are_exact_and_closed(function, name):
    with pytest.raises(ValueError):
        function(manifest(), name)


@pytest.mark.parametrize("function", [scope.encode, scope.scope_digest,
                                      lambda value: scope.endpoint(value, "http"),
                                      lambda value: scope.witness_addresses(value, "http")])
def test_every_public_consumer_revalidates_mutated_scope(function):
    value = scope.validate_scope(manifest())
    value["ssh"]["target"] = "8.8.8.8"
    with pytest.raises(ValueError):
        function(value)


@pytest.mark.parametrize("raw", [b'{"schema_version":"1","schema_version":"1"}',
                                 b'{"http":{"port":8080,"port":8080}}',
                                 b'{"ssh":{"target":"10.1.1.1","target":"10.1.1.1"}}',
                                 b"{\"http\":NaN}", b"{\"http\":Infinity}", b"{} trailing", b"[]", b"null",
                                 b"\xff", "\ud800", b"{}\x00", {}, None, bytearray(b"{}")])
def test_scope_json_rejects_duplicate_fields_extensions_and_encoding_aliases(raw):
    with pytest.raises(ValueError):
        scope.load_scope(raw)


def test_json_byte_limit_applies_before_json_parsing(monkeypatch):
    raw = scope.encode(manifest())
    padded = raw + b" " * (scope.MAX_SCOPE_BYTES - len(raw))
    assert scope.load_scope(padded) == manifest()
    assert scope.load_scope(padded.decode("ascii")) == manifest()
    monkeypatch.setattr(models, "load_json", lambda _raw: pytest.fail("over-limit JSON must not reach parser"))
    for oversized in (padded + b" ", padded.decode("ascii") + " ", "é" * (scope.MAX_SCOPE_BYTES // 2 + 1)):
        with pytest.raises(ValueError, match="^configurable_scope_json_limit$"):
            scope.load_scope(oversized)


def test_custom_python_mapping_string_and_integer_subclasses_are_rejected():
    class Mapping(dict):
        pass

    class Text(str):
        pass

    class Integer(int):
        pass

    candidates = [Mapping(manifest())]
    for field in ("scope_id", "schema_version"):
        candidate = manifest()
        candidate[field] = Text(candidate[field])
        candidates.append(candidate)
    for name in ("http", "ssh"):
        candidate = manifest()
        candidate[name] = Mapping(candidate[name])
        candidates.append(candidate)
        for field in candidate[name]:
            candidate = manifest()
            value = candidate[name][field]
            candidate[name][field] = Integer(value) if type(value) is int else Text(value)
            candidates.append(candidate)
    for candidate in candidates:
        with pytest.raises(ValueError):
            scope.validate_scope(candidate)
