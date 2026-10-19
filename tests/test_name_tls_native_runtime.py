"""Finite role partitions reject key exposure and source/image substitutions."""
from copy import deepcopy
import hashlib
from itertools import product

import pytest

from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent import name_tls_runtime as preparation
from recon_cockpit.secure_agent import name_tls_role_spec as roles
from recon_cockpit.secure_agent import name_tls_spec as spec
from recon_cockpit.secure_agent import name_tls_python_runtime as sources


def prepared(configuration="A", case="O1"):
    files = []
    for destination, source in {**preparation._native_files(), **{path: preparation.LIBRARY_ROOT + "ld-linux-x86-64.so.2"
            if path == preparation.INTERPRETER else path for path in preparation.DEPENDENCIES}}.items():
        files.append({"source": source, "destination": destination, "size": 128, "sha256": "a" * 64})
    files += [{"source": source, "destination": destination, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
              for source, destination, raw in spec.compiled_files(configuration, case)]
    value = {"schema_version": "1", "profile": preparation.PROFILE, "configuration": configuration,
        "case": case, "selection_sha256": spec.selection_digest(configuration, case), "interpreter": preparation.INTERPRETER,
        "dependency_kind": "fixed_four_elf_linked_dependencies_only", "executables": preparation._native_files(),
        "elf_dependencies": preparation._elf_dependencies(), "files": sorted(files, key=lambda row: row["destination"]),
        **{key: False for key in preparation._UNVERIFIED}}
    return preparation.validate_manifest(value)


def python_sources():
    return {"profile": sources.PROFILE, "files": [{"module": module, "destination": destination,
        "size": 128, "sha256": "a" * 64} for module, destination in sorted(sources.DESTINATIONS.items())]}


def bundle(preflight):
    return native.partitions(preflight, python_sources=python_sources())


@pytest.mark.parametrize("configuration,case", tuple(product(spec.CONFIGURATIONS, spec.CASES)))
def test_every_prepared_case_has_separate_exact_key_free_client_roles(configuration, case):
    value = bundle(prepared(configuration, case))
    assert native.validate_runtime(value) == value
    expected_counts = {"dns_daemon": 23, "web_daemon": 16, "dns_client": 40, "tls_client": 13}
    for role, manifest in value["roles"].items():
        assert len(manifest["files"]) == expected_counts[role]
        assert roles.dependencies(role) == value["preflight"]["elf_dependencies"][manifest["executable"]]
        assert all(row in value["preflight"]["files"] for row in manifest["files"])
        assert set(row["destination"] for row in manifest["files"]) == set(roles.destinations(role))
        if role.endswith("client"):
            assert not any(row["destination"].endswith(("server.key", "server.pem", "nginx.conf", "dnsmasq.conf"))
                           for row in manifest["files"])
            assert not any(row["destination"] in ("/tool/nginx", "/tool/dnsmasq") for row in manifest["files"])
    assert native.runtime_digest(value) != native.runtime_digest(bundle(prepared(configuration, "N14" if case != "N14" else "O1")))


@pytest.mark.parametrize("role", roles.ROLES)
def test_partition_is_detached_and_generated_bytes_match_pins(role):
    original = prepared()
    manifest = native.partition(original, role)
    files = {row["source"]: row for row in manifest["files"]}
    for source, raw in native.compiled_snapshots(manifest):
        assert files[source]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert files[source]["size"] == len(raw)
    manifest["files"][0]["sha256"] = "b" * 64
    assert original == prepared()


@pytest.mark.parametrize("role", roles.ROLES)
@pytest.mark.parametrize("change", ("source", "extra_image", "missing", "duplicate", "order", "preflight", "compiled", "cross_case", "cross_configuration", "role"))
def test_role_runtime_change_cannot_survive_host_partition_validation(role, change):
    value = bundle(prepared())
    manifest = value["roles"][role]
    if change == "source":
        manifest["files"][0]["source"] = "/tmp/libc.so.6"
    elif change == "extra_image":
        manifest["files"].append({"source": "/usr/bin/python3", "destination": "/tool/python", "size": 128, "sha256": "a" * 64})
    elif change == "missing":
        manifest["files"].pop()
    elif change == "duplicate":
        manifest["files"][-1] = deepcopy(manifest["files"][0])
    elif change == "order":
        manifest["files"].reverse()
    elif change == "preflight":
        manifest["preflight_sha256"] = "b" * 64
    elif change == "compiled":
        next(row for row in manifest["files"] if row["source"].startswith("compiled:"))["sha256"] = "b" * 64
    elif change == "cross_case":
        value["roles"][role] = native.partition(prepared("A", "N14"), role)
    elif change == "cross_configuration":
        value["roles"][role] = native.partition(prepared("B"), role)
    else:
        manifest["role"] = "web_daemon" if role != "web_daemon" else "dns_client"
    with pytest.raises(ValueError):
        native.validate_runtime(value)


@pytest.mark.parametrize("role", (True, None, {}, [], "dns", "parser", "../dns_daemon"))
def test_role_selection_is_closed_before_runtime_inspection(role):
    with pytest.raises(ValueError, match="role"):
        native.partition({}, role)


@pytest.mark.parametrize("field,value", (("size", True), ("size", 0), ("size", 16777217), ("sha256", "A" * 64), ("source", "/etc/shadow")))
def test_role_file_metadata_is_strict(field, value):
    manifest = native.partition(prepared(), "dns_client")
    manifest["files"][0][field] = value
    with pytest.raises(ValueError):
        roles.validate_manifest(manifest)


def test_key_free_role_spec_source_imports_only_standard_library():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(roles.__file__).read_text())
    assert not any(isinstance(node, ast.ImportFrom) and node.level for node in ast.walk(tree))
    assert "PRIVATE KEY-----" not in Path(roles.__file__).read_text()
    assert set(roles.COMPILED["tls_client"]) - set(roles.COMPILED["dns_client"]) == {roles.DATA + "ca.pem"}
