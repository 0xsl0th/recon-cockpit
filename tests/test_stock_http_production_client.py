"""Production client commitments remain distinct from diagnostic permissions."""

from copy import deepcopy
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import stock_http_client_runtime as client
from recon_cockpit.secure_agent import stock_http_execution as diagnostic
from recon_cockpit.secure_agent import stock_http_production_execution as production
from recon_cockpit.secure_agent import stock_http_production_contract as contract
from recon_cockpit.secure_agent import stock_http_spec as spec
from test_stock_http_production_authority import envelope


@pytest.mark.parametrize("implementation", ["nginx", "apache"])
@pytest.mark.parametrize("case", ["O1", "O5", "O6"])
def test_confined_client_closure_imports_and_verifies_production_without_repository(tmp_path, implementation, case):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(client.__file__).parent
    for module in (*client.MODULES, *client.PRODUCTION_MODULES):
        shutil.copyfile(source / (module + ".py"), package / (module + ".py"))
    value = envelope(implementation=implementation, case=case)
    raw = spec.encode(value)
    code = """import hashlib,sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent.stock_http_production_execution import consume_launch
from recon_cockpit.secure_agent import stock_http_client_worker
raw=sys.argv[2].encode('ascii')
request,deadline,namespaces,digest=consume_launch(raw,sys.argv[3],hashlib.sha256(raw).hexdigest(),now=100)
assert request['selection']['implementation']==sys.argv[4]
assert deadline==150
assert stock_http_client_worker.__file__.startswith(sys.argv[1])
print('production-client-closed-import-ok')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), raw.decode("ascii"),
        value["launch"]["nonce"], implementation], capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"production-client-closed-import-ok\n"


@pytest.mark.parametrize("implementation", ["nginx", "apache"])
def test_production_commitment_never_redeems_as_diagnostic(implementation):
    value = envelope(implementation=implementation)
    raw = spec.encode(value)
    nonce = value["launch"]["nonce"]
    digest = hashlib.sha256(raw).hexdigest()
    production.consume_launch(raw, nonce, digest, now=100)
    with pytest.raises(ValueError):
        diagnostic.consume_launch(raw, nonce, digest, now=100)
    changed = deepcopy(value)
    changed["selection"]["implementation"] = "nginx" if implementation == "apache" else "apache"
    raw = spec.encode(changed)
    with pytest.raises(ValueError):
        production.consume_launch(raw, nonce, hashlib.sha256(raw).hexdigest(), now=100)


@pytest.mark.parametrize("implementation", ["nginx", "apache"])
def test_production_client_mounts_no_daemon_or_private_namespace_capability(monkeypatch, implementation):
    monkeypatch.setattr(client, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(identity={"profile": contract.PROFILE}, _namespace_fds=(30, 31))
    argv = client._command(lab, ("/stdlib", [("/usr/sbin/apache2", "/usr/sbin/apache2"),
        ("/usr/sbin/nginx", "/usr/sbin/nginx"), ("/usr/bin/python3", "/usr/bin/python3")]),
        None, [], "a" * 64, "b" * 64)
    mounts = [argv[i+1:i+3] for i,v in enumerate(argv) if v == "--ro-bind"]
    assert all(Path(src).name not in {"apache2", "nginx"} for src,dst in mounts)
    assert all(dst not in {"/peer", "/scratch", "/stock-peer"} for src,dst in mounts)
    assert "--bind-fd" not in argv and "--bind" not in argv
    clear = argv.index(client._CLOSE_EXCEPT)
    assert argv[clear+1] == "0,1,2"
    selected = contract.selection(implementation, "A", "O1")
    assert set(client.boundary_names(selected)) == set(client.BOUNDARY_NAMES) | {"private_tcp_listener_blocked"}
    assert client.validate_client_runtime(None, selected) is None


@pytest.mark.parametrize("implementation", ["nginx", "apache"])
@pytest.mark.parametrize("configuration,case", [("A", "O5"), ("A", "O6"), ("B", "O5"), ("B", "O6")])
def test_production_recognition_keeps_exact_native_argv_and_sealed_mounts(monkeypatch, implementation, configuration, case):
    from recon_cockpit.secure_agent import network_tools_runtime as native
    from recon_cockpit.secure_agent import stock_http_production_nmap_runtime as runtime
    from recon_cockpit.secure_agent.stock_http_client_worker import argv_for
    monkeypatch.setattr(client, "_trusted_program", lambda name: "/usr/bin/" + name)
    value = envelope(implementation=implementation, config=configuration, case=case)
    raw = spec.encode(value)
    request, _, _, digest = production.consume_launch(raw, value["launch"]["nonce"], hashlib.sha256(raw).hexdigest(), now=100)
    manifest = value["runtime"]["client"]
    assert digest == runtime.manifest_digest(manifest)
    expected = list(native.FIXED_ARGV[native.NMAP_SERVICE])
    expected[expected.index("-p") + 1] = str(request["parameters"]["port"])
    expected[expected.index("--version-intensity") + 1] = "1"
    expected[-1] = request["target"]
    assert argv_for(request) == tuple(expected)
    entries = runtime.runtime_files(manifest)
    descriptors = list(range(40, 40 + len(entries)))
    lab = SimpleNamespace(identity=value["identity"], _namespace_fds=(30, 31))
    command = client._command(lab, ("/stdlib", []), manifest, descriptors, "a" * 64, "b" * 64)
    assert [command[i+1:i+3] for i, argument in enumerate(command) if argument == "--ro-bind-data"] == [
        [str(fd), row["destination"]] for fd, row in zip(descriptors, entries, strict=True)]
    assert command[command.index(client._CLOSE_EXCEPT) + 1] == ",".join(map(str, descriptors))
    with pytest.raises(ValueError):
        native.validate_manifest(manifest)


def test_runtime_dispatch_requires_complete_selection_and_rejects_cross_profile_manifests():
    from recon_cockpit.secure_agent import stock_http_contract as old_contract
    from recon_cockpit.secure_agent import stock_http_production_nmap_runtime as runtime
    from recon_cockpit.secure_agent import network_tools_runtime as native
    from test_secure_network_tools_runtime import manifest
    old_selected = old_contract.selection("A", "O5")
    selected = contract.selection("apache", "A", "O5")
    old_manifest = manifest(native.NMAP_SERVICE)
    current = runtime.from_native_manifest(old_manifest)
    assert client.validate_client_runtime(old_manifest, old_selected) == old_manifest
    assert client.validate_client_runtime(current, selected) == current
    for value, selection in ((old_manifest, selected), (current, old_selected)):
        with pytest.raises(ValueError):
            client.validate_client_runtime(value, selection)
    with pytest.raises(ValueError):
        client.client_runtime_module({**old_selected, "implementation": "apache"})
