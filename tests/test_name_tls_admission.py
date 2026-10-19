"""Nested data mounts must preserve finite bytes and close every staging FD."""

import fcntl
import os
from pathlib import Path
import time

import pytest

from recon_cockpit.secure_agent import admission_isolation as admission
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.session_limits import SessionLimits


def test_name_tls_nested_admission_stages_exact_sealed_closure():
    copies = admission._name_tls_source_copies(ExecutionControl(time.monotonic() + 5))
    try:
        selected = contract.selection("A", "O1")
        service = admission.LinuxLaunchAdmission(contract.policy_for_selection(selected),
            "00000000-0000-0000-0000-000000000001", SessionLimits(**contract.limits(selected)),
            execute=True, profile=contract.PROFILE, case=selected)
        argv = service._command("/usr/lib/python3.11", [], "a" * 64, copies)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        assert len(copies) == 9
        for destination, descriptor in copies.items():
            source = Path(admission.__file__).with_name(Path(destination).name)
            assert os.read(descriptor, 131073) == source.read_bytes()
            assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals == seals
            index = argv.index(destination)
            assert argv[index - 2:index] == ["--ro-bind-data", str(descriptor)]
            with pytest.raises(OSError):
                os.write(descriptor, b"changed")
        with pytest.raises(ValueError, match="source_inventory"):
            service._command("/usr/lib/python3.11", [], "a" * 64)
    finally:
        for descriptor in copies.values():
            os.close(descriptor)


def test_partial_admission_staging_closes_already_created_descriptors(monkeypatch):
    descriptors = []
    original = os.memfd_create
    def create(*args):
        value = original(*args)
        descriptors.append(value)
        return value
    monkeypatch.setattr(admission.os, "memfd_create", create)
    class StoppingControl:
        def check(self):
            if len(descriptors) == 2:
                raise RuntimeError("stopped")
    with pytest.raises(RuntimeError, match="stopped"):
        admission._name_tls_source_copies(StoppingControl())
    assert len(descriptors) == 2
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
