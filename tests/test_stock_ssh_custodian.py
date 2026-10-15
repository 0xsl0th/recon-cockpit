"""Bounded tracee-memory inspection without any process or network execution."""

import errno
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import stock_ssh_custodian as custody


def memory(monkeypatch, segments):
    def peek(request, pid, address=0, data=0):
        assert request == custody.PEEKDATA and pid == 2
        for base, raw in segments.items():
            if base <= address < base + len(raw):
                chunk = raw[address-base:address-base+8]
                return int.from_bytes(chunk.ljust(8, b"\0"), "little")
        raise OSError(errno.EFAULT, "unmapped tracee memory")
    monkeypatch.setattr(custody, "ptrace", peek)


def test_tracee_string_bounded_and_null_terminated(monkeypatch):
    memory(monkeypatch, {4096: b"a"*256 + b"\0"})
    assert custody._string(2, 4096) == "a"*256


@pytest.mark.parametrize("payload", (b"a"*257+b"\0", b"a"*264, b"\xff\0"))
def test_overlong_unterminated_or_nonascii_arguments_fail_closed(monkeypatch, payload):
    memory(monkeypatch, {4096: payload})
    with pytest.raises((ValueError, UnicodeError)): custody._string(2, 4096)


@pytest.mark.parametrize("pointer", (0, -1, 2**47, 2**64-1))
def test_invalid_pointers_rejected_before_ptrace(monkeypatch, pointer):
    monkeypatch.setattr(custody, "ptrace", lambda *a: pytest.fail("invalid pointer reached native read"))
    with pytest.raises(ValueError): custody._word(2, pointer)


def test_unterminated_vector_cannot_force_unbounded_memory_reads(monkeypatch):
    memory(monkeypatch, {4096: (8192).to_bytes(8,"little")*17, 8192: b"value\0"})
    with pytest.raises(ValueError, match="vector_limit"): custody._vector(2,4096)


@pytest.mark.parametrize("values", (("LC_ALL=C", "LC_ALL=C"), ("bad",), ("=value",)))
def test_duplicate_or_invalid_environment_variables_rejected(monkeypatch, values):
    monkeypatch.setattr(custody, "_string", lambda *a: "/tool/sshd")
    monkeypatch.setattr(custody, "_vector", lambda pid, address: ("/tool/sshd",) if address == 2 else values)
    with pytest.raises(ValueError, match="environment"):
        custody._exec_arguments(2, SimpleNamespace(rdi=1,rsi=2,rdx=3))


@pytest.mark.parametrize("deadline", (None, True, float("nan"), float("inf"), -1, 6))
def test_invalid_deadline_refused_before_runtime_or_process_access(monkeypatch, deadline):
    monkeypatch.setattr(custody.time, "monotonic", lambda:0)
    monkeypatch.setattr(custody.runtime, "validate_manifest", lambda *a:pytest.fail("runtime touched"))
    with pytest.raises(ValueError, match="deadline"):
        custody.run_instance(0, {}, deadline=deadline)


def test_stderr_overflow_retains_only_one_witness_byte(monkeypatch):
    output = bytearray(b"x"*65536)
    sizes = []
    def read(fd, size):
        sizes.append(size)
        return b"!"
    monkeypatch.setattr(custody.os, "read", read)
    with pytest.raises(ValueError, match="stderr_limit"): custody._drain(5, output)
    assert len(output)==65537 and sizes==[1]


def test_non_native_abi_registers_fail_closed(monkeypatch):
    def read_regs(request,pid,address,data):
        assert request == custody.GETREGS
        data._obj.cs=0x23
    monkeypatch.setattr(custody,"ptrace",read_regs)
    with pytest.raises(ValueError,match="syscall_abi"):custody.registers(2)
