"""Portable harness validation; these tests make no native execution claim."""

from copy import deepcopy
import textwrap
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_public as public
from recon_cockpit.secure_agent import name_tls_python_runtime as sources
from name_tls_binding_witness import PREFIX, MAX_BODY, _owner_source, _launcher_source, decode_frame, validate
from name_tls_native_instrument import variant
from test_name_tls_authority import Harness, semantic


@pytest.mark.parametrize("slot", ("http", "tls"))
def test_exact_injected_owner_guard_block_retains_real_replayable_transitions(slot):
    h = Harness(case="N1")
    h.dns()
    reviewed = contract.service_action(h.selected, h.identity, slot, h.ledger.snapshot()["binding"])
    h.clock = .3
    h.action_sequence = 2
    h.action = contract.dns_action(h.selected, h.identity, "dns_2")
    h.sequences["launcher"] += 1
    message = {"operation": "ARM", "sequence": h.sequences["launcher"], "action_sequence": 2,
        "action_digest": contract.digest(h.action), "owner_identity_sha256": h.identity["owner_identity_sha256"],
        "slot": "dns_2", "action": h.action}
    frames = []
    def write(descriptor, raw):
        assert descriptor == 2
        frames.append(raw)
        return len(raw)
    env = {"ledger": h.ledger, "role": "launcher", "message": message,
           "topology": SimpleNamespace(encode=public.encode), "os": SimpleNamespace(write=write)}
    source = _owner_source("                    reply = ledger.apply(message, role=role)", slot)
    exec(compile(textwrap.dedent(source), "fixed-native-owner-observation", "exec"), env)
    h.messages.append({"role": "launcher", "message": deepcopy(message), "reply": deepcopy(env["reply"])})
    assert len(frames) == 1 and len(frames[0]) <= MAX_BODY + len(PREFIX) + 10
    h.connection()
    h.reserve()
    answer = semantic(address=public.endpoints("A")["excluded_address"])
    h.send("OBSERVE_DNS", "dns_frontend", lease=h.lease, semantic=answer, request_sha256="1" * 64,
           original_answer_sha256="2" * 64, delivered_answer_sha256="3" * 64, response_bytes=80)
    h.finish_connection()
    h.finish(answer)
    result = {"name_tls_ledger": h.ledger.snapshot(), "name_tls_messages": h.messages}
    checked = validate(frames[0], reviewed, result)
    assert checked["reservation_guard"] == "action_binding_changed"
    changed = deepcopy(reviewed)
    changed["rationale"] += "changed"
    with pytest.raises(AssertionError):
        validate(frames[0], changed, result)


@pytest.mark.parametrize("mutation", ("extra_stderr", "second_frame", "oversize", "bad_length", "truncated", "wrong_prefix"))
def test_stderr_decoder_never_accepts_other_output(mutation):
    body = public.encode({"fixed": "observation"})
    frame = PREFIX + format(len(body), "08x").encode("ascii") + b":" + body + b"\n"
    assert decode_frame(frame) == {"fixed": "observation"}
    changed = {"extra_stderr": frame + b"unexpected", "second_frame": frame + frame,
        "oversize": PREFIX + b"ffffffff:" + body + b"\n",
        "bad_length": PREFIX + b"zzzzzzzz:" + body + b"\n",
        "truncated": frame[:-1], "wrong_prefix": b"OTHER" + frame}[mutation]
    with pytest.raises(ValueError):
        decode_frame(changed)


def test_launcher_variant_bytes_enter_source_manifest_and_drift_is_refused(tmp_path, monkeypatch):
    metadata = variant(tmp_path, monkeypatch, "launcher_worker", _launcher_source)
    control = SimpleNamespace(check=lambda: None)
    manifest = sources.inspect_sources(control)
    row = next(row for row in manifest["files"] if row["module"] == "launcher_worker")
    assert row["sha256"] == metadata["instrumented_sha256"]
    assert row["sha256"] != metadata["original_sha256"]
    sources.verify_sources(manifest, ("launcher_worker",), control)
    candidate = sources.source_path("launcher_worker")
    candidate.write_bytes(candidate.read_bytes() + b"\n# drift\n")
    with pytest.raises(ValueError, match="pin_changed"):
        sources.verify_sources(manifest, ("launcher_worker",), control)
