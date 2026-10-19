"""Test-only observation of unchanged guards in the actual surviving owner.

One framed record traverses existing stderr pipes. Only this harness consumes
that exact frame before ordinary launcher reply validation; all other stderr
still fails closed. No production RPC, descriptor or admitted slot is added.
"""

from copy import deepcopy
import textwrap

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_ledger as ledger
from recon_cockpit.secure_agent import name_tls_public as public
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from name_tls_native_instrument import variant

PREFIX = b"NAME-TLS-TEST-BINDING-WITNESS:"
MAX_BODY = 49152


def frame_size(raw):
    if len(raw) < len(PREFIX) + 9:
        return None
    if not raw.startswith(PREFIX) or raw[len(PREFIX) + 8:len(PREFIX) + 9] != b":":
        raise ValueError("binding_witness_frame_header")
    digits = raw[len(PREFIX):len(PREFIX) + 8]
    if any(byte not in b"0123456789abcdef" for byte in digits):
        raise ValueError("binding_witness_frame_length")
    length = int(digits, 16)
    if not 0 < length <= MAX_BODY:
        raise ValueError("binding_witness_frame_bound")
    return len(PREFIX) + 9 + length + 1


def decode_frame(raw):
    size = frame_size(raw)
    if size is None or len(raw) != size or not raw.endswith(b"\n"):
        raise ValueError("binding_witness_frame_size")
    value = public.decode(raw[len(PREFIX) + 9:-1], max_bytes=MAX_BODY)
    if type(value) is not dict:
        raise ValueError("binding_witness_frame_value")
    return value


def _owner_source(source, slot):
    marker = "                    reply = ledger.apply(message, role=role)"
    assert source.count(marker) == 1
    block = textwrap.dedent(f'''\
        test_witness = None
        if role == 'launcher' and message.get('operation') == 'ARM' and message.get('slot') == 'dns_2':
            from recon_cockpit.secure_agent import name_tls_contract as test_contract
            from recon_cockpit.secure_agent.name_tls_ledger import Refused as TestRefused
            test_before = ledger.snapshot()
            assert test_before['selection']['case'] == 'N1'
            assert test_before['binding'] is not None and test_before['observation_generation'] == 1
            test_action = test_contract.service_action(ledger.selection, ledger.identity, {slot!r}, test_before['binding'])
            assert test_contract.validate_action(test_action, ledger.selection, ledger.identity, test_before['binding']) == test_action
            ledger._binding_check(test_before['elapsed_us'])
            test_witness = {{'schema_version': '1', 'instrumented_guard_calls': True,
                'inherited_channel_claim': False, 'slot': {slot!r}, 'action': test_action,
                'action_sha256': test_contract.digest(test_action), 'before_arm': test_before,
                'before_binding_guard': 'ok'}}
        reply = ledger.apply(message, role=role)
        if test_witness is not None:
            assert reply['status'] == 'ok'
            test_after = ledger.snapshot()
            assert test_after['binding'] is None and test_after['observation_generation'] == 2
            assert test_after['active_action_sequence'] == 2 and not test_after['terminal']
            try:
                ledger._binding_check(test_after['elapsed_us'])
            except TestRefused as test_error:
                assert str(test_error) == 'binding_missing'
                test_witness['after_binding_guard'] = str(test_error)
            else:
                raise AssertionError('stale binding survived real DNS2 ARM')
            test_request = {{'operation': 'RESERVE_CONNECTION', 'sequence': 1,
                'action_sequence': 2, 'action_digest': test_contract.digest(test_action),
                'owner_identity_sha256': ledger.identity['owner_identity_sha256'], 'local_id': 1}}
            try:
                ledger._execute('RESERVE_CONNECTION', test_request, {slot + '_frontend'!r}, test_after['elapsed_us'])
            except TestRefused as test_error:
                assert str(test_error) == 'action_binding_changed'
                test_witness['reservation_guard'] = str(test_error)
            else:
                raise AssertionError('stale action reserved a connection')
            test_witness.update(after_arm=test_after, after_guards=ledger.snapshot(), reservation_request=test_request)
            assert test_witness['after_guards'] == test_after
            test_raw = topology.encode(test_witness)
            assert 0 < len(test_raw) <= {MAX_BODY}
            test_frame = {PREFIX!r} + format(len(test_raw), '08x').encode('ascii') + b':' + test_raw + b'\\n'
            assert os.write(2, test_frame) == len(test_frame)
    ''')
    return source.replace(marker, textwrap.indent(block.rstrip(), " " * 20))


def _launcher_source(source):
    marker = "        with _NestedAdmission(config, init['runtime']) as gate, (owned.lab if owned is not None else nullcontext()):"
    assert source.count(marker) == 1
    block = textwrap.dedent(f'''\
        from recon_cockpit.secure_agent.name_tls_topology import Topology as TestTopology
        test_original_ledger_request = TestTopology.ledger_request
        def test_observed_ledger_request(self, message):
            test_reply = test_original_ledger_request(self, message)
            if message.get('operation') == 'ARM' and message.get('slot') == 'dns_2' and test_reply['status'] == 'ok':
                self._supervisor.wait_for(lambda: b'\\n' in self._supervisor.buffers['topology_err'])
                test_frame = bytes(self._supervisor.buffers['topology_err'])
                assert test_frame.startswith({PREFIX!r}) and test_frame.endswith(b'\\n')
                assert test_frame.count(b'\\n') == 1 and len(test_frame) <= {MAX_BODY + len(PREFIX) + 10}
                assert not getattr(self, '_test_binding_witness_mirrored', False)
                self._test_binding_witness_mirrored = True
                assert os.write(2, test_frame) == len(test_frame)
            return test_reply
        TestTopology.ledger_request = test_observed_ledger_request
    ''')
    return source.replace(marker, textwrap.indent(block, " " * 8) + marker)


def install(tmp_path, monkeypatch, slot):
    assert slot in ("http", "tls")
    variants = [variant(tmp_path, monkeypatch, "name_tls_topology_worker", lambda raw: _owner_source(raw, slot)),
                variant(tmp_path, monkeypatch, "launcher_worker", _launcher_source)]
    frames = []
    ordinary_reply = LinuxFixtureLauncher._reply
    def observed_reply(self):
        supervisor = self._supervisor
        ordinary_wait = supervisor.wait_for
        def observed_wait(predicate, **kwargs):
            while True:
                ordinary_wait(predicate, **kwargs)
                raw = bytes(supervisor.buffers["worker_err"])
                if not raw or not (raw.startswith(PREFIX) or PREFIX.startswith(raw)):
                    return
                ordinary_wait(lambda: len(supervisor.buffers["worker_err"]) >= len(PREFIX) + 9
                              or bool(supervisor.eof), **kwargs)
                size = frame_size(bytes(supervisor.buffers["worker_err"]))
                assert size is not None
                ordinary_wait(lambda: len(supervisor.buffers["worker_err"]) >= size or bool(supervisor.eof), **kwargs)
                complete = bytes(supervisor.buffers["worker_err"])
                decode_frame(complete)  # Exact size rejects a second frame or unrelated stderr.
                assert not frames
                frames.append(complete)
                supervisor.buffers["worker_err"].clear()
                if predicate():
                    return
        supervisor.wait_for = observed_wait
        try:
            return ordinary_reply(self)
        finally:
            supervisor.wait_for = ordinary_wait
    monkeypatch.setattr(LinuxFixtureLauncher, "_reply", observed_reply)
    return {"source_variants": variants, "frames": frames,
            "transport": "one_exact_bounded_frame_on_existing_owner_and_launcher_stderr",
            "test_only_reply_exception": "consume_only_exact_frame_before_unchanged_reply_validation"}


def validate(frame, reviewed_action, final_result):
    witness = decode_frame(frame)
    expected = {"schema_version", "instrumented_guard_calls", "inherited_channel_claim", "slot", "action",
        "action_sha256", "before_arm", "before_binding_guard", "after_arm", "after_guards",
        "after_binding_guard", "reservation_guard", "reservation_request"}
    assert set(witness) == expected and witness["schema_version"] == "1"
    assert witness["instrumented_guard_calls"] is True and witness["inherited_channel_claim"] is False
    assert witness["action"] == reviewed_action and witness["action_sha256"] == contract.digest(reviewed_action)
    before, after = witness["before_arm"], witness["after_arm"]
    assert witness["after_guards"] == after
    assert before["binding"] is not None and before["observation_generation"] == 1
    assert after["binding"] is None and after["observation_generation"] == 2
    assert not before["terminal"] and not after["terminal"]
    assert before["active_action_sequence"] is None and after["active_action_sequence"] == 2
    assert witness["before_binding_guard"] == "ok" and witness["after_binding_guard"] == "binding_missing"
    assert witness["reservation_guard"] == "action_binding_changed"
    assert contract.validate_action(reviewed_action, before["selection"], before["identity"], before["binding"]) == reviewed_action
    request = witness["reservation_request"]
    assert request == {"operation": "RESERVE_CONNECTION", "sequence": 1, "action_sequence": 2,
        "action_digest": contract.digest(reviewed_action), "owner_identity_sha256": before["identity"]["owner_identity_sha256"],
        "local_id": 1}
    expected_counters = deepcopy(before["counters"])
    expected_counters["actions"] += 1
    expected_counters["output_bytes"] += contract.action_bounds("dns_2")["output_bytes"]
    assert after["counters"] == expected_counters
    for state in (before, after):
        count = sum(event["kind"] == "message" for event in state["events"])
        ledger.validate_snapshot(state, messages=final_result["name_tls_messages"][:count],
            selected=final_result["name_tls_ledger"]["selection"], identity=final_result["name_tls_ledger"]["identity"])
    final = final_result["name_tls_ledger"]
    assert final["binding"] is None and final["observation_generation"] == 2
    assert final["actions"][1]["observation"] is not None
    return witness
