"""Portable framing/gate tests; encrypted bytes below are intentionally opaque."""

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic_fixture as peer
from recon_cockpit.secure_agent import tls_posture_mediator as mediator


def vector(raw, width=2):
    return len(raw).to_bytes(width, "big") + raw


def extension(kind, raw):
    return kind.to_bytes(2, "big") + vector(raw)


def record(kind, raw, protocol=b"\x03\x03"):
    return bytes([kind]) + protocol + vector(raw)


def hello(version="tls1_3", name=b"harbordesk.test", extra=b""):
    protocol, _, cipher = peer.VERSIONS[version]
    extensions = extension(0, vector(b"\0" + vector(name))) + extension(10, b"\0\2\0\x17")
    if version == "tls1_3":
        extensions += extension(13, b"\0\2\4\3") + extension(43, b"\2\3\4")
        extensions += extension(51, vector(b"\0\x17" + vector(b"\4" + b"x" * 64)))
    body = min(protocol, 0x0303).to_bytes(2, "big") + b"r" * 32 + b"\0"
    body += vector(cipher.to_bytes(2, "big") + b"\0\xff") + b"\1\0" + vector(extensions + extra)
    return record(22, b"\1" + len(body).to_bytes(3, "big") + body, b"\3\1")


def sequence(version):
    protocol = {"tls1": b"\3\1", "tls1_1": b"\3\2", "tls1_2": b"\3\3", "tls1_3": b"\3\3"}[version]
    rows = [hello(version)]
    if version != "tls1_3":
        rows.append(record(22, b"\x10\0\0\x42\x41\x04" + b"k" * 64, protocol))
    rows.append(record(20, b"\1", protocol))
    rows.append(record(23 if version == "tls1_3" else 22,
                       b"f" * {"tls1": 52, "tls1_1": 68, "tls1_2": 40, "tls1_3": 69}[version], protocol))
    rows.append(record(23 if version == "tls1_3" else 21,
                       b"c" * {"tls1": 36, "tls1_1": 52, "tls1_2": 26, "tls1_3": 19}[version], protocol))
    return rows


def client_framer():
    return mediator.RecordFramer(max_bytes=mediator.CLIENT_MAX_BYTES, max_records=mediator.CLIENT_MAX_RECORDS)


def gate(version="tls1_3"):
    return mediator.ClientGate(version, peer.validate_client_hello)


def forward(boundary, raw):
    boundary.check(raw)
    boundary.forwarded(raw)


@pytest.mark.parametrize("version", mediator.VERSIONS)
def test_complete_finite_shapes_commit_only_after_forwarding(version):
    boundary = gate(version)
    records = sequence(version)
    total = 0
    for index, raw in enumerate(records):
        state = boundary.state
        boundary.check(raw)
        boundary.check(raw)  # Identical recheck does not consume a record.
        assert boundary.state == state
        assert boundary.forwarded_records == index
        assert boundary.forwarded_bytes == total
        boundary.forwarded(raw)
        total += len(raw)
        assert boundary.forwarded_records == index + 1
        assert boundary.forwarded_bytes == total
        assert boundary.forwarded_client_hellos == 1
    assert boundary.state == "complete"
    with pytest.raises(mediator.MediatorViolation, match="extra_client_record"):
        boundary.check(records[-1])
    assert boundary.forwarded_records == len(records)


@pytest.mark.parametrize("version", mediator.VERSIONS)
@pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 17, 8192])
def test_tcp_fragmentation_and_coalescing_preserve_exact_records(version, chunk_size):
    expected = sequence(version)
    raw, output, framed = b"".join(expected), [], client_framer()
    for offset in range(0, len(raw), chunk_size):
        output.extend(framed.feed(raw[offset:offset + chunk_size]))
    framed.finish()
    assert output == expected
    assert framed.received_bytes == len(raw)
    assert framed.record_count == len(expected)
    assert framed.pending_bytes == 0


def test_every_first_hello_tcp_split_waits_until_complete_before_exposure():
    raw = hello()
    for offset in range(1, len(raw)):
        framed = client_framer()
        assert framed.feed(raw[:offset]) == []
        assert framed.pending_bytes == offset
        assert framed.feed(raw[offset:]) == [raw]
        framed.finish()


@pytest.mark.parametrize("version", mediator.VERSIONS)
@pytest.mark.parametrize("point", ["after_hello", "after_ccs", "after_close"])
def test_second_plaintext_client_hello_is_never_forwarded(version, point):
    boundary, rows = gate(version), sequence(version)
    count = {"after_hello": 1, "after_ccs": len(rows) - 2, "after_close": len(rows)}[point]
    for raw in rows[:count]:
        forward(boundary, raw)
    before = (boundary.forwarded_bytes, boundary.forwarded_records)
    # A legacy encrypted Finished has outer22 and is opaque. A full second
    # ClientHello still fails its exact encrypted-record size in that state.
    code = "unexpected_client_record" if point == "after_ccs" and version != "tls1_3" else "extra_client_hello"
    second = hello(version)
    second = second[:1] + rows[-1][1:3] + second[3:]
    with pytest.raises(mediator.MediatorViolation, match=code):
        boundary.check(second)
    assert (boundary.forwarded_bytes, boundary.forwarded_records) == before
    assert boundary.forwarded_client_hellos == 1
    assert boundary.state == "blocked"


@pytest.mark.parametrize("fragment", [b"\1", b"\1\0", b"\1\0\1", b"\1\0\1\0"])
@pytest.mark.parametrize("with_ccs", [False, True])
def test_tls13_retry_fragment_is_blocked_even_after_compatibility_ccs(fragment, with_ccs):
    boundary = gate()
    forward(boundary, hello())
    if with_ccs:
        forward(boundary, record(20, b"\1"))
    before = boundary.forwarded_bytes
    with pytest.raises(mediator.MediatorViolation, match="extra_client_hello"):
        boundary.check(record(22, fragment))
    assert boundary.forwarded_bytes == before
    assert boundary.forwarded_client_hellos == 1


def test_two_tcp_coalesced_hellos_forward_only_the_first_complete_record():
    framed, boundary, forwarded = client_framer(), gate(), []
    first = hello()
    for raw in framed.feed(first + first):
        try:
            boundary.check(raw)
        except mediator.MediatorViolation as error:
            assert error.code == "extra_client_hello"
            break
        forwarded.append(raw)
        boundary.forwarded(raw)
    assert forwarded == [first]
    assert boundary.forwarded_bytes == len(first)


@pytest.mark.parametrize("kind", ["fragment", "coalesced", "wrong_sni", "extra_extension", "record_version"])
def test_invalid_first_handshake_never_reaches_peer(kind):
    raw = hello()
    if kind == "fragment":
        raw = record(22, raw[5:15], b"\3\1")
    elif kind == "coalesced":
        raw = record(22, raw[5:] + raw[5:], b"\3\1")
    elif kind == "wrong_sni":
        raw = hello(name=b"other.test")
    elif kind == "extra_extension":
        raw = hello(extra=extension(42, b""))
    else:
        raw = raw[:1] + b"\3\3" + raw[3:]
    boundary = gate()
    with pytest.raises(mediator.MediatorViolation, match="invalid_first_client_hello"):
        boundary.check(raw)
    assert boundary.forwarded_bytes == boundary.forwarded_records == boundary.forwarded_client_hellos == 0


@pytest.mark.parametrize("version", ["tls1", "tls1_1", "tls1_2"])
@pytest.mark.parametrize("mutation", ["fragment", "coalesced", "point", "vector", "inner_length", "early_ccs"])
def test_legacy_key_exchange_is_one_exact_clear_message(version, mutation):
    boundary, rows = gate(version), sequence(version)
    forward(boundary, rows[0])
    raw = bytearray(rows[1])
    if mutation == "fragment":
        raw = record(22, raw[5:20], bytes(raw[1:3]))
    elif mutation == "coalesced":
        raw = record(22, raw[5:] + rows[0][5:], bytes(raw[1:3]))
    elif mutation == "early_ccs":
        raw = rows[2]
    else:
        raw[{"point": 10, "vector": 9, "inner_length": 8}[mutation]] ^= 1
    with pytest.raises(mediator.MediatorViolation, match="unexpected_client_record"):
        boundary.check(bytes(raw))
    assert boundary.forwarded_records == 1


@pytest.mark.parametrize("version", mediator.VERSIONS)
@pytest.mark.parametrize("payload", [b"\0", b"\1\1", b"\2"])
def test_compatibility_ccs_cannot_expand_or_change_the_sequence(version, payload):
    boundary, rows = gate(version), sequence(version)
    for raw in rows[:len(rows) - 3]:
        forward(boundary, raw)
    with pytest.raises(mediator.MediatorViolation, match="unexpected_client_record"):
        boundary.check(record(20, payload, rows[-3][1:3]))


@pytest.mark.parametrize("version", mediator.VERSIONS)
def test_repeated_ccs_is_refused_before_encrypted_records(version):
    boundary, rows = gate(version), sequence(version)
    for raw in rows[:-2]:
        forward(boundary, raw)
    before = boundary.forwarded_records
    with pytest.raises(mediator.MediatorViolation, match="unexpected_client_record"):
        boundary.check(rows[-3])
    assert boundary.forwarded_records == before


@pytest.mark.parametrize("version", mediator.VERSIONS)
@pytest.mark.parametrize("state_offset", [2, 1])
@pytest.mark.parametrize("mutation", ["short", "long", "type", "version"])
def test_opaque_encrypted_records_still_have_exact_shape_bounds(version, state_offset, mutation):
    boundary, rows = gate(version), sequence(version)
    for raw in rows[:-state_offset]:
        forward(boundary, raw)
    raw = rows[-state_offset]
    if mutation == "short":
        raw = record(raw[0], raw[5:-1], raw[1:3])
    elif mutation == "long":
        raw = record(raw[0], raw[5:] + b"x", raw[1:3])
    elif mutation == "type":
        raw = bytes([20]) + raw[1:]
    else:
        raw = raw[:1] + (b"\3\2" if raw[1:3] != b"\3\2" else b"\3\3") + raw[3:]
    with pytest.raises(mediator.MediatorViolation, match="record_version_mismatch|unexpected_client_record"):
        boundary.check(raw)
    assert boundary.forwarded_records == len(rows) - state_offset


@pytest.mark.parametrize("version", ["tls1", "tls1_1", "tls1_2"])
def test_ciphertext_starting_with_hello_type_byte_is_not_misclassified(version):
    boundary, rows = gate(version), sequence(version)
    for raw in rows[:-2]:
        forward(boundary, raw)
    raw = rows[-2][:5] + b"\1" + rows[-2][6:]
    forward(boundary, raw)
    assert boundary.state == "expect_close"


@pytest.mark.parametrize("raw,code", [(b"\x16\3\3\0\0", "record_payload_limit"),
                                    (b"\x16\3\3\xff\xff", "record_payload_limit"),
                                    (b"\x19\3\3\0\1", "invalid_record_header"),
                                    (b"\x16\3\4\0\1", "invalid_record_header"),
                                    (b"\x16\3\3\x20\0", "direction_byte_limit")])
def test_framer_rejects_invalid_header_before_waiting_for_payload(raw, code):
    framed = client_framer()
    with pytest.raises(mediator.MediatorViolation, match=code):
        framed.feed(raw)
    assert framed.pending_bytes == 0
    assert framed.record_count == 0
    with pytest.raises(mediator.MediatorViolation, match="framer_already_blocked"):
        framed.feed(hello())


@pytest.mark.parametrize("length", [1, 2, 3, 4, 5, 6, 12])
def test_eof_with_partial_header_or_payload_is_never_complete(length):
    framed = client_framer()
    assert framed.feed(hello()[:length]) == []
    with pytest.raises(mediator.MediatorViolation, match="partial_record"):
        framed.finish()
    assert framed.pending_bytes == 0


def test_byte_limit_refuses_without_retaining_oversized_input():
    framed = client_framer()
    with pytest.raises(mediator.MediatorViolation, match="direction_byte_limit"):
        framed.feed(b"x" * (mediator.CLIENT_MAX_BYTES + 1))
    assert framed.received_bytes == mediator.CLIENT_MAX_BYTES + 1
    assert framed.pending_bytes == framed.record_count == 0


def test_record_limit_is_finite_even_with_partial_next_header():
    framed = mediator.RecordFramer(max_bytes=8192, max_records=1)
    raw = record(20, b"\1")
    assert framed.feed(raw) == [raw]
    with pytest.raises(mediator.MediatorViolation, match="direction_record_limit"):
        framed.feed(b"\x16")
    assert framed.record_count == 1


def test_bad_later_coalesced_header_exposes_no_records_from_that_feed():
    framed = client_framer()
    with pytest.raises(mediator.MediatorViolation, match="invalid_record_header"):
        framed.feed(hello() + b"\x19\3\3\0\1")
    assert framed.record_count == 1  # Parsed is distinct from forwarded.
    assert framed.pending_bytes == 0


def test_server_framer_retains_generic_records_only_within_independent_caps():
    framed = mediator.RecordFramer(max_bytes=mediator.SERVER_MAX_BYTES, max_records=mediator.SERVER_MAX_RECORDS)
    raw = record(23, b"x" * mediator.MAX_RECORD_PAYLOAD)
    assert framed.feed(raw) == [raw]
    with pytest.raises(mediator.MediatorViolation, match="direction_byte_limit"):
        framed.feed(raw)
    assert framed.record_count == 1


@pytest.mark.parametrize("options", [{"max_bytes": True, "max_records": 1},
                                     {"max_bytes": 32769, "max_records": 1},
                                     {"max_bytes": 6, "max_records": 33},
                                     {"max_bytes": 8192, "max_records": 8, "max_payload": 18433}])
def test_framer_does_not_accept_unbounded_or_boolean_configuration(options):
    with pytest.raises(ValueError, match="invalid_framer_bounds"):
        mediator.RecordFramer(**options)


def test_failed_send_has_no_committed_progress_or_peer_claim():
    boundary = gate()
    boundary.check(hello())
    # Caller encounters a send error and terminates; it must not call forwarded.
    assert boundary.forwarded_bytes == boundary.forwarded_records == boundary.forwarded_client_hellos == 0
    assert boundary.state == "expect_client_hello"


@pytest.mark.parametrize("operation", ["unvalidated", "changed_pending", "changed_commit"])
def test_forward_commits_cannot_replace_the_validated_record(operation):
    boundary, raw = gate(), hello()
    if operation == "unvalidated":
        with pytest.raises(mediator.MediatorViolation, match="unvalidated_forward_commit"):
            boundary.forwarded(raw)
    else:
        boundary.check(raw)
        changed = raw[:15] + bytes([raw[15] ^ 1]) + raw[16:]
        with pytest.raises(mediator.MediatorViolation, match="pending_record_changed|unvalidated_forward_commit"):
            (boundary.check if operation == "changed_pending" else boundary.forwarded)(changed)
    assert boundary.forwarded_records == 0
    with pytest.raises(mediator.MediatorViolation, match="gate_already_blocked"):
        boundary.check(raw)


@pytest.mark.parametrize("raw", [None, bytearray(b"x"), b"", b"x", b"\x16\3\1\0\1xx"])
def test_gate_requires_exact_immutable_complete_record(raw):
    boundary = gate()
    with pytest.raises(mediator.MediatorViolation):
        boundary.check(raw)
    assert boundary.forwarded_records == 0
