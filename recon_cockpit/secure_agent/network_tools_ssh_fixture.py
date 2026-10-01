"""PUBLIC synthetic SSH identity and bounded pre-authentication exchange.

The RSA private numbers are deliberately public test data, never credentials.
Only the owned service mounts this module. No authentication, encrypted session,
channel, shell, filesystem operation or forwarding is implemented.
"""

import hashlib
import secrets
import struct
import time

# RFC 3526 section 3, fixed 2048-bit MODP group; no supplied group parameters.
GROUP14_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BB"
    "EA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51"
    "C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE"
    "9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8F"
    "D24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
    "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF"
    "06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA"
    "68FFFFFFFFFFFFFFFF", 16)
MAX_PACKET = 8192
KEX_NAMES = (b"diffie-hellman-group14-sha256", b"rsa-sha2-256", b"aes128-ctr", b"aes128-ctr",
             b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b"")
SERVER_BANNER = b"SSH-2.0-HarborDesk_owned_fixture"


def ssh_string(value):
    if type(value) is not bytes or len(value) > MAX_PACKET:
        raise ValueError("invalid_ssh_string")
    return struct.pack("!I", len(value)) + value


def mpint(value):
    if type(value) is not int or not 0 <= value < 1 << 2049:
        raise ValueError("invalid_ssh_mpint")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw and raw[0] & 0x80:
        raw = b"\x00" + raw
    return ssh_string(raw)


def public_blob():
    return ssh_string(b"ssh-rsa") + mpint(RSA_E) + mpint(RSA_N)


def sign_sha256(message):
    """Fixed fixture RSA-SHA2-256; not a production signing API."""
    if type(message) is not bytes or not 1 <= len(message) <= 1024:
        raise ValueError("invalid_ssh_signature_input")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    size = (RSA_N.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), RSA_D, RSA_N).to_bytes(size, "big")


def _read_exact(connection, size, deadline):
    value = bytearray()
    while len(value) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ssh_fixture_deadline")
        connection.settimeout(min(remaining, 2))
        part = connection.recv(size - len(value))
        if not part:
            raise ValueError("incomplete_ssh_packet")
        value.extend(part)
    return bytes(value)


def _read_banner(connection, deadline):
    value = bytearray()
    while len(value) < 255:
        value.extend(_read_exact(connection, 1, deadline))
        if value.endswith(b"\r\n"):
            banner = bytes(value[:-2])
            if not banner.startswith(b"SSH-2.0-") or any(c < 32 or c > 126 for c in banner):
                raise ValueError("invalid_ssh_banner")
            return banner
    raise ValueError("ssh_banner_limit")


def _read_packet(connection, deadline):
    size = struct.unpack("!I", _read_exact(connection, 4, deadline))[0]
    if not 12 <= size <= MAX_PACKET or (size + 4) % 8:
        raise ValueError("ssh_packet_limit")
    body = _read_exact(connection, size, deadline)
    padding = body[0]
    if not 4 <= padding <= size - 2:
        raise ValueError("invalid_ssh_padding")
    return body[1:-padding]


def _packet(payload):
    padding = 8 - (len(payload) + 5) % 8
    if padding < 4:
        padding += 8
    return struct.pack("!I", len(payload) + padding + 1) + bytes([padding]) + payload + secrets.token_bytes(padding)


def _take_string(raw, offset, *, limit=MAX_PACKET):
    if offset + 4 > len(raw):
        raise ValueError("invalid_ssh_string")
    size = struct.unpack("!I", raw[offset:offset + 4])[0]
    offset += 4
    if size > limit or offset + size > len(raw):
        raise ValueError("invalid_ssh_string")
    return raw[offset:offset + size], offset + size


def validate_kexinit(payload):
    if not 22 <= len(payload) <= MAX_PACKET or payload[0] != 20:
        raise ValueError("invalid_ssh_kexinit")
    offset = 17
    for expected in KEX_NAMES:
        names, offset = _take_string(payload, offset, limit=4096)
        if any(c < 33 or c > 126 for c in names) or (expected and expected not in names.split(b",")):
            raise ValueError("unsupported_ssh_algorithm")
    # No optimistic first packet: accepting it would require additional state.
    if payload[offset:] != b"\x00\x00\x00\x00\x00":
        raise ValueError("unsupported_ssh_kexinit_flags")


def _client_dh(payload):
    if not payload or payload[0] != 30:
        raise ValueError("invalid_ssh_dh_message")
    raw, end = _take_string(payload, 1, limit=257)
    if (end != len(payload) or not raw or raw[0] & 0x80
            or (raw[0] == 0 and (len(raw) == 1 or not raw[1] & 0x80))):
        raise ValueError("invalid_ssh_dh_value")
    value = int.from_bytes(raw, "big")
    if not 2 <= value <= GROUP14_P - 2:
        raise ValueError("invalid_ssh_dh_value")
    return value


def serve(connection, *, banner, deadline):
    """Emit a genuine host-key KEX reply, then stop before an encrypted session."""
    connection.sendall(banner + b"\r\n")
    client_banner = _read_banner(connection, deadline)
    server_init = b"\x14" + secrets.token_bytes(16) + b"".join(ssh_string(name) for name in KEX_NAMES) + b"\x00" * 5
    connection.sendall(_packet(server_init))
    client_init = _read_packet(connection, deadline)
    validate_kexinit(client_init)
    client_dh = _client_dh(_read_packet(connection, deadline))
    private = secrets.randbits(256) | (1 << 255)
    server_dh, shared = pow(2, private, GROUP14_P), pow(client_dh, private, GROUP14_P)
    if shared in (0, 1, GROUP14_P - 1):
        raise ValueError("invalid_ssh_shared_value")
    blob = public_blob()
    exchange = b"".join(ssh_string(value) for value in
        (client_banner, banner, client_init, server_init, blob)) + mpint(client_dh) + mpint(server_dh) + mpint(shared)
    exchange_hash = hashlib.sha256(exchange).digest()
    signature = ssh_string(b"rsa-sha2-256") + ssh_string(sign_sha256(exchange_hash))
    reply = b"\x1f" + ssh_string(blob) + mpint(server_dh) + ssh_string(signature)
    connection.sendall(_packet(reply))
    # The collector needs the KEX host key, not userauth or encrypted channels.
    # No NEWKEYS, login, channel or request message is accepted or implemented.
    return True

RSA_N = 22373841116014850254946118730291452925326125802199260590376282356036650668182364954526123369215860340720508623130506937939149656907882823785945081993478670186682150008806645333305160305697746588557614121332035973774761521094685259417741584609180682520012974804134405566934592930220584629931302640605150989460946660730455249078678812788287690816522806188681852397483505511575741813938596964679382848679616785218631240083500747301976265061168745540897503250844490299839614690145924452017746626839178328541348521992899396761908242632775099262074597094533522640191630462608777689986216921874503030223344366534759223527229
RSA_E = 65537
RSA_D = 438591838321039038673313102830704217590189727807362799398494432213509924511484260877832211377560401090985755152079084863483382047158944531457702458954164781484030994550947581371511636020524578418948998914765703805606931655192605568378495180237034865588417191626934205679763872145230322624672659603325761125601010167960447646743747962957454425245183342514514070341861179260263542733016841330674752763847089104630437764735355886794991367552743633671351645185557582588214993105052592910442154110494380079753239267984590440496050582559740767440296090984982840892534012035135985551171913821712126925538290418964325833473
SIGNATURE_VECTOR_MESSAGE = b'HarborDesk public synthetic SSH fixture signature vector v1'
SIGNATURE_VECTOR = bytes.fromhex('3fd3231648573c4ac2a6b005749f6882ce0ad1fcad36789403ae88dfbfa429618d0efbe24cfe49fe019edac033d6fd18bbd9b10f6e193bf428499f3c88978eef1ac9e348495dd37992eb99fee6e697757171a11402003cbe21a731578606eaa63900e3ab4c20ad5f3b3640536bec80a67c5eece57a9fb29b9070f7ace43fd7540489ad3b82d33cd78f9e666dcf02b40148d44f9f45100e1ec476201d9d639f36948d079805d1c176be3673238262d990114cfad39e5112885c93e2ebd4d8e6089b09ddc8257b7ec43ad5f42d2ed43f7f35bdbd0d55efda074ec381f4e69dc88a8c3ac73be7804940e6d04cdf5c00922bace543f601d3204fc7d70b8ca6706ac3')
