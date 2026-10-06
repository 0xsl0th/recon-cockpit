"""Fixed local-X11 runtime for the isolated graphical approval worker.

Only one local display socket and one selected MIT cookie enter the read-only
runtime. The desktop session is trusted: X11 access is not a hostile-client input
provenance boundary. No terminal, home directory or complete authority file is
mounted, and no authorization answer travels on the host service interface.
"""

import fcntl
import os
from pathlib import Path
import socket
import stat
import struct
import time

from . import approval_protocol as protocol
from . import graphical_approval_protocol as graphical
from .approvals import ApprovalUnavailable
from .isolation import _namespaces, _runtime_files, _trusted_program
from .planner_isolation import LinuxIsolatedMockProvider
from .routed import _Supervisor

MAX_AUTHORITY_BYTES = 65536
AUTH_NAME = b'MIT-MAGIC-COOKIE-1'
AUTHORITY_PATH = graphical.AUTHORITY_PATH
FONTCONFIG_PATH = graphical.FONTCONFIG_PATH
FONT_CONFIG = b'''<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig><dir>/usr/share/fonts/truetype/dejavu</dir>
<cachedir>/var/cache/fontconfig</cachedir></fontconfig>
'''
RUNTIME_DIRECTORIES = (
    '/usr/share/tcltk/tcl8.6', '/usr/share/tcltk/tk8.6',
    '/usr/share/fonts/truetype/dejavu', '/var/cache/fontconfig',
)


def _field(value):
    return struct.pack('!H', len(value)) + value


def select_authority(raw, display, hostname):
    """Filter a bounded binary Xauthority file without invoking xauth or a shell."""
    display = graphical.canonical_display(display)
    number = display[1:].split('.')[0].encode('ascii')
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
        raise ValueError('invalid_graphical_authority')
    if type(hostname) is not bytes or not hostname or len(hostname) > 255:
        raise ValueError('invalid_graphical_hostname')
    position, matches = 0, set()
    while position < len(raw):
        if position + 2 > len(raw):
            raise ValueError('invalid_graphical_authority')
        family = struct.unpack_from('!H', raw, position)[0]
        position += 2
        fields = []
        for _ in range(4):
            if position + 2 > len(raw):
                raise ValueError('invalid_graphical_authority')
            length = struct.unpack_from('!H', raw, position)[0]
            position += 2
            if length > 4096 or position + length > len(raw):
                raise ValueError('invalid_graphical_authority')
            fields.append(raw[position:position + length])
            position += length
        address, recorded_number, name, cookie = fields
        if (recorded_number == number and name == AUTH_NAME
                and (family == 65535 or (family == 256 and address == hostname))):
            if len(cookie) != 16:
                raise ValueError('invalid_graphical_cookie')
            matches.add(cookie)
    if len(matches) != 1:
        raise ValueError('graphical_cookie_missing_or_ambiguous')
    # Wildcard address applies only to the selected display and selected cookie;
    # it avoids relying on an ambient hostname inside the private UTS namespace.
    return struct.pack('!H', 65535) + _field(b'') + _field(number) + _field(AUTH_NAME) + _field(matches.pop())


def _read_authority(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_AUTHORITY_BYTES):
            raise ApprovalUnavailable('invalid_graphical_authority_file')
        raw = bytearray()
        while len(raw) <= MAX_AUTHORITY_BYTES:
            block = os.read(fd, min(8192, MAX_AUTHORITY_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > MAX_AUTHORITY_BYTES:
            raise ApprovalUnavailable('graphical_authority_limit')
        return bytes(raw)
    finally:
        os.close(fd)


def _sealed_file(name, raw):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise ApprovalUnavailable('graphical_bootstrap_short_write')
            offset += count
        os.lseek(fd, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
            raise ApprovalUnavailable('graphical_bootstrap_unsealed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def command(stdlib, files, bootstrap_digest, *, display, socket_path,
            authority_fd, font_config_fd, launch_witness):
    """Fixed reviewed worker only; deliberately accepts no executable or module."""
    display = graphical.canonical_display(display)
    expected_socket = '/tmp/.X11-unix/X' + display[1:].split('.')[0]
    if str(socket_path) != expected_socket or type(launch_witness) is not bool:
        raise ApprovalUnavailable('invalid_graphical_runtime')
    host = _namespaces()
    argv = [_trusted_program('bwrap'), '--unshare-user', '--unshare-net', '--unshare-pid',
            '--unshare-ipc', '--unshare-uts', '--unshare-cgroup', '--uid', '0', '--gid', '0',
            '--cap-drop', 'ALL', '--die-with-parent', '--new-session', '--clearenv',
            '--setenv', 'LC_ALL', 'C', '--setenv', 'DISPLAY', display,
            '--setenv', 'XAUTHORITY', AUTHORITY_PATH,
            '--setenv', 'TCL_LIBRARY', '/usr/share/tcltk/tcl8.6',
            '--setenv', 'TK_LIBRARY', '/usr/share/tcltk/tk8.6',
            '--setenv', 'FONTCONFIG_FILE', FONTCONFIG_PATH,
            '--chdir', '/', '--proc', '/proc', '--dev', '/dev', '--ro-bind', stdlib, stdlib]
    for source, destination in files:
        argv.extend(('--ro-bind', source, destination))
    for directory in RUNTIME_DIRECTORIES:
        resource = Path(directory)
        if (not stat.S_ISDIR(resource.lstat().st_mode)
                or resource.resolve(strict=True) != resource):
            raise ApprovalUnavailable('graphical_runtime_resources_missing')
        argv.extend(('--ro-bind', directory, directory))
    argv.extend(('--ro-bind', expected_socket, expected_socket,
                 '--ro-bind-data', str(authority_fd), AUTHORITY_PATH,
                 '--ro-bind-data', str(font_config_fd), FONTCONFIG_PATH,
                 '--ro-bind', str(Path(__file__).with_name('planner_worker.py').resolve()), '/app/planner_worker.py'))
    for name in ('graphical_approval_worker', 'graphical_approval_view', 'graphical_approval_protocol',
                 'approval_protocol', 'approvals', 'models', 'tool_parameters', 'tool_adapters',
                 *(('approval_witness', 'audit_witness', 'audit_protocol') if launch_witness else ())):
        argv.extend(('--ro-bind', str(Path(__file__).with_name(name + '.py').resolve()),
                     '/app/approval_runtime/' + name + '.py'))
    argv.extend(('--remount-ro', '/proc', '--remount-ro', '/dev', '--remount-ro', '/',
                 '/usr/bin/python3', '-I', '-S', '/app/approval_runtime/graphical_approval_worker.py',
                 bootstrap_digest, *(host[name] for name in ('user', 'net', 'mnt', 'pid'))))
    if launch_witness:
        argv.append('launch-witness')
    return argv


def start(service, control):
    """Called only by the fixed service after its existing lifetime validation."""
    control.check()
    display = graphical.canonical_display(os.environ.get('DISPLAY'))
    socket_path = Path('/tmp/.X11-unix/X' + display[1:].split('.')[0])
    info = socket_path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in {0, os.getuid()}:
        raise ApprovalUnavailable('invalid_graphical_display_socket')
    authority_path = Path(os.environ['XAUTHORITY']) if os.environ.get('XAUTHORITY') else Path.home() / '.Xauthority'
    authority = select_authority(_read_authority(authority_path), display, socket.gethostname().encode('utf-8'))
    LinuxIsolatedMockProvider().check_available()
    stdlib, files = _runtime_files('/usr/bin/python3', None, control=control)
    initial = {'version': '1', 'frontend': graphical.FRONTEND, 'broker_id': service._identity,
               'session_id': service._session_id, 'policy': service._policy.to_dict(),
               'deadline': control.deadline, 'display': display,
               'display_socket': [info.st_dev, info.st_ino]}
    if service._launch_witness:
        witness_info = os.fstat(service._witness_writer.fileno())
        initial['witness'] = [witness_info.st_dev, witness_info.st_ino]
    graphical.initial(initial, time.monotonic())
    bootstrap_digest = protocol.digest(initial)
    service._supervisor = _Supervisor(10, 65536, control=control)
    service._channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    service._channel.setblocking(False)
    authority_fd = font_config_fd = None
    try:
        authority_fd = _sealed_file('reviewer-display-cookie', authority)
        font_config_fd = _sealed_file('reviewer-fonts', FONT_CONFIG)
        service._process = service._supervisor.launch('worker', command(stdlib, files, bootstrap_digest,
            display=display, socket_path=socket_path, authority_fd=authority_fd,
            font_config_fd=font_config_fd, launch_witness=service._launch_witness),
            stdin=child, pass_fds=(authority_fd, font_config_fd))
        child.close()
        # bubblewrap consumes and closes both read-only data descriptors before
        # exec. The reviewer inherits only stdin and supervised output pipes.
        os.close(authority_fd)
        authority_fd = None
        os.close(font_config_fd)
        font_config_fd = None
        for stream in (service._process.stdout, service._process.stderr):
            os.set_blocking(stream.fileno(), False)
        if service._launch_witness:
            # The common sender's single-fd form carries this one witness, not a
            # terminal. Its purpose is bound by the graphical bootstrap schema.
            service._send(protocol.encode(initial), fd=service._witness_writer.fileno())
            service._witness_writer.close()
            service._witness_writer = None
        else:
            service._send(protocol.encode(initial))
        expected = {'version': '1', 'bootstrap_digest': bootstrap_digest, 'ready': True,
                    'checks': dict.fromkeys(graphical.CHECKS, True)}
        if protocol.encode(service._reply()) != protocol.encode(expected):
            raise ApprovalUnavailable('graphical_approval_invalid_ready')
        service._checks = expected['checks']
    finally:
        child.close()
        for fd in (authority_fd, font_config_fd):
            if fd is not None:
                os.close(fd)
