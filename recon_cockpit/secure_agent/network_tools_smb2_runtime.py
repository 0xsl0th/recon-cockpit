"""Exact Ruby socket closure for one repository-owned SMB2 negotiation request.

The client emits only bounded wire bytes. The independent networkless parser
interprets those bytes; neither a response nor a proposal selects executable
code, an endpoint, a security handshake, or a second request.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from .tool_runtime_common import _read_regular


TOOL_ID = "smb2_negotiate_metadata_v1"
PROFILE = "network-tools-smb2-runtime-v1"
EXECUTABLE = "/usr/bin/ruby3.3"
DESTINATION = "/tool/ruby"
SCRIPT_PATH = "/tool/data/smb2-negotiate-metadata.rb"
FIXED_ARGV = (DESTINATION, "--disable=all", SCRIPT_PATH)
ENVIRONMENT = {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1"}
MAX_MANIFEST_BYTES = 8192
MAX_RUNTIME_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
RUBY_FILES = (
    "/usr/lib/ruby/3.3.0/socket.rb",
    "/usr/lib/x86_64-linux-gnu/ruby/3.3.0/enc/encdb.so",
    "/usr/lib/x86_64-linux-gnu/ruby/3.3.0/enc/trans/transdb.so",
    "/usr/lib/x86_64-linux-gnu/ruby/3.3.0/socket.so",
)
# Only the same reviewed Debian Ruby 3.3 x86-64 layout used by C3 and C5. No TLS,
# JSON, gems, plugins, user directories, or resolver files enter this closure.
NATIVE_FILES = (
    ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", INTERPRETER),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
    ("/usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0", "/usr/lib/x86_64-linux-gnu/libcrypt.so.1"),
    ("/usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0", "/usr/lib/x86_64-linux-gnu/libgmp.so.10"),
    ("/usr/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6"),
    ("/usr/lib/x86_64-linux-gnu/libruby-3.3.so.3.3.8", "/usr/lib/x86_64-linux-gnu/libruby-3.3.so.3.3"),
    ("/usr/lib/x86_64-linux-gnu/libz.so.1.3.2", "/usr/lib/x86_64-linux-gnu/libz.so.1"),
)

CLIENT = rb'''# Fixed repository adapter, not a general SMB2 client.
response = ''.b
connection = nil
failed = false
begin
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2.0
  require '/usr/lib/ruby/3.3.0/socket.rb'
  raise 'smb2_profile' unless ARGV.empty? && RUBY_VERSION.start_with?('3.3.')

  def remaining(deadline)
    value = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    raise 'smb2_deadline' unless value > 0
    value
  end

  def wait_for(connection, writable, deadline)
    ready = IO.select(writable ? nil : [connection], writable ? [connection] : nil,
                      nil, remaining(deadline))
    raise 'smb2_deadline' unless ready
  end

  def read_to(connection, response, size, deadline)
    while response.bytesize < size
      remaining(deadline)
      chunk = connection.read_nonblock(size - response.bytesize, exception: false)
      if chunk == :wait_readable
        wait_for(connection, false, deadline)
      elsif chunk.nil? || chunk.empty?
        raise 'smb2_incomplete'
      else
        response << chunk
      end
    end
  end

  # Literal Linux x86-64 sockaddr_in: AF_INET, port 8080, 127.0.0.1.
  # No hostname/service lookup or host resolver configuration is consulted.
  address = "\x02\x00\x1f\x90\x7f\x00\x00\x01".b + "\x00".b * 8
  connection = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, Socket::IPPROTO_TCP)
  remaining(deadline)
  connected = connection.connect_nonblock(address, exception: false)
  if connected == :wait_writable
    wait_for(connection, true, deadline)
    raise 'smb2_connect' unless connection.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int == 0
  elsif connected != 0
    raise 'smb2_connect'
  end

  # Fixed Direct TCP SMB2 NEGOTIATE. Dialects 0x0210/0x0302 only, signing
  # enabled, capabilities zero, nonzero fixed client GUID, message/session zero.
  # No authentication token, hostname, share name or response-selected bytes.
  request = [
    '00000068fe534d4240000000000000000000010000000000000000000000000000000000',
    '000000000000000000000000000000000000000000000000000000000000000024000200',
    '010000000000000018764adc93774428a96643d43d6e6bd4000000000000000010020203'
  ].join.then { |hex| [hex].pack('H*') }
  sent = 0
  while sent < request.bytesize
    remaining(deadline)
    count = connection.write_nonblock(request.byteslice(sent, request.bytesize - sent), exception: false)
    if count == :wait_writable
      wait_for(connection, true, deadline)
    elsif count.is_a?(Integer) && count > 0
      sent += count
    else
      raise 'smb2_write'
    end
  end
  # Permanently close this socket's write side before reading metadata. The
  # owned fixture witnesses the EOF, so no reply can elicit more client bytes.
  connection.shutdown(Socket::SHUT_WR)

  read_to(connection, response, 4, deadline)
  raise 'smb2_transport_type' unless response.getbyte(0) == 0
  size = (response.getbyte(1) << 16) | (response.getbyte(2) << 8) | response.getbyte(3)
  raise 'smb2_frame_limit' unless size >= 72 && size <= 4096
  read_to(connection, response, 4 + size, deadline)
  # End at the first complete frame. Opaque server security bytes stay data.
  # No EOF wait, NTLM, SESSION_SETUP, tree/share access, second connection,
  # or response-directed operation exists here.
rescue StandardError
  failed = true
ensure
  connection.close if connection && !connection.closed?
  STDOUT.binmode
  STDOUT.write(response)
  STDOUT.flush
end
if failed
  STDERR.write("smb2_negotiate_metadata_failed\n")
  exit 1
end
'''
COMPILED = (("compiled:smb2-negotiate-metadata", SCRIPT_PATH, CLIENT),)


def fixed_entries():
    return ((EXECUTABLE, DESTINATION), *((path, path) for path in RUBY_FILES),
        *NATIVE_FILES, *((source, destination) for source, destination, _ in COMPILED))


def validate_manifest(value, *, tool_id=None):
    from .network_tools_runtime import encode
    if (type(value) is not dict
            or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE or value["tool_id"] != TOOL_ID
            or tool_id not in (None, TOOL_ID) or value["executable"] != DESTINATION
            or value["interpreter"] != INTERPRETER or type(value["files"]) is not list
            or len(value["files"]) != len(fixed_entries()) or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_smb2_runtime_manifest")
    fixed = set(fixed_entries())
    compiled = {destination: (source, raw) for source, destination, raw in COMPILED}
    present, destinations, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["source"]) is not str or type(row["destination"]) is not str
                or type(row["size"]) is not int or not 1 <= row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])):
            raise ValueError("invalid_smb2_runtime_file")
        source, destination = row["source"], row["destination"]
        if (source, destination) not in fixed or destination in destinations:
            raise ValueError("invalid_smb2_runtime_path")
        if destination in compiled:
            expected, raw = compiled[destination]
            if source != expected or row["size"] != len(raw) or row["sha256"] != hashlib.sha256(raw).hexdigest():
                raise ValueError("invalid_smb2_compiled_client")
        present.add((source, destination))
        destinations.add(destination)
        total += row["size"]
    if (present != fixed or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])):
        raise ValueError("invalid_smb2_runtime_closure")
    return value


def inspect_runtime(control: ExecutionControl):
    entries, native = [], []
    compiled = {source: raw for source, _, raw in COMPILED}
    for source, destination in fixed_entries():
        control.check()
        if source in compiled:
            raw = compiled[source]
        else:
            if str(Path(source).resolve(strict=True)) != source:
                raise IsolationUnavailable("SMB2 requires the reviewed distribution file layout")
            raw = _read_regular(source)
        if source == EXECUTABLE or source.endswith(".so"):
            if not raw.startswith(b"\x7fELF"):
                raise IsolationUnavailable("SMB2 native runtime must contain ELF files")
            native.append(source)
        entries.append({"source": source, "destination": destination, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()})
    listing = _runtime_probe([_trusted_program("ldd"), *native], 5, 32768, control).decode("ascii")
    paths = sorted(set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing)))
    if ("not found" in listing or INTERPRETER not in paths
            or any(not LIBRARY.fullmatch(path) for path in paths)
            or {(str(Path(path).resolve(strict=True)), path) for path in paths} != set(NATIVE_FILES)):
        raise IsolationUnavailable("SMB2 dependencies differ from the reviewed finite closure")
    return validate_manifest({"version": "1", "profile": PROFILE, "tool_id": TOOL_ID,
        "executable": DESTINATION, "interpreter": INTERPRETER,
        "files": sorted(entries, key=lambda row: row["destination"])})
