"""Finite Ruby/WhatWeb 0.6.3 closure for one unauthenticated owned HTTP GET.

Distribution files are read and hashed, never executed during inspection. This
profile deliberately supports the reviewed Debian Ruby 3.3 x86-64 layout only;
missing or differently located dependencies fail closed. No directory trees,
user gems, plugin discovery or host configuration are copied into execution.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from .tool_runtime_common import _read_regular

TOOL_ID = "whatweb_http_fingerprint_v1"
PROFILE = "network-tools-whatweb-runtime-v1"
EXECUTABLE = "/usr/bin/ruby3.3"
DESTINATION = "/tool/ruby"
SCRIPT = "/usr/bin/whatweb"
GUARD_PATH = "/tool/data/whatweb-guard.rb"
URL = "http://127.0.0.1:8080/harbordesk/portal.html"
MAX_MANIFEST_BYTES = 18432
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 224
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
PLUGINS = ("title.rb", "http-server.rb", "x-powered-by-header.rb", "meta-generator.rb", "jquery.rb")
PLUGIN_PATHS = tuple("/usr/share/whatweb/plugins/" + name for name in PLUGINS)
FIXED_ARGV = (DESTINATION, "--disable=did_you_mean,error_highlight,syntax_suggest",
    "-r", GUARD_PATH, "/tool/whatweb", "--aggression=1", "--follow-redirect=never",
    "--max-redirects=0", "--max-threads=1", "--open-timeout=1", "--read-timeout=1",
    "--no-cookies", "--color=never", "--quiet", "--log-json=-",
    "--user-agent=recon-cockpit-c3/1", "--header=Connection:close",
    "--header=Accept-Encoding:identity", "--plugins=" + ",".join(PLUGIN_PATHS), URL)
# No inherited Ruby options, proxies, HOME, gem credentials or loader variables.
ENVIRONMENT = {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1",
    "GEM_HOME": "/tool/no-user-gems",
    "GEM_PATH": "/usr/lib/ruby/gems/3.3.0:/usr/share/rubygems-integration/all:/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0",
    "GEM_SPEC_CACHE": "/tool/no-gem-cache"}
# Explicit finite files, not recursive traversal or host-side code discovery.
RUBY_FILES = (
    '/usr/lib/ruby/3.3.0/bundled_gems.rb',
    '/usr/lib/ruby/3.3.0/cgi.rb',
    '/usr/lib/ruby/3.3.0/cgi/cookie.rb',
    '/usr/lib/ruby/3.3.0/cgi/core.rb',
    '/usr/lib/ruby/3.3.0/cgi/util.rb',
    '/usr/lib/ruby/3.3.0/date.rb',
    '/usr/lib/ruby/3.3.0/digest.rb',
    '/usr/lib/ruby/3.3.0/digest/loader.rb',
    '/usr/lib/ruby/3.3.0/digest/version.rb',
    '/usr/lib/ruby/3.3.0/getoptlong.rb',
    '/usr/lib/ruby/3.3.0/ipaddr.rb',
    '/usr/lib/ruby/3.3.0/monitor.rb',
    '/usr/lib/ruby/3.3.0/net/http.rb',
    '/usr/lib/ruby/3.3.0/net/http/backward.rb',
    '/usr/lib/ruby/3.3.0/net/http/exceptions.rb',
    '/usr/lib/ruby/3.3.0/net/http/generic_request.rb',
    '/usr/lib/ruby/3.3.0/net/http/header.rb',
    '/usr/lib/ruby/3.3.0/net/http/proxy_delta.rb',
    '/usr/lib/ruby/3.3.0/net/http/request.rb',
    '/usr/lib/ruby/3.3.0/net/http/requests.rb',
    '/usr/lib/ruby/3.3.0/net/http/response.rb',
    '/usr/lib/ruby/3.3.0/net/http/responses.rb',
    '/usr/lib/ruby/3.3.0/net/protocol.rb',
    '/usr/lib/ruby/3.3.0/open-uri.rb',
    '/usr/lib/ruby/3.3.0/openssl.rb',
    '/usr/lib/ruby/3.3.0/openssl/bn.rb',
    '/usr/lib/ruby/3.3.0/openssl/buffering.rb',
    '/usr/lib/ruby/3.3.0/openssl/cipher.rb',
    '/usr/lib/ruby/3.3.0/openssl/digest.rb',
    '/usr/lib/ruby/3.3.0/openssl/hmac.rb',
    '/usr/lib/ruby/3.3.0/openssl/marshal.rb',
    '/usr/lib/ruby/3.3.0/openssl/pkcs5.rb',
    '/usr/lib/ruby/3.3.0/openssl/pkey.rb',
    '/usr/lib/ruby/3.3.0/openssl/ssl.rb',
    '/usr/lib/ruby/3.3.0/openssl/version.rb',
    '/usr/lib/ruby/3.3.0/openssl/x509.rb',
    '/usr/lib/ruby/3.3.0/pp.rb',
    '/usr/lib/ruby/3.3.0/prettyprint.rb',
    '/usr/lib/ruby/3.3.0/random/formatter.rb',
    '/usr/lib/ruby/3.3.0/resolv-replace.rb',
    '/usr/lib/ruby/3.3.0/resolv.rb',
    '/usr/lib/ruby/3.3.0/securerandom.rb',
    '/usr/lib/ruby/3.3.0/set.rb',
    '/usr/lib/ruby/3.3.0/socket.rb',
    '/usr/lib/ruby/3.3.0/time.rb',
    '/usr/lib/ruby/3.3.0/timeout.rb',
    '/usr/lib/ruby/3.3.0/uri.rb',
    '/usr/lib/ruby/3.3.0/uri/common.rb',
    '/usr/lib/ruby/3.3.0/uri/file.rb',
    '/usr/lib/ruby/3.3.0/uri/ftp.rb',
    '/usr/lib/ruby/3.3.0/uri/generic.rb',
    '/usr/lib/ruby/3.3.0/uri/http.rb',
    '/usr/lib/ruby/3.3.0/uri/https.rb',
    '/usr/lib/ruby/3.3.0/uri/ldap.rb',
    '/usr/lib/ruby/3.3.0/uri/ldaps.rb',
    '/usr/lib/ruby/3.3.0/uri/mailto.rb',
    '/usr/lib/ruby/3.3.0/uri/rfc2396_parser.rb',
    '/usr/lib/ruby/3.3.0/uri/rfc3986_parser.rb',
    '/usr/lib/ruby/3.3.0/uri/version.rb',
    '/usr/lib/ruby/3.3.0/uri/ws.rb',
    '/usr/lib/ruby/3.3.0/uri/wss.rb',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/cgi-0.4.2.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/date-3.3.4.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/digest-3.1.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/getoptlong-0.2.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/io-nonblock-0.3.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/io-wait-0.3.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/ipaddr-1.2.6.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/net-http-0.4.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/net-protocol-0.2.2.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/open-uri-0.4.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/openssl-3.2.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/pp-0.5.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/prettyprint-0.2.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/resolv-0.3.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/resolv-replace-0.1.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/securerandom-0.3.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/set-1.1.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/stringio-3.1.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/time-0.3.0.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/timeout-0.4.1.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/uri-0.13.2.gemspec',
    '/usr/lib/ruby/gems/3.3.0/specifications/default/zlib-3.1.1.gemspec',
    '/usr/lib/ruby/vendor_ruby/colour.rb',
    '/usr/lib/ruby/vendor_ruby/extend-http.rb',
    '/usr/lib/ruby/vendor_ruby/gems.rb',
    '/usr/lib/ruby/vendor_ruby/helper.rb',
    '/usr/lib/ruby/vendor_ruby/http-status.rb',
    '/usr/lib/ruby/vendor_ruby/messages.rb',
    '/usr/lib/ruby/vendor_ruby/plugin_support.rb',
    '/usr/lib/ruby/vendor_ruby/plugins.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/basic_specification.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/compatibility.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_gem.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/defaults.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/defaults/operating_system.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/dependency.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/deprecate.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/errors.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/exceptions.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/path_support.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/platform.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/requirement.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/specification.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/specification_record.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/stub_specification.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/target_rbconfig.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/unknown_command_spell_checker.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/util.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/util/list.rb',
    '/usr/lib/ruby/vendor_ruby/rubygems/version.rb',
    '/usr/lib/ruby/vendor_ruby/target.rb',
    '/usr/lib/ruby/vendor_ruby/version_class.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/banner.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/logging.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/logging/errors.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/logging/json.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/parser.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/redirect.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/scan.rb',
    '/usr/lib/ruby/vendor_ruby/whatweb/version.rb',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/cgi/escape.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/date_core.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/digest.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/digest/md5.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/enc/encdb.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/enc/trans/transdb.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/io/nonblock.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/io/wait.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/monitor.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/openssl.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/rbconfig.rb',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/socket.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/stringio.so',
    '/usr/lib/x86_64-linux-gnu/ruby/3.3.0/zlib.so',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/extensions/x86_64-linux-gnu/3.3.0/json-2.15.2/json/ext/generator.so',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/extensions/x86_64-linux-gnu/3.3.0/json-2.15.2/json/ext/parser.so',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/gems/json-2.15.2/lib/json.rb',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/gems/json-2.15.2/lib/json/common.rb',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/gems/json-2.15.2/lib/json/ext.rb',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/gems/json-2.15.2/lib/json/ext/generator/state.rb',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/gems/json-2.15.2/lib/json/version.rb',
    '/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/specifications/json-2.15.2.gemspec',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/data/unicode.data',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable.rb',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable/idna.rb',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable/idna/pure.rb',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable/template.rb',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable/uri.rb',
    '/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib/addressable/version.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix/domain.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix/errors.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix/list.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix/rule.rb',
    '/usr/share/rubygems-integration/all/gems/public_suffix-6.0.2/lib/public_suffix/version.rb',
    '/usr/share/rubygems-integration/all/specifications/addressable-2.8.7.gemspec',
    '/usr/share/rubygems-integration/all/specifications/public_suffix-6.0.2.gemspec',
)

# Exact reviewed loader/library aliases, independently checked against ldd.
NATIVE_FILES = (
    ('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', '/lib64/ld-linux-x86-64.so.2'),
    ('/usr/lib/x86_64-linux-gnu/libc.so.6', '/usr/lib/x86_64-linux-gnu/libc.so.6'),
    ('/usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0', '/usr/lib/x86_64-linux-gnu/libcrypt.so.1'),
    ('/usr/lib/x86_64-linux-gnu/libcrypto.so.3', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'),
    ('/usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0', '/usr/lib/x86_64-linux-gnu/libgmp.so.10'),
    ('/usr/lib/x86_64-linux-gnu/libm.so.6', '/usr/lib/x86_64-linux-gnu/libm.so.6'),
    ('/usr/lib/x86_64-linux-gnu/libruby-3.3.so.3.3.8', '/usr/lib/x86_64-linux-gnu/libruby-3.3.so.3.3'),
    ('/usr/lib/x86_64-linux-gnu/libssl.so.3', '/usr/lib/x86_64-linux-gnu/libssl.so.3'),
    ('/usr/lib/x86_64-linux-gnu/libz.so.1.3.2', '/usr/lib/x86_64-linux-gnu/libz.so.1'),
    ('/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7', '/usr/lib/x86_64-linux-gnu/libzstd.so.1'),
)

GUARD = rb'''# Trusted, byte-pinned confinement supplement; never evaluates response bytes.
require 'whatweb'
raise 'unsupported_whatweb_runtime' unless WhatWeb::VERSION == '0.6.3' && RUBY_VERSION.start_with?('3.3.')
Regexp.timeout = 0.05
module ReconWhatWebBound
  @lock = Mutex.new
  @connections = 0
  @requests = 0
  @received = 0
  class << self
    def connection!(host, port, tls, proxy)
      @lock.synchronize do
        raise 'whatweb_connection_refused' unless host == '127.0.0.1' && port == 8080 && !tls && !proxy && @connections == 0
        @connections += 1
      end
    end
    def request!(request, path)
      @lock.synchronize do
        expected = {'host'=>'127.0.0.1:8080', 'user-agent'=>'recon-cockpit-c3/1',
          'accept'=>'*/*', 'accept-encoding'=>'identity', 'connection'=>'close'}
        actual = request.to_hash.transform_values { |values| values.length == 1 ? values[0] : nil }
        raise 'whatweb_request_refused' unless @connections == 1 && @requests == 0 && request.method == 'GET' &&
          request.path == '/harbordesk/portal.html' && path == request.path && actual == expected &&
          request.body.nil? && request.body_stream.nil? && !request.decode_content
        @requests += 1
      end
    end
    def remaining
      @lock.synchronize { 8193 - @received }
    end
    def received!(value)
      @lock.synchronize do
        @received += value.bytesize
        raise 'whatweb_input_limit' if @received > 8192
      end
    end
  end
end
module ReconWhatWebConnect
  def connect
    ReconWhatWebBound.connection!(@address, @port, use_ssl?, proxy?)
    super
  end
  private :connect
end
ExtendedHTTP.prepend(ReconWhatWebConnect)
module ReconWhatWebRequest
  def exec(socket, version, path)
    ReconWhatWebBound.request!(self, path)
    super
  end
end
Net::HTTPGenericRequest.prepend(ReconWhatWebRequest)
module ReconWhatWebRead
  def read_nonblock(length, *args, **kwargs)
    remaining = ReconWhatWebBound.remaining
    raise 'whatweb_input_limit' if remaining <= 0
    result = super([length, remaining].min, *args, **kwargs)
    ReconWhatWebBound.received!(result) if result.is_a?(String)
    result
  end
end
TCPSocket.prepend(ReconWhatWebRead)
module ReconWhatWebResponse
  def read_new(socket)
    response, raw = super
    encoding = response['content-encoding']
    raise 'whatweb_content_encoding_refused' unless encoding.nil? || encoding.downcase == 'identity'
    [response, raw]
  end
end
ExtendedHTTPResponse.singleton_class.prepend(ReconWhatWebResponse)
'''
# RubyGems only tests existence of this build marker. Its compiled nonempty
# content supplies no native code, setup command or mutable gem state.
JSON_MARKER_PATH = "/usr/lib/x86_64-linux-gnu/rubygems-integration/3.3.0/extensions/x86_64-linux-gnu/3.3.0/json-2.15.2/gem.build_complete"
COMPILED = (("compiled:whatweb-guard", GUARD_PATH, GUARD),
    ("compiled:whatweb-json-marker", JSON_MARKER_PATH, b"reviewed native JSON extension\n"))


def fixed_entries():
    return ((EXECUTABLE, DESTINATION), (SCRIPT, "/tool/whatweb"),
        *((path, path) for path in (*RUBY_FILES, *PLUGIN_PATHS)),
        *((source, destination) for source, destination, _ in COMPILED), *NATIVE_FILES)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def compact_manifest(value):
    indexes = {pair: index for index, pair in enumerate(fixed_entries())}
    rows = []
    for item in value["files"]:
        pair = item["source"], item["destination"]
        if pair in indexes:
            rows.append([indexes[pair], item["size"], item["sha256"]])
        else:
            rows.append([item["source"], None if pair[0] == pair[1] else pair[1], item["size"], item["sha256"]])
    return {**value, "profile": PROFILE, "files": rows}


def expanded_files(value):
    fixed = fixed_entries()
    files = []
    for row in value["files"]:
        if type(row) is not list:
            raise ValueError("invalid_whatweb_runtime_row")
        if len(row) == 3 and type(row[0]) is int and 0 <= row[0] < len(fixed):
            source, destination = fixed[row[0]]
            size, digest = row[1:]
        elif len(row) == 4 and type(row[0]) is str and (row[1] is None or type(row[1]) is str):
            source, destination = row[0], row[0] if row[1] is None else row[1]
            size, digest = row[2:]
        else:
            raise ValueError("invalid_whatweb_runtime_row")
        files.append({"source": source, "destination": destination, "size": size, "sha256": digest})
    if compact_manifest({**value, "files": files}) != value:
        raise ValueError("noncanonical_whatweb_runtime_rows")
    return files


def validate_manifest(value, *, tool_id=None):
    if (type(value) is not dict or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE or value["tool_id"] != TOOL_ID
            or tool_id not in (None, TOOL_ID) or value["executable"] != DESTINATION
            or type(value["interpreter"]) is not str
            or not re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:x86_64-linux-gnu/)?ld-linux-x86-64\.so\.2", value["interpreter"])
            or type(value["files"]) is not list or len(value["files"]) != len(fixed_entries())
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_whatweb_runtime_manifest")
    files = expanded_files(value)
    fixed = set(fixed_entries())
    compiled = {destination: (source, raw) for source, destination, raw in COMPILED}
    destinations, present, total = set(), set(), 0
    for row in files:
        source, destination, size, digest = (row[key] for key in ("source", "destination", "size", "sha256"))
        if (type(size) is not int or not 1 <= size <= MAX_FILE_BYTES or type(digest) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or any(".." in path or "//" in path for path in (source, destination))):
            raise ValueError("invalid_whatweb_runtime_file")
        pair = source, destination
        accepted = pair in fixed
        if destination in compiled:
            selected_source, raw = compiled[destination]
            accepted = source == selected_source and size == len(raw) and digest == hashlib.sha256(raw).hexdigest()
        if not accepted or destination in destinations:
            raise ValueError("invalid_whatweb_runtime_path")
        destinations.add(destination)
        present.add(pair)
        total += size
    if (not fixed <= present or value["interpreter"] not in destinations or total > MAX_RUNTIME_BYTES
            or files != sorted(files, key=lambda row: row["destination"])):
        raise ValueError("invalid_whatweb_runtime_closure")
    return value


def inspect_runtime(control: ExecutionControl):
    control.check()
    entries = []
    native = []
    compiled = {source: raw for source, _, raw in COMPILED}
    for source, destination in fixed_entries():
        control.check()
        if source in compiled:
            raw = compiled[source]
        else:
            # Only exact reviewed file locations are accepted; no symlink-led
            # Ruby load path or alternate gem/plugin version is discovered.
            if str(Path(source).resolve(strict=True)) != source:
                raise IsolationUnavailable("WhatWeb requires the reviewed distribution file layout")
            raw = _read_regular(source)
        if source == EXECUTABLE or source.endswith(".so"):
            if not raw.startswith(b"\x7fELF"):
                raise IsolationUnavailable("WhatWeb native runtime must contain ELF files")
            native.append(source)
        entries.append({"source": source, "destination": destination, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()})
    listing = _runtime_probe([_trusted_program("ldd"), *native], 5, 65536, control).decode("ascii")
    paths = sorted(set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing)))
    interpreters = [path for path in paths if re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:x86_64-linux-gnu/)?ld-linux-x86-64\.so\.2", path)]
    if "not found" in listing or len(interpreters) != 1 or any(not LIBRARY.fullmatch(path) for path in paths):
        raise IsolationUnavailable("Unsupported WhatWeb dynamic runtime")
    if {(str(Path(path).resolve(strict=True)), path) for path in paths} != set(NATIVE_FILES):
        raise IsolationUnavailable("WhatWeb dependencies differ from the reviewed finite closure")
    return validate_manifest(compact_manifest({"version": "1", "profile": PROFILE, "tool_id": TOOL_ID,
        "executable": DESTINATION, "interpreter": interpreters[0],
        "files": sorted(entries, key=lambda row: row["destination"])}))
