# Stock nginx: source review and non-executing runtime preparation

**S3.2a, 14 October 2026.** This is the bounded first part of the
[Stage 3 nginx diagnostic](stage3-compatibility-routing.md), following accepted
S3.1 in [PR #87](https://github.com/0xsl0th/recon-cockpit/pull/87) at `48c0bce`.
It reviews actual upstream/distribution source and prepares immutable inputs
for the 26 declared trials. It does not start nginx, test its configuration,
create a listener, grant an action or establish service compatibility.

The source findings support a small candidate: one foreground nginx process
serving compiled public responses on a private pathname Unix socket, behind a
separately bounded recorder. The next S3.2b slice must implement its independent
diagnostic admission/owner boundary and prove actual execution. Splitting S3.2
into these two reviewable parts uses eight PRs in the Stage 3 estimate; it does
not add a new milestone or replace the required native result with preparation.
Accepted coverage remains **52 profiles / 17 programs**. Credentials, paid/live
models, external or attached networks, deeper workflows and benchmarking remain
deferred.

## Pinned source and installed binary

The current Debian mirror no longer retained this exact revision. The official
Debian snapshot supplied its source descriptor, patch archive and binary package.
Files are retained privately under
`.secure-agent/stock-nginx-20261014/source-review/`; none belongs in Git.

| Primary source / artifact | SHA-256 | Verified relationship |
| --- | --- | --- |
| [Official nginx 1.28.0 source archive](https://nginx.org/download/nginx-1.28.0.tar.gz) | `c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a` | 1,280,111 bytes; identical digest and size to the upstream archive named in the Debian descriptor. |
| [Debian nginx 1.28.0-6 source descriptor](https://snapshot.debian.org/archive/debian/20251215T000000Z/pool/main/n/nginx/nginx_1.28.0-6.dsc) | `74f4ba25bdc2f499ed8e4d6024ac893494f10a4ccf1ace4e917a06843fa137f4` | Declares source version `1.28.0-6` and hashes of the upstream and Debian archives. |
| [Exact Debian packaging and patches](https://snapshot.debian.org/archive/debian/20251215T000000Z/pool/main/n/nginx/nginx_1.28.0-6.debian.tar.xz) | `28e72be9c3c6baa5bd00258ec27760f74a9ae801c7376704255c7c07d544fc54` | 73,032 bytes; matches the descriptor. All four listed patches applied to a private source copy with zero fuzz and no offsets. |
| [Archived amd64 binary package](https://snapshot.debian.org/archive/debian/20251215T000000Z/pool/main/n/nginx/nginx_1.28.0-6_amd64.deb) | `7935a2b9016c26c6d627a458074757bb96d56059dab2a48065cdb275386c7c26` | 671,512 bytes; inspected as archive data only. Its nginx ELF is byte-identical to the installed executable. |
| Installed `/usr/sbin/nginx` | `5375eebf429718d099ed8480bcfcb55065b19d1a1a66522b9724f54caf088491` | 1,668,240 bytes; reported package/source version `1.28.0-6`, executable mode 0755. |

The comparison ties the reviewed release/packaging to the archived installed
binary; it is not a reproducible-build verification. The source descriptor's
embedded maintainer signature was not independently verified with a signing
key. Archive hashes, official HTTPS origins, patch application and exact binary
comparison are recorded separately rather than presented as a stronger proof.
No source was built or executed and no package was installed.

The four Debian patches have distinct effects:

- `nginx-fix-pidfile.patch` changes daemonization/pidfile handling in
  `src/core/nginx.c` and `src/os/unix/ngx_daemon.c`. With `daemon off`, the fork
  branch is skipped and foreground pidfile creation remains; a writable private
  pid path is still necessary.
- `nginx-ssl_cert_cb_yield.patch` handles asynchronous certificate-callback
  results in TLS handshake/write paths. It does not remove early OpenSSL
  initialization from plaintext nginx startup.
- `CVE-2025-53859.patch` changes mail-authentication handling. The proposed HTTP
  configuration loads no mail module and creates no mail listener.
- `override-uname.patch` adds reproducible build-system overrides. Its Linux,
  release and machine flags agree with the installed `nginx -V` output; it does
  not change the selected HTTP response path.

`patch-application.json` retains patch hashes and application output.
`installed-package-comparison.json` retains the archive/installed ELF comparison.
The source-review receipt records the relevant reviewed files and their hashes.

## Startup findings that determine the configuration

The references below name files/functions in the pinned upstream archive and
the separately retained Debian-patched copy. These are source findings, not
observed sandbox startup results.

| Source finding | Required preparation / later boundary |
| --- | --- |
| `src/core/nginx.c:ngx_core_module_init_conf` looks up the compiled default user/group when effective UID is zero. `ngx_set_user` also resolves explicit names through `getpwnam`/`getgrnam`. | Supply generated `reconlab` passwd/group entries with UID/GID zero in the single unprivileged user mapping, and `passwd: files` / `group: files` NSS configuration. Never mount host account databases. Namespace-local UID zero is not host root. |
| `nginx.c:main` honors `daemon off`, and `master_process off` selects `ngx_single_process_cycle`. `src/os/unix/ngx_process_cycle.c` invokes module initialization and its event loop directly in that mode. | Use foreground single-process mode. Do not infer a no-thread guarantee merely from this branch: compiled module callbacks still require review and native enforcement. No thread pool, AIO, cache manager or dynamic module is configured. |
| `nginx.c:main` calls `ngx_ssl_init` before parsing nginx.conf. `src/event/ngx_event_openssl.c:ngx_ssl_init` requests OpenSSL configuration loading. | Set `OPENSSL_CONF=/tool/data/openssl.cnf` in the bootstrap environment, pointing to a generated comment-only configuration. A later `env OPENSSL_CONF;` directive alone would be too late. Pin the actual linked OpenSSL files even though the diagnostic is plaintext. |
| `src/core/ngx_cycle.c:ngx_init_cycle` creates registered temporary paths and initializes modules. HTTP module merge functions register temp directories even without a proxy request. | Redirect all five client-body/proxy/FastCGI/SCGI/uWSGI temp paths under bounded `/scratch`; use private pid/lock paths and stderr logging. No host `/var/lib/nginx`, `/run`, log path or wildcard include enters the closure. |
| `src/core/ngx_connection.c:ngx_open_listening_sockets` supports pathname Unix listeners and changes their mode to 0666. | Privacy must come from the 0700 parent directory, absent client mount and the client's AF_UNIX denial, not socket mode. A later explicit bypass witness must prove the client cannot reach the private listener. |
| `ngx_init_cycle` opens listeners during configuration testing; the local nginx manual says `-t` opens referenced files. The Unix-listener path is removed again in test mode. | Do not call `nginx -t` or `-T` as a harmless metadata check in this preparation slice. Informational `-V`, file inspection and generated-byte validation do not establish that the configuration parses or starts. |

The installed build contains multiple static HTTP modules and supports dynamic
modules. The candidate config uses no `load_module`, `include`, resolver, proxy,
upstream, certificate fetch, authenticated operation or host environment input.
This limits configured behavior; it does not mean the compiled-in code is absent.
Source review and dynamic-library discovery cannot enumerate every future
startup read or establish syscall compatibility. The next slice must refuse
unreviewed dependencies rather than mounting broad host directories.

## Exact proposed configuration and runtime inputs

[stock_http_spec.py](../recon_cockpit/secure_agent/stock_http_spec.py) describes
only the closed A/B endpoint and O1–O6/R1–R2/N1–N5 selections. It generates five
files: `/tool/data/nginx.conf`, `/tool/data/openssl.cnf`, `/etc/passwd`,
`/etc/group` and `/etc/nsswitch.conf`. Bodies and directives come from fixed
public constants, not operator text. The selector is metadata and cannot
authorize execution.

The proposed nginx invocation uses an explicit config and prefix with stderr
logging. Configuration selects `daemon off`, `master_process off`,
`user reconlab reconlab`, `/scratch/nginx.pid`, `/scratch/nginx.lock` and
`listen unix:/scratch/nginx.sock`. It disables access logs, gzip, chunked transfer
encoding and HTTP keepalive, sets a small worker connection count, and exposes
only the exact root probe and selected header path. A fallback location refuses
other paths; the recorder must reject any undeclared request before forwarding,
so this fallback does not replace request authorization.

Literal `return` responses keep the ordinary corpus small while nginx itself
parses the request and generates the HTTP response. In
`src/http/ngx_http_core_module.c:ngx_http_send_response`, nonredirect bodies set
the Content-Length from their exact length. Redirect statuses instead set a
Location and use the normal special-response path. O4 therefore supplies the
declared other endpoint as the redirect value; it does not treat arbitrary text
as a redirect body. `ngx_http_header_filter_module.c` and
`ngx_http_special_response.c` supply normal server/date/status/framing fields.
The response is not byte-pinned in advance: retain and validate actual received
bytes, including dynamic Date and advertised server values.

The generated cases retain the contract's exact headers, status, version setting
and hostile body. R2 must preserve every daemon byte. N1–N5 retain a valid daemon
reply separately from their later transport fault; N4's overflow is not a claim
that nginx violates a cap. No recorder or transformation executes in S3.2a.

The x86-64 candidate links libcrypt, PCRE2, libssl, libcrypto, zlib, libc and
libzstd through `/lib64/ld-linux-x86-64.so.2`, resolving to canonical files under
`/usr/lib/x86_64-linux-gnu/`. nginx reports OpenSSL 3.5.2 at build time and 3.6.2
at runtime: pin actual bytes, not only package versions. Other architectures,
distributions and dependency sets are outside this narrow preflight contract.

The intended bootstrap environment fixes `LC_ALL=C`, `MALLOC_ARENA_MAX=1`,
`OPENSSL_CONF=/tool/data/openssl.cnf` and `TZ=UTC0`. The empty OpenSSL config has
no includes/providers, and generated NSS rules select files only. Dynamic-loader
dependency inspection does not prove the absence of additional NSS/OpenSSL or
module startup reads; successful confined startup remains an explicit open test.

## Required next execution work

The accepted configurable service enforces four ordered actions. Its existing
action constructors can describe the proposed Nmap/header input, but they cannot
make these independent trials executable. Likewise, the earlier hierarchy
diagnostic deliberately sits outside production authority and is not an
authorized launch path to copy. S3.2b needs its own versioned one-action
diagnostic request/admission contract, retaining durable audit, fresh approval
when required, independently checked authorization and exact runtime/owner
binding before native execution.

Reuse existing lifecycle, sealed runtime, client and inspection primitives.
The recorder needs exact request admission, independent attempts/delivery counts,
separate original/transformed streams, caps and private-listener bypass prevention.
Separate daemon/recorder resource bounds, kernel-bounded aggregate scratch,
cancellation, descendant cleanup and unchanged inspection need actual trials.

The unchanged acceptance target is **12 ordinary completions, four robustness
completions, ten correctly inconclusive negative cases and 16 blocked destination
checks**, plus every declared authority, budget and cleanup test. None has been
run by this preparation step. Ordinary blocking cannot count as usefulness.
Native compatibility, enforced limits and production support remain unverified;
zero provider calls/spend and deferred comparative overhead remain mandatory.
