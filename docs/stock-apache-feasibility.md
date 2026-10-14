# Stock Apache: fixed configuration and read-only runtime preparation

S3.2 is accepted in PR #89 at `c068a9d`. **S3.3a is preparation only and awaits
review/acceptance.** It compiles the same 26 A/B corpus selections for Apache,
pins the installed executable, four selected modules and their finite linked
dependencies, and defines the [separate production HTTP contract](stage3-http-production.md).
It creates no service, listener, session, grant or tool action. Apache startup,
private transport and production compatibility remain unverified.

The accepted catalog remains 52 profiles across 17 external programs. Apache is
a possible owned fixture server, not an additional pentest-tool integration.
All accepted milestones remain closed. Network attachment, credentials,
paid/live models, deeper workflows, comparative benchmarks and proposal
submission retain their later gates.

## Source findings and limits

The reviewed upstream source version is Apache HTTP Server **2.4.65**. Local
package metadata reports `2.4.65-3+b1`; this preparation pins the actual installed
bytes. The upstream tag and package metadata do not establish a reproducible
build, verify Debian patches or prove a source-to-installed-binary relationship.
The selection's `reviewed_source_version` context is not a native version probe.

| Primary source finding | Preparation consequence and remaining native gate |
| --- | --- |
| [`mod_unixd.c`](https://github.com/apache/httpd/blob/47490973d568337011e4073099fb570d4151083b/modules/arch/unix/mod_unixd.c) rejects a configured User resolving to UID zero. Its startup code can change user/group when starting as effective root. | Generate `reconlab` passwd/group entries for UID/GID 65534 and require a future nonzero namespace mapping. Never mount host account databases. This input does not prove that mapping, startup or privilege restrictions work. |
| [`prefork.c`](https://github.com/apache/httpd/blob/47490973d568337011e4073099fb570d4151083b/server/mpm/prefork/prefork.c) has a one-process debug path; the [`httpd` command documentation](https://httpd.apache.org/docs/2.4/programs/httpd.html) describes `-X` debugging mode. | Propose the prefork module with `-X`, foreground operation and one configured worker. Native process/thread enforcement and startup must still pass; the flag is not a sandbox. |
| [`listen.c`](https://github.com/apache/httpd/blob/47490973d568337011e4073099fb570d4151083b/server/listen.c) handles IP/port listeners. The [Listen directive](https://httpd.apache.org/docs/2.4/mod/mpm_common.html#listen) uses an address/port contract. | Propose private TCP `127.0.0.1:19080` in a future disconnected daemon namespace. nginx's pathname Unix-socket handoff cannot simply be reused. This grants no host-loopback access. |
| [`mod_so.c`](https://github.com/apache/httpd/blob/47490973d568337011e4073099fb570d4151083b/modules/core/mod_so.c) loads explicitly selected module files. | Pin only prefork, authz_core, headers and alias DSOs individually. Inspect each module's linked dependencies; no module directory, wildcard loading or host config is exposed. Successful loading remains unverified. |
| [`mod_alias.c`](https://github.com/apache/httpd/blob/47490973d568337011e4073099fb570d4151083b/modules/mappers/mod_alias.c) supplies exact-regex aliases and redirects; core provides local error documents and forced response type. | Compile fixed root/selected-file aliases, an O3 local error document and an O4 redirect to the other declared endpoint. Native status/body/framing and redirect non-follow behavior remain required evidence. |
| [ServerTokens](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens), [ForceType](https://httpd.apache.org/docs/2.4/mod/core.html#forcetype), and [Header](https://httpd.apache.org/docs/2.4/mod/mod_headers.html#header) define the selected response settings. | Full/Prod version advertising, HTML response type and fixed security headers preserve the existing observable criteria. Actual Nmap recognition and received bytes must be measured later. |

No `apache2 -t`, `-S`, `-M`, configuration test, service manager, package install
or daemon launch is part of the inspector. Dependency metadata runs only the
fixed trusted `ldd` command against the five exact selected ELF files. This is
not an exhaustive startup trace: NSS, APR mechanisms, filesystem reads and
module initialization can introduce further requirements, which must fail
closed until reviewed during S3.3b.

## Generated configuration and runtime boundary

[stock_apache_spec.py](../recon_cockpit/secure_agent/stock_apache_spec.py) reuses
the accepted stock-HTTP action, request, expected-outcome and budget functions.
Its distinct selection digest covers the proposed Apache argv/environment,
namespace UID/GID, private listener, modules and six generated public files.
No new launch profile is registered, and the planned production contract is
explicitly disabled.

The proposed argv is `/tool/apache2 -X -d /scratch -f /tool/data/apache2.conf`.
The fixed environment is `LC_ALL=C`, `MALLOC_ARENA_MAX=1`, `TZ=UTC0`. Config and
two public HTML files are compiled alongside `/etc/passwd`, `/etc/group` and
`/etc/nsswitch.conf`. Config permits no host includes, `.htaccess`, proxy, CGI,
TLS, authentication, directory listing or response-directed fetch. Optional
security headers are present only in their declared cases. R1 contains the
same inert hostile text; O4's actual server-generated body is not predicted.

Paths for pid/runtime/error log stay under future bounded private `/scratch`.
Static files are read-only proposed inputs. KeepAlive, sendfile and mmap are
disabled. Exact-request admission remains the recorder's responsibility;
configuration routing alone is not authorization. The proposed private listener
must remain inaccessible to the client and host throughout native validation.

[stock_apache_runtime.py](../recon_cockpit/secure_agent/stock_apache_runtime.py)
pins **13 native files and six generated files per selection**: Apache, four
DSOs, the x86-64 loader and seven libraries (APR, APR-util, libc, libcrypt,
libexpat, PCRE2 and libuuid). The executable's linked set is exact, and each DSO
has a separate expected loader/libc dependency set. Native file aliases resolve
only to reviewed canonical locations; extra/missing/changed files and group/world-writable
or nonregular inputs fail inspection. Bounds are 16 MiB per file, 64 MiB total
runtime, 24 manifest files and 16 KiB manifest encoding. Both readiness flags
remain false even after successful inspection.

The reader retains the existing no-follow/stable-file checks and rechecks all
bytes and canonical aliases after metadata probes. Saved manifests validate as
data only; rechecking cannot execute capture-supplied paths or grant an action.
Hash consistency is not protection against a compromised host owner replacing
all evidence. Other distributions, architectures, module sets and library
closures remain outside this finite preparation contract.

## Validation and continuation

```sh
.venv/bin/python scripts/inspect_stock_apache_runtime.py \
  --configuration A --case O1 \
  --output /absolute/private-directory/new-receipt.json
```

The output parent must already be owner-only. Receipts are exclusive 0600 files;
existing paths, final symlinks and public parents are refused before runtime
work. Only A/B and the thirteen fixed case identifiers are accepted. There is
no execute, command, target, binary, model, credential or approval option.
Failures remain recorded as failures and cannot acquire a readiness claim.

Frozen source `274140b17ac3d2d4f2e65ecff5bf938b5199d296` passed **all 26 actual
installed-runtime inspections** and **24,761 portable tests**, with zero
failures, errors or skips. All **882 tracked source hashes** remained unchanged
in each run. Every selection pins the same 13 native files and six case-bound
generated files. Inspection took 72–104 ms per selection; this is metadata
preparation latency, not action latency or comparative overhead.

The focused preparation suite passed 118 checks; a separate 191-case Apache/nginx
spec/runtime run passed. No accepted execution, admission, launcher or catalog
file changed. No server, tool action, authority, provider call or spend occurred.
Private receipts remain under `.secure-agent/stock-apache-20261014/`:

- `preflight-final-01/verification.json`: 26 receipt hashes, runtime pins and all source pins.
- `portable-final-02/verification.json`, `tests.xml` and `pytest.log`: complete portable run outside the coding sandbox and source custody.
- `portable-final-01/`: preserved initial sandbox run; 24,625 passed and 136 tests failed under socket restrictions. It is not a passing full run and no test was excluded to obtain the later result.
- `apache-source-review-partial.json`: upstream tag/commit and reviewed source anchors, installed ELF/module hashes and explicit review limitations.
- `independent-roadmap-cli-review-274140b.json`: scoped documentation/CLI review; its permission-wording correction is applied here.

The upstream tag resolves to commit `47490973d568337011e4073099fb570d4151083b`.
Source bodies were viewed from the official repository, not retained locally:
the separate download attempt stopped before receiving data. Empty attempts
are preserved and count as no source archive or verification. No upstream tag
signature, Debian patch or source-to-binary verification is claimed. The source
review receipt has SHA-256
`57f0848ad7e1f6fca4cdd3ba3b7c74e9cdc1a510fe4912b74e0957c28a0c1bd7`.
Private evidence and source-review material stay outside Git. PR review and
latest checks remain acceptance gates.

After S3.3a acceptance, S3.3b must implement the separately versioned production
boundary and demonstrate all 52 native corpus rows across nginx and Apache,
plus authority/required-approval/audit, private-listener denial, budgets,
cancellation/cleanup, unchanged inspection and accepted-profile regressions.
The nonzero UID and private TCP handoff must be reviewed before starting Apache.
Preparation does not close S3.3 or Stage 3 and does not substitute a different
server for the required Apache comparison.
