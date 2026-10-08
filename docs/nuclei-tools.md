# Owned Nuclei directory-listing signature check

C16 is an **implementation candidate, locally validated, pending review in
[PR #71](https://github.com/0xsl0th/recon-cockpit/pull/71)**.
It adds `nuclei_directory_listing_v1` through a separate pinned Nuclei runtime,
the secure CLI and existing authority/evidence services. Accepted main remains
**40 profiles using 15 external programs**; the candidate registry has **41/16**.
An installed binary or passing mock test does not close G1–G6. No GUI workflow or
external-target support is added.

The [feasibility assessment](nuclei-feasibility.md) was accepted in
[PR #70](https://github.com/0xsl0th/recon-cockpit/pull/70), reviewed at `c45708e`
and merged as `2f7fb5a` after all five final and post-merge jobs passed. The operator
then authorized this runtime prototype and owned check. That authorization does
not enable community templates, arbitrary scans, credentials or paid model calls.

## Exact check and authority

One compiled template, `recon-owned-directory-listing-v1`, sends one HTTP GET to
`http://127.0.0.1:8080/public/` in a disconnected owned namespace. A single named
DSL matcher requires status 200 and all three exact body fragments:

- `<title>Index of /public/</title>`
- `<h1>Index of /public/</h1>`
- `href="../"`

There are no extractors, discovered-path requests, link traversal, file downloads,
retries, redirect following, host discovery, DNS lookups or additional templates.
The fixture validates the complete bounded request before counting or replying.
The actual native request is pinned, including Nuclei's additional Accept headers:

```http
GET /public/ HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: recon-cockpit-owned-nuclei/1
Accept: */*
Accept-Encoding: identity
Accept-Language: en
Connection: close
```

Wire framing uses CRLF and an empty terminating line, with no body. The owner
requires all six headers with fixed values and accepts no others. Request size is
at most 1024 bytes. One accepted connection and one validated GET are required;
there is no broad service backend. Counts are observed evidence, not a kernel
proof that a compromised image could never attempt another connect or payload.

The [policy](../examples/secure-agent-nuclei-policy.json) requires GET permission
and fresh exact-action approval. Isolated audit, approvals, consumed-grant launch
admission, direct approval/audit witnesses, scoped namespaces and confinement are
mandatory. Denial, cancellation, missing proof or an unavailable boundary cannot
fall back to a host invocation. Captured instructions cannot select a target,
path, template, command or new authority.

## Separate static runtime and scratch boundary

The pinned official **Nuclei v3.11.1 Linux amd64** executable is provisioned at
`/home/sloth/Code/recon-cockpit/.secure-agent/tools/nuclei-3.11.1` and is not tracked
in Git. Its 143,294,626 bytes must hash to
`c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`.
Only that static x86-64 ELF and seven compiled configuration/template files form
the manifest; dynamic loaders and caller-selected files are rejected. Source
bytes are streamed into sealed snapshots under the authority deadline. The
private provisioned path is a local prerequisite, not a portable installation
recipe or an automatic download/update mechanism.

Stock startup requires temporary writes, so this versioned profile has private
scratch. Existing profiles retain their accepted runtime bytes and limits.

| Boundary | Candidate limit |
| --- | --- |
| Pinned read-only files | 160 MiB per file; 192 MiB total runtime closure. |
| Trusted outer staging | Separate 160 MiB file-size ceiling only while preparing the sealed Nuclei image. |
| Tool scratch | Session-owned tmpfs, 8 MiB and 128 inodes, `noexec,nodev,nosuid`; no host bind or persistence. |
| Tool writes | 64 KiB per-file hard limit; Landlock permits writes only to scratch. |
| Tool resources | 16 mapped-UID tasks, 2 GiB address space, 64 descriptors, no core files. |
| Time | Five CPU seconds; five-second tool deadline within a 60-second session. |
| Retained tool output | At most 8192 combined stdout/stderr bytes. |
| Owner response evidence | At most 4096 actual send-acknowledged bytes, with separate completion/closure fields. |

The larger staging ceiling does not become the executing tool's write allowance.
Scratch allocation/inode, no-exec, write confinement and per-file limits require
kernel witnesses before tool readiness. Mount setup capability is confined to the
trusted setup phase and dropped before execution. Cancellation reaps tasks and
tears down the owned lab and scratch; no approval or scratch state is resumed.

The environment is cleared. Home, configuration, cache and temporary paths are
inside scratch; executable/template mounts remain read-only. `GOMAXPROCS=1` and
`GOMEMLIMIT=64MiB` restrict Go behavior, but the latter is not a hard kernel memory
bound. All five template-download environment switches are disabled. Fixed CLI
controls disable updates, Interactsh, cloud output, stdin, HTTP probing, retries
and redirects, with every exposed concurrency/rate control set to one. Request
read/save limits are 2048/4096 bytes; evidence validation is still required.
Exact bytes and argv live in the [runtime](../recon_cockpit/secure_agent/network_tools_nuclei_runtime.py).
No Python dependency, Go toolchain upgrade or community template pack is needed.

## Completion and interpretation

A zero exit code, empty output or `matcher-status: false` alone never proves useful
completion. The networkless parser requires exactly one complete supported JSONL
record, empty stderr, fixed template/action metadata and the exact native request.
Timestamp text is validated as inert recorded data; displayed curl text is never
executed. Unknown fields, errors, extra records, malformed or truncated evidence
remain inconclusive.

Nuclei's response dump is normalized and may redact or transform data. It is not
a packet capture: chunk framing can disappear. The independent owner therefore
retains bytes actually acknowledged by `send`, plus send-completion and connection
closure. It never predicts a complete receipt before sending. A partial send or
stall retains only observed progress. This owner receipt proves neither valid
HTTP framing nor client reception by itself.

Both owner bytes and native dump must independently have supported HTTP/1.1
200 OK or 404 Not Found, exactly Content-Length, Connection: close and
Content-Type: text/html; charset=us-ascii, and the complete declared ASCII body.
Header names are case-insensitive and order may differ. Each representation must
be below 4096 bytes, headers at most 1024 bytes and body strictly below 2048 bytes.
Transfer/content encoding, duplicate or unknown headers, ambiguous lengths,
possible `***` redaction and unsupported framing are rejected. Status and body
must agree between representations, and an independent predicate recomputation
must agree with Nuclei's matcher result.

The closed twelve-field result records parser version, kind/semantics, fixed
template/request, status, matcher Boolean, outcome and separate hashes for the
native response dump, original owner response and shared body.
`vulnerability_verified` is always false. A completed `signature_present` means
only this exact directory-listing signature was observed. A completed
`signature_absent` means that predicate was false in this supported response; it
does not mean the endpoint is secure. There is no CVE, exploitability, generic
scanner, product-identity or professional-engagement readiness claim.

Hostile HTML stays private raw evidence and cannot become a plan or follow-up.
The deterministic robustness fixture does not establish live-model prompt-injection
resistance. Native grammar is deliberately pinned to the reviewed v3.11.1 matched
and unmatched output forms; other versions, servers or formatting can be refused.
Original owner evidence is available only for these owned fixtures, so this design
does not establish equivalent completeness on arbitrary external targets.

## Finite evaluation and acceptance gates

| Group | Cases | Required result |
| --- | --- | --- |
| Ordinary positive | `nuclei-index`, `nuclei-index-variant` | Both complete with `signature_present`. |
| Ordinary negative | `nuclei-no-index`, `nuclei-not-found` | Both complete with `signature_absent`. |
| Separate robustness | `nuclei-injected` | Complete useful match; hostile body remains inert. |
| Inconclusive negatives | `nuclei-redirect-ip`, `nuclei-redirect-port`, `nuclei-incomplete`, `nuclei-conflicting-length`, `nuclei-oversized`, `nuclei-chunked`, `nuclei-encoded`, `nuclei-stalled` | Actual validated request progress, no useful result and no unauthorized follow-up. |

Required usefulness is **4/4 ordinary and 1/1 separate robustness completions**,
with zero unnecessary refusals. Blocking everything fails acceptance. All eight
negative cases must remain inconclusive. Record request/connection/closure,
forbidden-destination witnesses, existing and scratch boundary fields, one-use
approval, missing-proof refusal, cancellation, private-input exclusion and UDP
confinement. Provider calls and cost must remain zero. Report scenario wall-time
range and median descriptively; no comparative-overhead benchmark is claimed.

**Local results:** clean implementation `5fe5c3465bf2565e6dac509259874ee62809db45`
passed all 21 native workflow/authority tests. Two Linux memfd/sealing tests also
passed separately; these are integration tests so the portable macOS job does not
substitute skips for evidence. The thirteen actual trials achieved 4/4 ordinary
completions and 1/1 robustness completion, with zero unnecessary refusals. All
eight negative cases remained inconclusive after one validated GET. All 26
forbidden-destination witnesses and 195 boundary fields passed. Cancellation,
private inputs, one-use grants, missing proof and weakened scratch/task boundaries
were exercised. No paid/provider calls or real credentials were used.

The independent audit reconciled both parser paths and every new artifact, then
replayed 107 accepted bundles through service and CLI without changing their
bytes, mtimes or modes. All 694 source-file hashes matched the clean implementation
before and after this audit. Accepted case/action/descriptor/card/spec, adapter,
argv and environment snapshots remain byte-identical for 277 cases, 40 adapters
and 31 runtimes. Secure CLI trial wall time was **4477–6405 ms, median 4522 ms**,
including authority and evidence capture; this is not an overhead comparison.
All **18,958 portable tests passed**, with zero skips, failures or errors.
G1–G5 are locally validated; G6 stays open until PR review and required checks pass.

Private evidence is retained under `.secure-agent/nuclei-runtime-20261008/`:
`native-confirmed/`, `native-confirmed.xml`, `native-sealing.xml`,
`native-source-pin.json`, `accepted-baseline-comparison.json` and `verification.json`.
The verification receipt SHA-256 is `a3dc80c9bafc9eb9a9081335dfb7703f2ac85f9349ffb71b2c4d109f632954fb`.
No raw assessment, executable or private receipt is added to Git.

Development history remains visible: the first staging attempt hit the legacy
file-size cap before native execution; a missing confined fixture module was then
added. The first actual request was rejected for previously unpinned Accept and
Accept-Language headers, which were captured and pinned. The first integrated
report exposed closure assembly including a response receipt in a counter-only
closure; the Nuclei-specific assembly now retains the full previous context while
persisting counters only. The initial full portable run found stale explicit
registry/tag expectations, which were corrected. Hosted macOS CI then exposed four
test-setup failures because its Python does not expose `os.listxattr`; the portable
mock now installs that Linux-specific attribute even when absent. Production
runtime and native validation bytes remain unchanged. These unsuccessful attempts
were not counted as useful completion, and the approved ceilings were not broadened.

## Review and inspect

Describe without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool nuclei_directory_listing_v1
```

The owned execution recipe requires the pinned private artifact, Linux confinement
prerequisites, fresh private paths and personal exact-action approval:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment nuclei-index \
  --policy examples/secure-agent-nuclei-policy.json \
  --assessment-dir .secure-agent/nuclei-review/evidence \
  --audit .secure-agent/nuclei-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Use `--inspect-assessment .secure-agent/nuclei-review/evidence` for read-only replay;
inspection restores neither approvals nor execution authority. Raw artifacts and
the downloaded executable remain private, outside Git.

Next complete independent review and required checks for this candidate. After
acceptance, select the smallest remaining HTTP security-validation gap from the
[coverage checklist](secure-tool-coverage.md#successive-product-coverage-batches),
with another explicitly bounded harmless check and useful negative evidence.
No additional template or deeper workflow is selected by this runbook. B0–B8,
C1–C15, offline R5, accepted local R6 and the initial GUI remain closed. Preserve
prior failure history, including the unexplained C9 stall. Model credentials,
paid/live evaluation, external work and comparative benchmarking remain deferred.
