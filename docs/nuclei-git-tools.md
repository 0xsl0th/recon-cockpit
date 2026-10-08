# Owned Git HEAD marker check

C17 is in development on `feature/nuclei-git-head-coverage`. **Native validation
and acceptance are pending.** It adds `nuclei_git_head_v1` to the secure CLI using
the existing pinned Nuclei executable and authority services. The working catalog
contains 42 profiles using 16 external programs; acceptance remains at C16's
41 profiles until the C17 gates are complete.

C16 is accepted through [PR #71](https://github.com/0xsl0th/recon-cockpit/pull/71)
on main `1cfbf8b`; all five post-merge checks now pass. Its
[directory-listing runbook](nuclei-tools.md), compiled template, runtime limits,
accepted evidence and failure history remain regression anchors.

## Exact operation and finite predicate

One compiled template sends one GET to the disconnected owned
`http://127.0.0.1:8080/.git/HEAD` fixture. Its named matcher,
`git-head-signature`, requires all of:

- HTTP status 200.
- Exact content type `text/plain; charset=us-ascii`.
- The complete body is exactly `b"ref: refs/heads/main\n"` or
  `b"ref: refs/heads/release\n"`, including the final LF and no other bytes.

The compiled check uses documented [Nuclei DSL matchers](https://docs.projectdiscovery.io/templates/reference/matchers)
and the [hex encoding helper](https://docs.projectdiscovery.io/templates/reference/helper-functions).
It compares `hex_encode(body)` to fixed literals so the terminal LF is part of
the predicate without expression-string newline ambiguity. Template syntax alone
does not establish native completion or matcher agreement.

The complete request contract is:

```http
GET /.git/HEAD HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: recon-cockpit-owned-nuclei/1
Accept: */*
Accept-Encoding: identity
Accept-Language: en
Connection: close
```

Wire framing uses CRLF and an empty terminating line, with no request body. The
owner requires all six fixed-value headers, accepts no additional headers and
reads at most 1024 bytes. It validates the complete request before counting or
replying. There is no file backend: the branch references and every response are
finite synthetic bytes. No reference, object, configuration, repository content,
source file or credential is fetched. Redirects, retries, extractors, returned-ref
follow-up, DNS lookup and additional templates are outside the operation.

A useful result requires exactly one observed connection and one validated GET.
These counters establish observed progress; they are not a kernel quota proving
that a compromised image cannot attempt another connection or payload. Network
confinement and forbidden-destination witnesses remain separate requirements.

## Separate contract, shared boundary

C17 has its own tool identity, fixed template and response parser. It reuses the
reviewed C16 static-runtime worker and transport helpers through a fixed tool-ID
selection; caller input cannot supply a template, executable, environment or path.

| Identity | C17 value |
| --- | --- |
| Tool | `nuclei_git_head_v1` |
| Runtime profile | `network-tools-nuclei-git-static-runtime-v1` |
| Template | `recon-owned-git-head-v1`, mounted at `/tool/data/git-head.yaml` |
| Parser | `nuclei-git-head-v1` |
| Workflow card | Version `25`; C16 retains version `24`. |
| Fixed parameters | Port 8080, five-second tool deadline, 8192 output bytes. |
| Session | One action, 60 seconds, 8192 output bytes. |

The runtime retains C16's existing limits:

| Boundary | Limit |
| --- | --- |
| Read-only pinned runtime | 160 MiB per file; 192 MiB total closure. |
| Trusted outer staging | 160 MiB file-size ceiling during sealed-image preparation. |
| Tool scratch | Private session tmpfs, 8 MiB and 128 inodes, `noexec,nodev,nosuid`. |
| Tool writes | 64 KiB per file; Landlock permits writes only inside scratch. |
| Tool resources | 16 mapped-UID tasks, 2 GiB address space, 64 descriptors, no core files. |
| CPU and deadline | Five CPU seconds and a five-second tool deadline. |
| Native response controls | Read cap 2048 bytes; saved-response cap 4096 bytes. |
| Retained output | At most 8192 combined stdout/stderr bytes. |
| Owner response capture | At most 4096 actual send-acknowledged bytes. |

The staging allowance does not become the tool's write allowance. Scratch byte,
inode, no-exec, write-confinement and file-size limits require kernel witnesses
before readiness. Setup capability is dropped before execution; cancellation
must reap tasks and destroy the owned lab and scratch. There is no resumption.

The environment is cleared; home, cache, configuration and temporary paths are
inside scratch. Executable and compiled data mounts are read-only. Existing
`GOMAXPROCS=1` and `GOMEMLIMIT=64MiB` settings remain; the latter is a Go runtime
setting, not a hard kernel memory limit. All template-download environment
switches remain disabled. Fixed CLI flags disable updates, Interactsh, cloud
output, stdin, HTTP probing, retries and redirects; exposed concurrency and rate
controls remain one. Exact bytes are in the [C17 runtime](../recon_cockpit/secure_agent/network_tools_nuclei_git_runtime.py)
and [shared C16 runtime](../recon_cockpit/secure_agent/network_tools_nuclei_runtime.py).

## Completion, independent bytes and limitations

Exit zero, empty output or `matcher-status: false` alone never establishes useful
completion. The networkless parser requires one complete supported JSONL event,
empty stderr and fixed tool/template/action/request metadata. It validates the
timestamp as inert data; displayed curl text is never executed. Extra fields,
additional records, errors, malformed output and truncated evidence are refused.

The native response dump may be normalized or transformed. The independent owner
therefore retains only bytes acknowledged by each successful `send`, with
separate send-completion and connection-closure fields. A failed partial send
retains its actual prefix; a stall does not invent response bytes. Owner closure
and complete transmission alone prove neither valid HTTP framing nor reception
by the client.

Owner bytes and native dump must each independently satisfy the new response
contract: HTTP/1.1 200 OK or 404 Not Found; exactly Content-Length, Connection:
close and Content-Type; and a complete declared ASCII body. The permitted content
types are exactly `text/plain; charset=us-ascii` and
`text/html; charset=us-ascii`. Header names are case-insensitive and order may
differ. Each representation must be strictly below 4096 bytes, headers at most
1024 bytes and body strictly below 2048 bytes. Transfer/content encoding,
duplicate or unknown headers, conflicting lengths, unsupported body bytes and
possible `***` redaction are rejected.

**Status, content type and body must agree between owner and native
representations.** The independent parser recomputes the exact finite predicate
and requires agreement with Nuclei's matcher Boolean. The closed result contains
separate native-response, original-owner-response and body hashes, fixed request
metadata, status, matcher result and outcome. `vulnerability_verified` is always
false. See the [C17 parser](../recon_cockpit/secure_agent/network_tools_nuclei_git_parser.py).

`signature_present` means only one of these two exact marker bodies was observed
under the complete supported contract. It does not prove that a repository,
retrievable source, sensitive data, exploitability or a verified vulnerability
exists. `signature_absent` means only that this finite predicate was false in a
supported complete response. An unknown branch reference, detached HEAD value,
different line ending or additional body text does not match; a supported ASCII
response of that kind can be `signature_absent`, so absence does not rule out a
Git repository. Unsupported statuses, content types, framing or body shapes are
inconclusive, never evidence of absence.

The hostile HTML case deliberately contains a misleading `ref: refs/heads/main`
marker and instructions to change scope. It must complete as `signature_absent`;
its HTML content type and whole body fail the exact predicate. Such text stays
private raw evidence and grants no target, command, template or follow-up
authority. This deterministic fixture does not establish live-model prompt
injection resistance. The pinned native grammar and independent owner evidence
apply to these owned fixtures, not arbitrary external servers.

## Prerequisites, approval and CLI recipe

Use the already provisioned C16 **Nuclei v3.11.1 Linux amd64** executable at
`/home/sloth/Code/recon-cockpit/.secure-agent/tools/nuclei-3.11.1`. Its size must be
143,294,626 bytes and SHA-256 must be
`c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`.
The runtime verifies the pinned static x86-64 ELF and snapshots it with seven
compiled template/configuration files. No download, binary upgrade, community
template pack, Go toolchain change or new Python dependency is part of C17. A
missing artifact or unavailable Linux confinement prerequisite stops execution.

The [C17 policy](../examples/secure-agent-nuclei-git-policy.json) allows only this
tool, `127.0.0.1/32`, port 8080 and GET, and requires fresh exact-action approval.
Isolated audit, approvals, consumed-grant launch admission, approval/audit
witnesses and the existing namespace and confinement gates remain mandatory.
Denial, cancellation or missing proof cannot fall back to host execution.
Synthetic approval tests demonstrate service behavior; they do not constitute
personal operator acceptance or approve a later run.

Describe the fixed profile without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool nuclei_git_head_v1
```

For a personally approved owned run, choose fresh private output paths. This
recipe requests the ordinary `main` fixture through the full authority path:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment nuclei-git-main \
  --policy examples/secure-agent-nuclei-git-policy.json \
  --assessment-dir .secure-agent/nuclei-git-review/evidence \
  --audit .secure-agent/nuclei-git-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Use `--dry-run` in place of `--execute` to inspect the plan. After an actual run,
`--inspect-assessment .secure-agent/nuclei-git-review/evidence` performs read-only
replay and restores no execution authority. Keep raw evidence, private receipts
and the existing executable outside Git.

## Evaluation plan and pending acceptance

| Group | Cases | Required result |
| --- | --- | --- |
| Ordinary positive | `nuclei-git-main`, `nuclei-git-release` | Both complete with `signature_present`. |
| Ordinary negative | `nuclei-git-no-marker`, `nuclei-git-not-found` | Both complete with `signature_absent`. |
| Separate robustness | `nuclei-git-injected` | Complete with `signature_absent`; hostile HTML remains inert. |
| Inconclusive negatives | `nuclei-git-redirect-ip`, `nuclei-git-redirect-port`, `nuclei-git-incomplete`, `nuclei-git-conflicting-length`, `nuclei-git-oversized`, `nuclei-git-chunked`, `nuclei-git-encoded`, `nuclei-git-stalled` | Validated request progress, no useful result and no unauthorized follow-up. |

Acceptance requires **4/4 ordinary plus 1/1 separate robustness completions**,
zero unnecessary refusals and all eight negative cases remaining inconclusive.
Blocking every case fails usefulness. Record connection/request/closure evidence,
both forbidden destinations, existing and scratch boundary fields, fresh one-use
grants, missing-proof refusal, cancellation, private-input exclusion and UDP
confinement. Independently replay the new evidence and accepted historical
bundles without changing bytes, mtimes or modes. Portable tests cannot substitute
for native Linux witnesses, and native synthetic approvals cannot substitute for
personal acceptance.

The frozen accepted baseline contains **290 cases, 41 adapters and 32 runtimes**.
Its canonical SHA-256 is
`dd5900c5d75230fd09580f7f8ecdfad046f4c7db4f8f69eee59c314c49ceedfc`.
Compare the complete accepted case/action/descriptor/card/spec, adapter,
executable/argv/environment and compiled-byte subsets against that baseline;
exclude only the additive C17 entries. Preserve C16's compiled bytes and every
older snapshot hash and subset count.

Provider/model calls and monetary cost are required to remain zero. Planned
measurements are the secure CLI scenario wall-time range and median, including
authority and evidence capture. No measured latency or comparative-overhead
claim is recorded yet. Final portable/native counts, reconciled evidence paths,
source hashes, usefulness and boundary totals, replay results and G1–G6 status
remain pending.

Development history: the first native trial failed closed before tool readiness
because the outer launcher mounts omitted the new C17 modules. The reviewed
closure was extended with the three required modules; the failed native smoke
and diagnostic evidence are preserved. One normal positive smoke retry then
completed; the full native matrix and portable acceptance remain pending. The
failed attempt is not counted as useful completion or native acceptance.

Credentials, paid/live models, external-target work, deeper workflows,
comparative benchmarking and GUI changes remain deferred. Preserve accepted
B0–B8, C1–C16, offline R5, local R6, the initial GUI and prior failure history,
including the unexplained C9 stall.
