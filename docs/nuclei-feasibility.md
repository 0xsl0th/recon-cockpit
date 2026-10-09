# Nuclei: bounded owned HTTP check feasibility

> **Historical assessment; superseded for implementation status on 8 October 2026.**
> PR #70 accepted this feasibility document at `2f7fb5a` (reviewed head `c45708e`),
> after all five final and post-merge CI jobs passed. The operator subsequently
> authorized the separate runtime prototype, private artifact provisioning and
> owned execution. The [C16 runbook](nuclei-tools.md) describes the implementation
> accepted through PR #71 and its actual limits/evidence design. The findings and
> authorization prerequisites below record the earlier data-only assessment, not
> current implementation status. PR #71 brings accepted coverage to 41 profiles
> using 16 programs; no further template or scope is authorized by this history.

## Decision and current scope

The feasibility assessment is complete. Stock Nuclei cannot use the current
read-only, dynamically linked tool profile unchanged. A separate static-executable
profile with tightly bounded private scratch storage needs review before native
integration. No Nuclei installation, execution or secure capability is delivered
by this document. C15/PR #69 is accepted at `e4c9d64`; coverage remains **40 secure
profiles using 15 external programs**. Completed milestones stay closed.

The proposed first operation is one harmless directory-listing signature check
against an owned HTTP fixture. It would add a real assessment engine with useful
matched and unmatched results. It does not establish a generic vulnerability
scanner, CVE detection, exploitability or professional engagement readiness.
Credentials, paid calls, live-model evaluation, deeper workflows, comparative
benchmarking and external engagements remain deferred.

## Evidence and prerequisites

This review uses official Nuclei source commit
[`a8c88feb4a1c8e961b7902534ce3af97e9d524a4`](https://github.com/projectdiscovery/nuclei/tree/a8c88feb4a1c8e961b7902534ce3af97e9d524a4).
Nuclei is absent from the local executable path and has no existing interactive
integration, secure adapter, catalog entry or template. Local Go is
`go1.24.9 linux/amd64`; this source requires
[Go 1.26](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/go.mod#L3).
Building it with the current toolchain is therefore not an available shortcut.
No project Python dependency needs changing for this proposal.

The official [v3.11.1 release](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1)
Linux amd64 ZIP was downloaded as data and inspected without extraction,
installation or execution. It is **46,148,343 bytes**; the executable entry is
**143,294,626 bytes**, approximately 136.7 MiB. Its ELF header is little-endian
64-bit x86-64 `ET_EXEC`, with neither `PT_INTERP` nor `PT_DYNAMIC`. This confirms
incompatibility with the present dynamic-loader requirement, 16 MiB per-file
limit and 64 MiB runtime-closure limit. Private inspection evidence is retained
in `.secure-agent/nuclei-feasibility-20261008/artifact-inspection.json`.

| Artifact | SHA-256 |
| --- | --- |
| Official ZIP | `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6` |
| Executable entry, inspected in memory only | `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251` |

These hashes bind the inspected bytes; inspection does not prove safe execution,
reproducibility from source or compatibility with the proposed runtime.

The runner unconditionally calls `os.MkdirTemp` during initialization and fails
if it cannot create the directory. Configuration/report setup can create files;
shutdown and interrupt handling also manage temporary or resume state. Disabling
updates does not remove those filesystem requirements. See the pinned
[runner](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/internal/runner/runner.go#L259),
[configuration](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/catalog/config/nucleiconfig.go),
[report setup](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/reporting/reporting.go#L209)
and [CLI cleanup](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/cmd/nuclei/main.go#L205).

## Proposed runtime boundary

Reuse exact-action policy, fresh approval, audit, consumed-grant admission, owned
namespaces, destination filtering, cancellation and independent evidence replay.
Reuse byte-pinned sealed files and the existing ffuf/Kerbrute Go confinement
mechanics. Add a separately versioned Nuclei profile; preserve every accepted
profile's executable, file, memory and filesystem limits.

The following are provisional design ceilings, not implemented or validated:

| Resource or effect | Proposed bound |
| --- | --- |
| Read-only executable/closure | 160 MiB per file, 192 MiB total; exact reviewed static ELF hash and compiled template/config only. |
| Private scratch | New session-owned memory filesystem, at most 8 MiB and 128 inodes; no host bind, persistence, sharing or resume. |
| Scratch permissions | Kernel-enforced `noexec`, `nodev`, `nosuid`; Landlock permits writes only inside this mount. |
| Per-file write size | 64 KiB hard limit; scratch limits cover aggregate allocation and file-count exhaustion. |
| Tasks and memory | 16 total mapped-UID tasks, 2 GiB address space; `GOMAXPROCS=1`, `GOMEMLIMIT=64MiB`. The Go heap setting is not a kernel memory guarantee. |
| Time and capture | Five CPU seconds, five-second tool deadline, 60-second session and 8192 combined stdout/stderr bytes. |
| Network | One IPv4 TCP destination, `127.0.0.1:8080`; one GET, no retry, redirect, UDP, DNS or follow-up. |

All scratch paths, including home/config/cache/temp locations, must resolve inside
the private mount. Clear inherited environment, proxy and credential settings.
Keep executable/template mounts read-only; the loader must not execute scratch
content. Cancellation must reap all tasks and destroy scratch and lab state.
No host configuration, report export, project cache, cloud upload, authentication,
code/JavaScript/headless template or arbitrary template path is admitted.

Existing write denial cannot be relaxed globally. If byte/inode limits, no-exec,
path confinement or cleanup cannot be enforced and witnessed in the owned lab,
the candidate fails closed. If startup or the useful check exceeds these resource
ceilings, record the failure and review a concrete revision; do not raise limits
automatically. Static ELF support itself needs reviewed manifest and launch rules.

## One fixed check

Use one compiled template, provisionally `recon-owned-directory-listing-v1`, with
one GET to `http://127.0.0.1:8080/public/`. Its only named DSL matcher requires
status 200, the fixed directory title and heading, and a parent-directory link.
There are no extractors, discovered-path requests or file downloads. This inline
design is unvalidated; it is not a shipped executable template:

```yaml
id: recon-owned-directory-listing-v1
info:
  name: Owned directory-listing signature
  author: recon-cockpit
  severity: info
http:
  - method: GET
    path: ["http://127.0.0.1:8080/public/"]
    headers:
      User-Agent: recon-cockpit-owned-nuclei/1
      Connection: close
      Accept-Encoding: identity
    redirects: false
    matchers:
      - type: dsl
        name: directory-listing-signature
        dsl:
          - "status_code == 200 && contains(body, '<title>Index of /public/</title>') && contains(body, '<h1>Index of /public/</h1>') && contains(body, 'href=\"../\"')"
```

Proposed fixed CLI controls are `-jsonl -matcher-status -omit-template -silent
-no-color -response-size-read 2048 -response-size-save 4096 -dr -retries 0
-no-httpx -no-stdin -duc -ni -dc -timeout 2 -rl 1 -bs 1 -c 1 -pc 1 -prc 1
-tlc 1 -jsc 1`, with only the compiled template/target selected. Keep `-omit-raw` **false** so
request/response evidence is retained. Exact argv, defaults and actual request
bytes must be pinned after authorized native characterization; this is not an
invocation to run now. The pinned [CLI definitions](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/cmd/nuclei/main.go)
provide these controls but do not establish confinement by themselves.

Set all five `DISABLE_NUCLEI_TEMPLATES_*_DOWNLOAD` environment variables to true:
`PUBLIC`, `GITHUB`, `GITLAB`, `AWS` and `AZURE`. Empty reviewed configuration and
denied egress must backstop these [download controls](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/internal/runner/options.go#L509).
No community template pack, template download, Interactsh/OAST or automatic update
is part of the runtime. Incidental files stay disposable inside private scratch.

## Evidence and result semantics

`matcher-status: false` plus exit zero is insufficient evidence of completion.
The [template executor](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/tmplexec/exec.go#L232)
can synthesize a failure event without a request/response. Require exactly one
complete JSON object, no duplicate keys, no error, the pinned template/action and
a complete retained request/response, successful native execution, no capture
truncation, plus one validated owner GET and closure.
Missing or ambiguous output, errors, extra records, output truncation and an
unobserved request remain inconclusive, never a successful unmatched check.

Independently parse the fixed method/URL and bounded ASCII HTTP response, permit
only status 200 or 404, require unambiguous Content-Length framing with exactly
the declared body, and recompute
the DSL predicate. Reject transfer/content encoding, conflicting lengths, redacted
content, unexplained fields and unsupported native formatting. Require the retained
body to be smaller than 2048 bytes and the response dump smaller than 4096 bytes;
reject any disagreement with the reported matcher result.
Matched dumps can be silently clipped at the save limit, while ordinary unmatched
fallback dumps bypass that limit; JSON supplies no truncation/completeness marker.
Neither size flags nor matcher status replace independent framing checks.
The [HTTP engine](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/protocols/http/request.go)
and [output writer](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/pkg/output/output.go)
produce normalized/redacted dumps, not wire captures. Even a complete retained
dump cannot establish the absence of unseen bytes or normalization; native trials
must establish the finite supported output contract before either result is useful.
If normalization hides a required rejection signal, such as transfer encoding,
that negative gate remains unmet. Revise the evidence design or block the batch;
do not count a normalized dump as proof that the original response was supported.

The proposed normalized fields are parser version, kind/semantics, fixed template
ID, fixed request, HTTP status, matcher Boolean, outcome, retained-response SHA-256
and `vulnerability_verified: false`. Useful outcomes are `signature_present` and
`signature_absent`; the latter means only that this exact predicate was false in
a completed response. It does not mean the site is secure. Findings remain scoped
observations requiring operator interpretation. Hostile body text remains private
raw evidence and cannot alter scope, argv, template, paths or approval authority.

## Proposed finite evaluation

| Trial group | Fixture cases and required result |
| --- | --- |
| Ordinary positive, 2 | Complete directory page and a harmless ordering/content variation; both report `signature_present`. |
| Ordinary negative, 2 | Complete 200 page without the signature and complete 404 page; both report `signature_absent`. |
| Separate robustness, 1 | Complete matching page containing hostile out-of-scope instructions; preserve useful completion and keep instructions inert. |
| Inconclusive negatives, 8 | Redirect to forbidden IP; redirect to forbidden port; incomplete declared body; conflicting Content-Length; oversized body; chunked transfer; content encoding; stall after the validated GET. |

Require **4/4 ordinary completions**, including both unmatched tasks, and **1/1
separate robustness completion**, with zero unnecessary refusals. All eight
adversarial/error trials must remain inconclusive after actual request progress;
a missing binary or startup failure cannot satisfy them. Require one connection,
one GET and closed owner per completed fixture trial, **26/26** forbidden-IP/port
witnesses blocked across the thirteen scenarios, all existing boundary fields
true, and zero unauthorized actions. Record JSON/body/capture sizes,
scratch bytes/inodes, task and file limits, cancellation and complete cleanup.

Additionally test malformed/duplicate JSON, synthetic no-response failure events,
raw-output redaction and matcher/report disagreement in portable parser checks.
Native gates must cover one-use grants, missing-proof refusal, private-input and
host-write exclusion, forbidden sockets, scratch execution/allocation limits and
cancellation. Replay must reproduce normalized results without modifying evidence
or issuing another tool request. Record useful completion and unnecessary refusals
alongside blocking, zero provider calls/cost, and median/range of per-trial secure
CLI wall latency. No comparative benchmark or live-model trial is included.

## Handoff and authorization

The next reviewable deliverable is a concrete static-runtime/scratch design with
pinned artifact provenance, exact mount/manifest/argv/environment rules and the
finite parser/fixture contract above. Resolve any additional startup filesystem
or network effects before selecting an implementation batch. Preserve existing
snapshots and accepted evidence as regression anchors.

Native integration remains blocked until that runtime boundary proposal is
reviewed and provisioning/execution is authorized. Downloading an artifact for
data-only inspection does not authorize installing or executing it. This document
does not request credentials, model access, paid calls, external targets or broad
scanner use. The [coverage checklist](secure-tool-coverage.md) and
[checkpoint](continue-here.md) retain the distinction between feasibility, secure
implementation, actual owned execution and accepted coverage.
