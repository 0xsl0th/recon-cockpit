# Reviewed tool adapters and owned Nmap assessment

This increment establishes a common, versioned contract for reviewed, bundled
capability profiles. The longer-term product may integrate roughly 40 tools;
this increment adds only one Nmap profile alongside the existing TCP and HTTP
capabilities. It does not declare professional deployment readiness or reopen
accepted R1–R6 offline milestones.

The follow-on [HarborDesk lab](web-lab.md) uses these same tools with a separate
versioned fixture and workflow; the six cases documented here remain unchanged.
The separate [HTTP response-header assessment](http-headers-assessment.md) adds
`http_headers_v1` with fixed wire capture and networkless parsing. It preserves
the existing `http_probe` contract and exposes no new provider schema.

## Contract and authority

The static adapter registry describes strict parameters, effects, resource and
scope requirements, execution profile and result/parser versions. Adapter code
can decode parameters, describe a fixed invocation and interpret a bounded
result. It never grants authorization or receives approval/audit ownership.
Unknown adapters or versions fail closed. Runtime plugin discovery, user modules
and arbitrary executable/argument/environment fields are absent.

The existing `http_probe` and `tcp_connect` actions keep their serialized fields,
policy behavior and historical digests. `nmap_tcp_connect_v1` is a new capability;
incompatible future behavior needs a new profile version. Existing proposal
schemas remain unchanged by default. An explicit offline schema profile can
represent Nmap, but no public provider integration is enabled.

The new `owned-nmap-http-assessment-v1` workflow has three actions: Nmap TCP
reachability, the existing HTTP index request and the existing diagnostics
request. A validated predecessor permits proposing the next action; policy,
fresh approval when required, budgets, isolated launch admission, direct approval
and durable-audit witnesses, and independent executor validation still decide
whether it runs. The workflow planner is deterministic and makes no model calls.

## Nmap profile and containment

The only destination is `127.0.0.1:8080` inside a disposable, disconnected owned
network namespace. It is not the host's loopback service. The fixed invocation
uses unprivileged TCP connect, no DNS/host discovery, one port, no configured
retries, one parallel probe, XML stdout and a three-second Nmap host timeout.
Scripts, service/version detection, OS detection, raw scans and custom flags
are not exposed.

The launcher selects a reviewed distribution ELF, not the shell wrapper found
on some distributions. It pins the executable, required libraries and two data
files by content hash. Sealed byte copies strip file-capability metadata. The
trusted launcher stages these copies with a profile-specific 16 MiB per-file
ceiling; the accepted launcher profiles keep their previous limit. The tool
gets only its read-only runtime, no credentials or host case storage.

A dedicated worker verifies the launch commitment, policy, reservations and
namespace identities. It drops capabilities, sets `no_new_privs`, restricts
filesystem read/execute access with Landlock and installs a separate syscall
filter. The existing worker's ban on launching additional programs is unchanged.
The Nmap worker blocks process creation, namespace changes and raw sockets.
Python, shells and application source become unreadable after the final seal;
`/dev/null` is the only permitted writable device used by Nmap output routing.
The Nmap ELF and required loader remain executable. This does not claim a
one-shot exec filter: re-execution of the approved image remains contained by
the same network and resource ceilings.
The kernel restricts destinations and resources; it does not enforce a fixed
number of connect syscalls or forbid every payload byte if the approved tool
were compromised.

Linux on x86_64 or aarch64 with a supported distribution ELF/glibc runtime,
working namespaces, Bubblewrap, nftables, seccomp and Landlock ABI 3 or newer is
required for the new runtime. Missing prerequisites cause refusal;
there is no automatic installation, privilege escalation or host fallback.

| Bound | New Nmap profile |
| --- | --- |
| Tool wall time / CPU | 5 seconds / 3 seconds; session deadline wins |
| Tool address space / descriptors | 256 MiB / 64 |
| Processes / output files | One process; no core or regular output files |
| Captured stdout plus stderr | 16 KiB maximum |
| Session | Three actions, 60 seconds, 18,432 reserved output bytes |
| XML parser | Separate networkless worker, 2 seconds, 128 MiB, ≤1 KiB normalized reply |

## Evidence and interpretation

The XML parser rejects entities, external/internal DTDs, unexpected hosts/ports,
ambiguous structure and incomplete scans. Nmap's bare document type is allowed.
An open result means reported TCP reachability, not HTTP identity or a finding.
Only subsequent HTTP evidence can validate the seeded diagnostic exposure.
Cases a–f retain the existing exposed, absent, malformed, stalled, oversized
and hostile-discovery scenarios, under a separate workflow/evidence contract.

Raw XML and stderr stay in bounded private artifacts. New evidence records bind
runtime hashes, adapter/parser versions, action/policy/session identities,
normalized observations and lab closure. Capture and read-only replay verify
XML inside a networkless parser; the new Nmap evidence inspector therefore
requires the Linux parser prerequisites. Existing evidence inspectors remain
unchanged. Reports contain validated fields and references, not raw tool text.
During an assessment, evidence revalidation honors the original session
deadline; later inspection gets its own bounded parser deadline. Cancellation during
this read-only parser stage may take up to ten seconds to finish bounded setup
and parsing; no additional tool action is launched during that cleanup.

The physical fixture identity remains the existing owned service specification.
The new workflow/result contract treats accepted TCP connection counts as
monotone lower bounds: a rapid Nmap reset may precede service acceptance.
HTTP request progression remains exact. Forbidden services are confirmed before
filter installation and remain listening witnesses afterwards. Zero accepted
connections alone does not prove that every attempted connection was absent.
Audit denials, launch records and boundary probes provide complementary evidence.

## Run and inspect

Use a normal interactive Linux terminal. Each action in this example requires
its own fresh human approval. Evidence paths must be new; inspection never
resumes execution or restores grants.

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --nmap-assessment a --owned-lab --execute \
  --policy examples/secure-agent-nmap-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --assessment-dir .secure-agent/nmap-a-001 \
  --audit .secure-agent/nmap-a-001.audit.jsonl

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/nmap-a-001
```

Use `--dry-run` instead of `--execute` to record proposals without inspecting
Nmap dependencies, starting a lab or launching a tool. Session overrides may
shorten the reviewed limits but cannot expand them. Tests may use an explicitly
unattended owned-fixture policy or scripted test grants; neither records human
consent or operator acceptance.

## Following work

After review of this integration, prepare the richer resettable local web
scenario, then its paired malicious-output comparison. Authenticated web/API,
Windows/AD, broader discovery and further adapters remain later work. Live model
access, credentials, external/VPN targets and spending retain their separate
approval gates. Update the competition proposal with verified results in early
November; no submission is performed by this implementation.
