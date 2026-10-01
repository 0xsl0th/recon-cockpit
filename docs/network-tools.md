# Owned DNS and TLS tools

This is B1 of the [secure-tool coverage milestone](secure-tool-coverage.md).
It adds two independent executable capabilities, not a cross-tool workflow.
Both use the existing authority, fresh approval, durable audit, launch admission
and confined launcher. They run only in a fresh disconnected owned namespace.
The interactive host runner is never an execution fallback.

| Capability | Fixed action | Useful structured result |
| --- | --- | --- |
| `dig_dns_query_v1` | One nonrecursive `harbordesk.test. IN A` query over TCP to `127.0.0.1:8080` | Answer/absence status, bounded A record and TTL, with additional TXT content discarded. |
| `openssl_tls_handshake_v1` | One handshake to that owned endpoint with SNI/verification name `harbordesk.test`, the pinned public fixture CA, TLS 1.3 and `TLS_AES_256_GCM_SHA384` | Verified peer name, protocol and cipher; no certificate-fingerprint or general TLS-scan claim. |

DNS never uses the host resolver, search list, recursion, zone transfer or a
returned address as a new target. TLS uses no client credential, application
request, session cache or user configuration. Fixture private material is public
synthetic test data mounted only in the owner, not the tool or parser.

Each profile reserves one action, a 60-second session and 8,192 bytes of combined
stdout/stderr. The tool deadline is five seconds; dig has a two-second query
timeout and one try. Executable, library and fixed data bytes are pinned and
staged read-only. Existing profile limits and argument lists remain unchanged.
Shared helpers handle sealed staging and kernel enforcement; there is no dynamic
plugin discovery or caller-selected executable.

Both tools use a 256 MiB virtual address-space ceiling, bounded CPU/descriptors
and no regular file output. OpenSSL cannot create threads or processes. dig
permits only thread-style clones under the same hard sixteen-mapped-UID-task
ceiling used by the reviewed ffuf profile, including the private supervisor.
A real thread-limit witness runs before tool execution. Neither can create
new namespaces, raw sockets or child processes; only IPv4 TCP sockets are allowed
and the owned network filter fixes the destination. Missing prerequisites refuse
execution rather than install software or run on the host.

The installed dig emits one known startup diagnostic when its unsupported socket
probe is denied. The parser accepts only that exact reviewed diagnostic (or empty
stderr), followed by otherwise valid output. Unknown, repeated or appended
diagnostics remain inconclusive. This is a version-specific compatibility choice,
not a weakened socket rule. Raw stderr is retained and hashed. OpenSSL's `-brief`
facts are on stderr; capture and independent replay validate both output channels.

Overflow may discard the chunk that crosses the limit, so retained output can be
shorter than the reservation. Such a receipt must still bind its actual bytes,
hashes, runtime commitment and `output_limit` stop reason, with no useful parsed
observation. No padding or invented captured bytes are reported.

## Run and inspect

Use an unprivileged Linux environment with the existing Bubblewrap, nftables,
seccomp and Landlock prerequisites and installed distribution dig/OpenSSL ELFs.
Choose new audit/evidence paths for every run. The shipped policy requires a fresh
operator approval; automated lab grants never stand in for human acceptance.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment dig-ok --owned-lab --execute \
  --policy examples/secure-agent-network-tools-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-dig-audit.jsonl \
  --assessment-dir .secure-agent/NEW-dig-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-dig-evidence
```

Use `openssl-ok` for the separate TLS trial. Other fixed cases are
`dig-nxdomain`, `dig-injected`, `dig-malformed`, `dig-stalled`,
`openssl-untrusted`, `openssl-malformed` and `openssl-stalled`.
`--dry-run` records the proposed action without inspecting executables or launching
a lab. Inspection is read-only and does not restore approvals, budgets or authority.

The inherited `request_count` field counts validated DNS questions for dig and
completed server-side TLS handshakes for OpenSSL; it does not count HTTP requests.
Connections remain lower-bound acknowledged totals. A native zero exit code does
not guarantee useful output: for example, malformed dig responses can exit zero
and still correctly produce an inconclusive assessment.

## Verification and remaining scope

See [verification.md](verification.md) for the source revision, actual cases,
test receipts and review status. The normal cases must complete useful work;
unknown/partial results, invalid TLS, hostile text, missing approvals, tampering,
cancellation and output pressure must preserve the boundaries and close the lab.
Every selected tool has separate raw evidence and an independently replayed report.
Latency is descriptive per-tool timing; comparative benchmarking is deferred.

These profiles do not establish recursive/UDP DNS support, broad TLS assessment,
certificate inventories or professional engagement readiness. After this batch,
prioritize B2's missing SSH/LDAP tool coverage, subject to its own prerequisite
review. Keep the broader milestone open. Deeper workflows, comparative benchmarks,
model credentials, paid calls and live-model evaluation remain deferred.
