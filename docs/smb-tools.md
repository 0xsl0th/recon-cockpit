# Owned anonymous SMB share metadata

B3 extends the [secure-tool coverage checklist](secure-tool-coverage.md) with
`smb_share_list_v1`. It invokes the installed `smbclient` through the existing
policy, approval, audit, admission, confined launcher and evidence path. The
interactive host runner is not a fallback. B3 is accepted in [PR #40](https://github.com/0xsl0th/recon-cockpit/pull/40), merge `775352e`.

The fixed action lists shares anonymously on a fresh disconnected owned
`127.0.0.1:8080` fixture. SMB2_02, the endpoint, empty username/password, workgroup,
client configuration and two-second native timeout are fixed. Kerberos, NetBIOS,
SMB1 fallback and user configuration are disabled. The tool has one action, a
five-second tool deadline, 60-second session ceiling and 8,192 bytes of combined
stdout/stderr. There are no real credentials or external targets.

The fixture implements only anonymous SMB negotiation and the bounded IPC$/srvsvc
level-1 share-enumeration exchange. IPC protocol reads and writes carry metadata;
there is no file-share backend, traversal, file transfer, remote command or login
capability. Listed names never authorize access to a share or another endpoint.
This deliberately finite protocol server is not a general SMB server.

Structured observations contain the reviewed synthetic share names (`PUBLIC`,
`IPC$`) and their types. Share comments remain private raw evidence and are
excluded from normalized reports. The parser accepts only reviewed native framing;
unknown output is inconclusive. The parser's finite vocabulary is a current
owned-lab limitation, not a claim to import arbitrary production share names.
Both output channels are bounded, retained and independently reparsed in a
networkless process on capture and inspection. This native mode can return identical output for an empty list, access denial
and malformed protocol data, even with exit zero. Footer-only output therefore
remains inconclusive; it never establishes an empty or denied share set. Useful
completion requires the complete reviewed two-share result. Process exit zero
alone does not prove usefulness.

## Runtime boundary

The distribution SMB client has a larger pinned library closure than earlier
tools. Its separate compact manifest permits at most 160 files, 128 MiB total,
40 MiB per file and 18,432 manifest bytes. Only its staging launcher receives
256 file descriptors and a 40 MiB file-size limit. Existing tool manifests and
limits remain unchanged. The native tool still runs with a 256 MiB address-space
limit, no child processes or threads, read-only staged files, Landlock, seccomp
and the fixed IPv4 TCP destination filter. Missing prerequisites refuse execution;
no package installation, host fallback or extra network access is implied.

## Run and inspect

Use the existing unprivileged Linux isolation prerequisites and installed
`smbclient` ELF. Use fresh audit/evidence paths. The example policy requires a
fresh operator approval. Automated synthetic validation grants do not claim
human acceptance.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment smb-ok --owned-lab --execute \
  --policy examples/secure-agent-smb-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-smb-audit.jsonl \
  --assessment-dir .secure-agent/NEW-smb-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-smb-evidence
```

Other fixtures are `smb-empty`, `smb-denied`, `smb-injected`, `smb-malformed` and
`smb-stalled`. `--dry-run` proposes the fixed action without inspecting an
executable or starting a lab. Inspection reconciles evidence read-only and never
restores execution authority. `request_count` means a validated share-enumeration
request, not the number of SMB wire messages or a successful result. Connection
counts are acknowledged lower bounds.

## Verification and next gap

[verification.md](verification.md) records actual execution, enforcement, replay
and review receipts. Useful normal execution and unnecessary refusals are measured
alongside hostile/malformed output, policy and approval refusal, output pressure,
timeouts, cancellation, private input isolation and cleanup. Local elapsed times
are descriptive; they are not comparative authority-overhead measurements.

After B3 meets G1–G6, B4 RPC/NFS metadata is next: bounded `rpcinfo` and `showmount`
observations without following advertised endpoints or mounting exports. B4–B8
remain required coverage. Deeper composition and comparative benchmarking wait
for the coverage milestone. Model credentials, paid calls and live evaluation
remain deferred until much later. Accepted offline R5/local R6 stay closed.
