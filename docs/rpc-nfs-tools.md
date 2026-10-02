# Owned RPC registration and NFS export metadata

B4 extends the [secure-tool coverage checklist](secure-tool-coverage.md) with two
independently invoked native tools. It was accepted in
[PR #41](https://github.com/0xsl0th/recon-cockpit/pull/41), merged as `6623aa0`.
Both profiles reuse the existing policy, approval, audit,
admission, confined launcher, networkless parser and private evidence path.

| Capability | Fixed native action | Intended structured result |
| --- | --- | --- |
| `rpcinfo_dump_v1` | `rpcinfo -p 127.0.0.1` | Program, version, advertised transport and port registrations. |
| `showmount_exports_v1` | `showmount -e 127.0.0.1` | Finite reviewed export paths and advertised access groups. |

The owned topology uses one predeclared IPv4 TCP endpoint, `127.0.0.1:111`.
The synthetic service multiplexes rpcbind discovery and MOUNT export metadata at
that same endpoint. Returned addresses or ports never expand the firewall or
execution policy. Minimal TCP transport and service-name configuration is compiled,
pinned and mounted read-only; host databases and configuration are not imported.
Previous B0–B3 endpoint, manifest and evidence contracts remain unchanged.

Each profile permits one action, a five-second tool deadline, a 60-second session
and 8,192 combined stdout/stderr bytes. Native processes retain 256 MiB address
space, 64 descriptors, zero file writes, no child processes or threads, Landlock
and seccomp. Only the fixture owner receives `CAP_NET_BIND_SERVICE` to create
its fixed low-port listeners; it drops all capabilities before starting the service.
Native clients receive no added capability. A fixed private hostname and namespace identity prevent host identity
from becoming RPC AUTH_SYS metadata. AUTH_SYS is synthetic protocol metadata,
not a supplied credential or proof of authenticated access. Real credentials,
passwords, model providers and external targets remain absent.

The fixture exposes only bounded RPC discovery, registration listing and export
metadata operations. It implements no mount operation or filesystem backend.
An advertised export does not prove that files are accessible; an advertised port
does not authorize connecting to it. The `showmount` profile is not complete NFS
service coverage, including NFSv4-only environments. Unsupported or malformed output formats
must remain inconclusive; observations cannot select follow-up work.

## Run and inspect

Use the existing unprivileged Linux isolation prerequisites and installed
`rpcinfo` / `showmount` executables. Missing prerequisites refuse execution;
there is no host-service or package-installation fallback. The shipped policy
requires fresh operator approval. Use fresh paths for each action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment rpc-ok --owned-lab --execute \
  --policy examples/secure-agent-rpc-nfs-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-rpc-audit.jsonl \
  --assessment-dir .secure-agent/NEW-rpc-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-rpc-evidence
```

Use `nfs-ok` for the separate export trial. Fixtures distinguish valid empty results from injected, malformed and stalled
replies, and an unapproved advertised mount-service port. Valid absence counts
as useful completion only when native evidence establishes it.
`--dry-run` starts no lab or native process. Inspection is read-only and never
restores execution authority. The fixture permits at most four accepted connections and eight RPC calls,
including at most three discovery calls and one DUMP or EXPORT. Logical request
counters count the metadata query; discovery exchanges are excluded. Connection
counts are acknowledged lower bounds. The captured normal and empty trials each
use two connections and one metadata query to the same fixed endpoint.

## Verification and next gap

[verification.md](verification.md) records actual execution, enforced boundaries,
independent evidence replay and review status. Require useful normal completion
and valid absence handling as well as denial, hostile output, endpoint redirection,
output pressure, deadline, cancellation and cleanup checks. Record unnecessary
refusals and local descriptive elapsed times; zero provider calls and zero actual
provider cost are required. Automated grants do not claim human acceptance.

B5 FTP/SMTP metadata follows B4 after G1–G6: finite anonymous FTP listing and SMTP
banner/EHLO/QUIT without file transfer, mail or authentication. B5–B8 remain required
coverage. Deeper composition and comparative benchmarks wait for the coverage
milestone; credentials, paid calls and live evaluation remain deferred until much
later. Accepted offline R5/local R6 and the proposal/PDF stay closed.
