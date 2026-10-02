# Owned FTP listing and SMTP capability metadata

B5 extends the [secure-tool coverage checklist](secure-tool-coverage.md) with two
independently invoked curl profiles. Implementation and owned-lab validation are
complete; the batch remains pending PR review and an authorized merge.
Both profiles reuse policy, approval, audit, admission, the confined native
launcher, networkless parsing and private evidence replay.

| Capability | Fixed operation | Structured result |
| --- | --- | --- |
| `curl_ftp_list_v1` | Anonymous root-directory NLST against the owned FTP service | Finite names only; no file type or content claim. |
| `curl_smtp_capabilities_v1` | Fixed SMTP greeting/EHLO and QUIT | Advertised extension tokens; no claim the extensions were exercised. |

Both use the predeclared IPv4 TCP `127.0.0.1:8080` endpoint. The FTP fixture accepts
its one control and one passive data connection on that same listener, preserving
the existing firewall and forbidden witnesses. This synthetic topology does not
establish support for arbitrary FTP servers or dynamic passive port ranges.
PASV advertisements are untrusted: neither a returned address nor port expands
permission. Active mode, EPSV fallback, proxies and redirects are disabled by the
fixed invocation. Only the compiled public `anonymous:anonymous@` identity is
sent; no real credentials, user netrc or host curl configuration are imported.

FTP implements no filesystem backend, retrieval, upload, traversal or mutation.
A complete control reply through `226` accompanies stdout names; an empty stdout
alone cannot prove an empty listing. Curl's cleanup QUIT response is not part of
the captured listing transcript. SMTP uses `reconlab` as its synthetic greeting
identity, advertises only reviewed tokens and quits without AUTH, MAIL, RCPT,
DATA, HELP or account probing. Curl can try HELO if EHLO is rejected; that bounded
benign greeting fallback never establishes an ESMTP capability result.

Each profile allows one action, a five-second tool deadline, a 60-second session
and 8,192 combined stdout/stderr bytes. Curl's own deadline is three seconds with
no retries. Native processes retain 256 MiB address space, 64 descriptors, zero
file writes, no child processes or threads, Landlock and TCP-only seccomp. No new
native privilege or network endpoint is introduced. B0–B4 profiles and evidence
identities remain unchanged.

## Run and inspect

Use the existing Linux isolation prerequisites and installed distribution curl.
Unsupported prerequisites refuse execution; there is no host runner or package
installation fallback. The shipped policy requires fresh operator approval.
Use fresh audit/evidence paths for each separate action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment ftp-ok --owned-lab --execute \
  --policy examples/secure-agent-ftp-smtp-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-ftp-audit.jsonl \
  --assessment-dir .secure-agent/NEW-ftp-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-ftp-evidence
```

Use `smtp-ok` for the separate capability trial. Valid empty cases require
complete native success framing; refusals, malformed replies, unsupported names
or extensions and incomplete output remain inconclusive. Hostile raw text never
selects another action. Protocol counters record one validated NLST or EHLO
query; connection counts are acknowledged lower bounds. Inspection is read-only
and never restores execution authority. Dry runs start no lab or native client.

## Verification and next gap

[verification.md](verification.md) records useful real execution, negative cases,
independent replay, actual approval/enforcement/resource checks and cleanup.
Record legitimate completion and unnecessary refusals as well as blocking.
Provider calls and cost remain zero. Automated grants are test instrumentation,
not human acceptance; local CLI timings are descriptive, not comparative overhead.

B6 Docker/WinRM metadata follows B5 once G1–G6 are complete. B6–B8 remain required
coverage. Deeper composition and comparative benchmarking wait for this milestone;
model credentials, paid calls and live-model evaluation remain deferred until much
later. Accepted offline R5/local R6 and the separate proposal/PDF stay closed.
