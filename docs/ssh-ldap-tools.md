# Owned SSH host keys and LDAP RootDSE

Review handoff: [PR #39](https://github.com/0xsl0th/recon-cockpit/pull/39).
B2 extends the [secure-tool coverage checklist](secure-tool-coverage.md) with two
independently invoked capabilities. Both reuse the reviewed authority, approval,
audit, admission, launcher, parser and evidence machinery. Each runs a real
installed executable against one fresh disconnected owned `127.0.0.1:8080`
fixture. The interactive command runner is not a fallback.

| Capability | Fixed action | Structured result |
| --- | --- | --- |
| `ssh_host_keys_v1` | `ssh-keyscan`, IPv4, one endpoint and RSA key type, two-second native timeout | Canonical 2048-bit RSA public key with exponent 65537, bit length and computed SHA256 fingerprint; explicitly untrusted. |
| `ldap_rootdse_v1` | `ldapsearch`, LDAPv3 anonymous simple bind, empty base DN, base scope, fixed filter and four attributes | RootDSE presence, naming contexts, LDAP versions, SASL mechanisms and finite vendor metadata. A valid entry with no attributes is distinct from useful metadata. |

SSH key collection does not authenticate the server or establish a trusted key.
It does not log in, use client keys, open a shell or establish an application
session. The fixture implements only a bounded pre-authentication SSH key exchange
using public synthetic RSA material; it is not a production SSH server or a
reusable cryptographic implementation. No real SSH daemon or user configuration
is exposed to the tool.

LDAP uses `(objectClass=*)` and only `namingContexts`, `supportedLDAPVersion`,
`supportedSASLMechanisms` and `vendorName`. It does not use real credentials,
StartTLS, arbitrary DNs, account enumeration or referral chasing. An advertised
SASL mechanism is metadata, not an authentication attempt. Unknown or malformed
results cannot become an approved next action. The current LDAP parser accepts
only the reviewed synthetic naming context, version, mechanism and vendor values;
it is not yet a general directory metadata importer. Hostile descriptions and SSH banners
remain raw untrusted evidence and are excluded from normalized reports.

Each trial reserves one action, a 60-second session and 8,192 bytes of combined
stdout/stderr; the tool deadline is five seconds. Executables and libraries are
pinned and staged read-only. User/system configuration is absent; LDAP defaults
are disabled explicitly. Both tools retain the no-process/no-thread profile,
256 MiB address-space limit, network destination filter, Landlock and seccomp
checks. Neither tool can read the synthetic SSH signing material. Missing
prerequisites refuse execution without installing software or executing on the
host.

## Run and inspect

Use the existing unprivileged Linux isolation prerequisites plus the distribution
`ssh-keyscan` and `ldapsearch` ELFs. Choose fresh evidence/audit paths. The separate
B2 example policy requires a fresh operator approval; automated synthetic lab
grants are development checks, not human acceptance.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment ssh-ok --owned-lab --execute \
  --policy examples/secure-agent-ssh-ldap-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-ssh-audit.jsonl \
  --assessment-dir .secure-agent/NEW-ssh-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-ssh-evidence
```

Use `ldap-ok` for the separate LDAP trial. Negative and hostile fixtures are
`ssh-malformed`, `ssh-stalled`, `ssh-injected`, `ldap-empty`, `ldap-referral`,
`ldap-malformed`, `ldap-stalled` and `ldap-injected`. `ldap-empty` means a valid
RootDSE entry without attributes; it does not mean a failed or missing response.
`--dry-run` proposes the fixed action without inspecting executables or starting
a lab. Inspection only reconciles evidence and never restores execution authority.

The inherited `request_count` is one logical protocol event: a completed SSH key
reply or a validated LDAP RootDSE search. LDAP bind/search/unbind are separate
wire messages, not three counted assessment actions. Connection counts are
acknowledged lower bounds. A zero process exit alone never establishes usefulness.
B2 uses its own versioned workflow card; the B1 card, policy and fixture identities
remain unchanged so accepted DNS/TLS evidence can still be replayed.

## Verification and next gap

See [verification.md](verification.md) for actual execution receipts and current
review status. Each normal case must complete useful work and persist bounded raw
output with independently replayed observations. Tests must also verify malformed,
hostile, referral, stalled and output-pressure behavior; policy/approval denial;
runtime pins; kernel restrictions; deadlines/cancellation; and lab cleanup.
Descriptive elapsed times are correctness evidence, not comparative benchmarks.

After this batch meets G1–G6, B3's anonymous bounded SMB share metadata is the next
coverage gap. It reuses an existing `smbclient` interactive precedent and adds a
missing protocol family. RPC/NFS, FTP/SMTP, Docker/WinRM, reviewed Nmap service
identification and owned Kerberos principal enumeration remain required later
rows. Deeper composition and comparative benchmarking wait for all required rows.
Model credentials, paid calls and live-model evaluation remain deferred until
much later. Accepted offline R5/local R6 and the proposal/PDF stay closed/unchanged.
