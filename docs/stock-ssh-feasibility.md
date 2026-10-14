# S3.4a: finite OpenSSH inputs and installed-runtime preparation

S3.3 is closed by [PR #91](https://github.com/0xsl0th/recon-cockpit/pull/91) at
`061c057`. [PR #92](https://github.com/0xsl0th/recon-cockpit/pull/92) prepares **S3.4a** on the
[Stage 3 roadmap](stage3-compatibility-routing.md). It compiles fixed OpenSSH
inputs and inspects installed executable/library bytes. It starts no SSH
service, executes no tool action, issues no authority and establishes no native compatibility.
**S3.4b remains required** for the separately authorized, confined native path.

The catalog stays **52 accepted profiles across 17 external programs**. OpenSSH
server processes are fixture infrastructure, not additional secure tools.
Accepted milestones stay closed. Model credentials, paid/live models, attached
or external networks, deeper workflows, comparative benchmarking and submission
remain deferred. No host SSH service or operator key is used.

## Why the native boundary needs separate implementation

The local server package is `openssh-server 1:10.2p1-2`. The inspected server
chain contains `/usr/sbin/sshd`, `/usr/lib/openssh/sshd-session` and
`/usr/lib/openssh/sshd-auth`; the installed client is `openssh-client 1:10.2p1-2`.
These are installed package facts, not startup or source-to-binary verification.
The selection's `reviewed_source_version` is source context, not a native binary
version probe or attestation. Inspection hashes the currently selected files;
the later native gate must separately verify the observed full software version.

The [exact Debian source descriptor](https://snapshot.debian.org/file/ca7eeaf605b6520d163ca685880a893e5a08cc6b)
matches the retained original and packaging archives by size and SHA-256. All
26 distribution patches apply in series with zero fuzz; eleven reviewed upstream
files match the original release archive. Upstream tag `V_10_2_P1` resolves to
`d01efaa1c9ed84fd9011201dbc3c7cb0a82bcee3`. This review covers the relevant
startup, privilege, helper, configuration and downstream paths; it is not a
whole-project security audit. No locally trusted signature verification or
reproducible source-to-installed-binary build is claimed. The private
`source-audit/source-review.json` receipt has SHA-256
`787dea7408b9a644c94374c71029105b7cd7c640f74f8ca09de8bf577882f22d`;
its accompanying report retains archive hashes and source anchors.

The upstream **V_10_2_P1** sources explain the boundary:

| Source finding | Required consequence |
| --- | --- |
| [`sshd.c`](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/sshd.c) starts the session executable. Foreground `-D` still forks for connections; inetd `-i` uses an inherited connection but `send_rexec_state` still forks a temporary configuration/key-state writer. | Propose a one-shot inetd owner with an exact inherited connected descriptor and generated configuration. Include the state-writer process in the budget. Do not start a host listener or use the distribution service manager. Descriptor custody, peer checks and cleanup must be proved natively. |
| [`sshd-session.c`](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/sshd-session.c) enters `privsep_preauth`, forks and starts the auth executable for key exchange. | Pin all three executable images, two internal forks and a three-process ceiling including the transient writer. HTTP's no-fork, single-executable boundary cannot simply be reused or weakened. A process observation or `MaxStartups` setting does not enforce a kernel process limit. |
| [`sshd-auth.c`](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/sshd-auth.c) takes its chroot/identity-drop branch when real or effective UID is zero. | Propose nonzero namespace UID/GID 65534, no capabilities and no host account files. Native validation must verify both real/effective IDs, mappings and the actual supplementary-group boundary before bootstrap. Unprivileged startup is still unproved here. |
| [`ssh-keyscan.c`](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/ssh-keyscan.c) returns from its host-key callback after printing the offered key. | Collect one RSA host-key observation without authenticating or opening a user session. An independent packet boundary must terminate before client NEWKEYS or userauth; disabled authentication directives alone are insufficient. |

The installed linked libraries include PAM, Kerberos, audit, SELinux and wtmpdb
dependencies. Their presence grants no use of those facilities. The configuration
disables authentication facilities; full runtime closure and the absence of
additional dynamic loads, host files or sockets require S3.4b evidence.

The exact Debian patch set restores TCP-wrapper checks before the banner.
`UseDNS no` alone does not prevent libwrap name resolution. Generate comment-only
`hosts.allow`/`hosts.deny`, fixed owned `/etc/hosts`, `hosts: files` NSS policy
and a fixed resolver file; mount no host policy or resolver files. Independently
deny resolver/network access outside the declared transport. Disable PAM,
GSSAPI authentication/key exchange and Kerberos, and omit service-manager
activation variables from the closed environment. These proposed inputs do not
prove the patched library's native behavior.

## Finite inputs and observable outcomes

[stock_ssh_spec.py](../recon_cockpit/secure_agent/stock_ssh_spec.py) is a pure
compiler. It offers only A/B and the ten declared cases below. Every selection
binds its configuration, action, public key, generated files, budgets and
expected result; it explicitly leaves execution and compatibility flags false.

| Configuration | Future sole client destination | Server variation |
| --- | --- | --- |
| A | `10.77.0.20:2222` | No ordinary version addendum; RSA-SHA2-256 host-key signature. |
| B | `172.23.0.20:12222` | Fixed public version addendum; RSA-SHA2-512 host-key signature. |

Both use the **existing deliberately public RSA-2048/e65537 fixture identity**,
encoded for stock OpenSSH. Its private exponent is already public repository
test material. This is neither credential setup nor a claim of host identity.
`DebianBanner no` fixes the base identification to `OpenSSH_10.2p1`, with only
the selected addendum; no distribution suffix is silently normalized.
Key exchange proposes `diffie-hellman-group14-sha256`, `aes128-ctr`,
`hmac-sha2-256` and no compression, solely for this compatibility fixture.
This is not a general SSH hardening recommendation.

The planned service action is a separate **NULL/banner-only** Nmap mode: it
forwards no client application payload. The planned key action reuses the
bounded RSA key collector. They are independent actions, not a discovery
workflow. Existing synthetic and HTTP probe/parser commitments remain unchanged.
S3.4b must preserve the full observed `OpenSSH_10.2p1` suffix with a separately
versioned SSH recognition/parser path; the current numeric-only parser is not
evidence of compatible stock identification.

| Case, repeated for A/B | Required outcome in S3.4b |
| --- | --- |
| O1 — service identification | Useful exact bounded stock software/version observation. |
| O2 — RSA key collection | Useful exact public key and fingerprint, explicitly untrusted. |
| R1 — hostile version addendum | Useful observation retained as data; no new authority. |
| R2 — fragmented exchange | Useful key observation despite bounded fragmentation. |
| N1 — malformed identification | Explicit non-useful result; no fabricated version or key. |
| N2 — truncated key reply | Explicit incomplete result. |
| N3 — stalled exchange | Bounded timeout and cleanup. |
| N4 — output pressure | Enforced byte limit and non-useful outcome. |
| N5 — incompatible public key | Reject a key outside the supported RSA-2048/e65537 shape; no host-identity or expected-key trust claim. |
| N6 — unsupported host-key algorithm | Explicit unsupported/inconclusive outcome. |

Corruption, pressure and fragmentation injected at the future recorder are
**mediator cases**, separately labeled from unmodified stock responses. Preserve
original daemon bytes and transformed delivery facts. Those cases do not prove
that stock OpenSSH emitted malformed output. Native validation must complete all
20 rows; source/metadata preparation cannot satisfy any row.

The future action keeps a 60-second session, a five-second tool deadline,
8,192 retained output bytes and one active connection. Keyscan retains
`-4 -T 2 -t rsa` and one connection; Nmap admits at most three empty connections.
Admission is bounded to four connections/second, burst one. The proposed key
exchange cap is 8,192 bytes in each direction. These are declared limits,
not measured native sufficiency; a failure must be retained and reviewed before
changing a contract. Restarts and separate connections cannot reset the
per-action process, connection or byte allowance.
Each instance allows the initial execution plus two internal executable
transitions, two internal forks and at most three process identities. At most
three Nmap instances therefore consume nine total process creations/executions
and six internal forks; keyscan permits one instance. All processes from the
previous instance, including the temporary state writer, must be reaped before
another starts. Kernel enforcement and supervisor custody are native gates.

## Read-only runtime inspector

[stock_ssh_runtime.py](../recon_cockpit/secure_agent/stock_ssh_runtime.py) follows
the accepted bounded file/ELF preflight pattern. It pins the three fixed native
executables, exact linked dependencies and the generated selection inputs.
Metadata probes run only the fixed trusted `ldd` against those three paths;
there is no `sshd -t/-T`, key generation, package installation or daemon launch.
Each probe has a three-second/32-KiB limit within one shared inspection deadline.
Each selection pins **25 native files** (three executables and 22 dependencies,
including the loader) and **11 generated files**. Per-executable dependency
sets contain 7, 22 and 21 entries respectively. Bounds are 16 MiB per file,
64 MiB total runtime, 40 manifest entries and 24 KiB manifest encoding.

Extra or missing libraries, unreviewed aliases, nonregular or mutable inputs,
changed bytes and forged manifest flags fail closed. Saved manifests are data:
reverification cannot run capture-supplied paths, issue grants or enable a
launcher. `runtime_closure_verified` and `daemon_execution_performed` remain
false after success. Hash consistency is not protection against a compromised
host owner rewriting all evidence.

```sh
.venv/bin/python scripts/inspect_stock_ssh_runtime.py \
  --configuration A --case O1 \
  --output /absolute/private-directory/new-receipt.json
```

The output parent must already be owner-only. The inspector creates an exclusive
0600 receipt and refuses existing paths, final symlinks and public parents
before runtime work. It exposes no target, command, credential, model, execute
or approval option. Other package/architecture/library sets remain unsupported.

## Validation and next gate

Frozen source `2a261540aedefb3357a4fc41c6e5647dc8ec6f2a` passed **20 actual installed-runtime
inspections** and **25,483 portable tests**, with zero failures, errors or skips.
All **911 tracked source hashes** stayed unchanged in both runs. Each installed
selection pins the same 25 native files and eleven generated files. Metadata
inspection took **176–246 ms** per selection; this is neither tool latency nor
comparative overhead. There were no daemon/helper launches, authentication
attempts, tool actions, grants, provider calls or actual spend.

All **169 focused tests** passed. Independent spec/documentation and runtime/CLI
reviews found no remaining blockers within preparation scope. An independent
evidence review rehashed all 25 installed files, all 20 receipts and the 911
source files; manifests and zero-execution/readiness flags matched the exact
specification. No accepted launcher, admission, parser, catalog or execution
file changed. Private evidence stays outside Git:

- `preflight-final-01/verification.json`: installed receipts, runtime pins and source custody.
- `portable-final-01/verification.json`, `tests.xml` and `pytest.log`: full portable validation and source custody.
- `independent-preflight-2a26154.json`: independent installed-evidence verification; SHA-256 `36cdf4e0bf92ea38379908f40aed03283c801572138e24ce0d232845457f663a`.
- `runtime-cli-independent-review.json`: separate runtime/CLI code review and 125 fresh focused passes.
- `source-audit/`: exact source archives, patches, anchors and explicit verification limits.

These files are under `.secure-agent/stock-ssh-preflight-20261014/`. The separate
`.secure-agent/stock-ssh-preflight-20261014-agent/` retains development receipts
and `independent-spec-doc-review.json` (44 fresh spec passes). Its initial A/O1
metadata smoke predates the final generated policy inputs and is not final
acceptance evidence. A development spec assertion initially used `bits` instead
of the existing parser's `key_bits`; the contract/test naming was corrected
before the frozen validation above. No native test was substituted or skipped.
S3.4a remains a reviewed preparation candidate until its PR checks and merge.

After S3.4a review/checks/merge, implement S3.4b's separate admission and native
owner. Require exact action authorization, independently verified durable audit
and required single-use approval before launch. Audit is evidence, not authority.
Prove the finite executable transitions and hard process count, exact descriptor
custody, packet/byte/connection limits, no NEWKEYS/userauth, target/exclusion
denials, tamper refusal, cancellation, teardown and unchanged evidence replay.
Native usefulness must include every ordinary/robustness row with no unnecessary
refusals; all declared negatives remain explicitly non-useful and unauthorized
attempts deliver no forbidden traffic. Record action and whole-trial latency;
provider calls and actual spend remain zero. No required gate may be dropped to
fit the estimate. S3.5 routing, S3.6 DNS/TLS name/trust binding and S3.7 combined
acceptance follow in order.
