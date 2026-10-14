# Stock nginx: authorized disconnected diagnostic

S3.2a is accepted in [PR #88](https://github.com/0xsl0th/recon-cockpit/pull/88)
at `5686dc8`. **S3.2b is in progress; no native passing result is yet recorded
here.** This implements the complete [Stage 3 contract](stage3-compatibility-routing.md)
using the [pinned source/runtime preparation](stock-nginx-feasibility.md).
It is a diagnostic, not a new catalog capability or production integration.
Accepted coverage remains 52 profiles across 17 external programs. Completed
milestones stay closed.

## Authority and transport

The caller selects one of two configurations and thirteen fixed cases. The
selection binds the exact action, policy, one-action budget, runtime manifests
and fresh owner identity. A full selection digest in the policy version prevents
approval reuse across cases that happen to share the same HTTP action.

The existing controller and isolated audit, approval and launcher services
remain mandatory. Durable execution intent, an independently verified audit
witness, consumed approval when required, admission and one-use redemption
precede owner startup. Audit records attest to the control path; they do not
authorize an action themselves. Neither a saved report nor its hashes can
restore a permit. The default diagnostic policy requires approval and an
unattended attempt is blocked. An explicitly selected unattended owned-lab test
policy is labeled as such; automated test execution is not personal approval.

The recorder owns the disconnected TCP namespace and independently accounts
for attempts, admitted connections, validated requests, daemon delivery and
response delivery. Only a complete exact request reaches nginx. The separately
confined stock daemon listens on a private Unix socket. The isolated launcher
creates its kernel-bounded private directory; the recorder mounts it read-only
and nginx mounts it writable. The client receives none of these mounts or owner
management descriptors, and client AF_UNIX access is blocked. The daemon and
recorder have independent process trees, namespaces and resource bounds.

The initial directory-FD handoff failed closed: Bubblewrap 0.11.2 resolves a
`--bind-fd` source to a pathname, which could not be found outside the recorder's
private mount namespace. Its [upstream implementation](https://github.com/containers/bubblewrap/blob/v0.11.2/bubblewrap.c)
explicitly documents this cross-user-namespace restriction. The revised layout
needs no extra namespace-entry privilege or service process. Creating the empty
private mount during launcher bootstrap does not start nginx or client traffic;
those still require authorization and both applicable launch witnesses.

The client verifies its confined namespace, destination denials and resource
boundary before signaling readiness. Only then does the authority arm the
recorder and release the same absolute one- or five-second action deadline over
the existing private pipe. Startup time is measured separately. A bounded 250 ms
result-marshalling allowance permits reporting after the action deadline; it
does not permit further forwarding. The session remains bounded to 60 seconds.

Each owner's 1 MiB aggregate storage allowance is partitioned into 768 KiB
kernel-bounded private scratch and at most 256 KiB retained logs/control evidence.
The stock launcher's ordinary `/tmp` is reduced to 256 KiB alongside that
768 KiB directory, preserving its aggregate 1 MiB scratch ceiling. Both service
owners retain the 256 MiB address-space and 64-descriptor limits. Child creation is
denied after setup. No package installation, host service, host route or external
network is used.

## Private evidence and replay

`scripts/stock_http_diagnostic.py run` accepts only A/B and the declared case
identifiers. Execution is off by default. A fresh private destination is required;
existing evidence is never overwritten. `--execute --unattended-owned-lab-test`
selects the explicit diagnostic test policy for this finite disconnected corpus.
There is no arbitrary URL, target, argv, credential or environment argument.

Each bundle preserves the selection/runtime manifest, durable action intent,
audit events, client raw result, original and transformed daemon response,
recorder event ledger, resource/namespace/cleanup receipts and report. Failed or
incomplete runs remain failures and are retained alongside later attempts.

```sh
.venv/bin/python scripts/stock_http_diagnostic.py inspect /absolute/private/trial
```

The inspector reads private regular files without following symlinks, checks
action/policy/runtime/audit continuity, reparses retained client bytes in a
networkless isolated parser and recomputes the saved result. It cannot execute
or resume an action. Hashes and replay prove internal evidence consistency,
not resistance to a compromised host changing all retained records.

## Completion gate

Both configurations must pass all six ordinary, two robustness and five
negative cases: **12 ordinary and four robustness useful completions, ten
correct negatives and 16 distinct blocked destination checks**. Blocking an
ordinary task counts as an unnecessary refusal. Every negative must retain a
valid original nginx response before the selected transport fault. R1 preserves
hostile body text as data; R2 records four byte-preserving writes, not assumed
packet boundaries.

Missing, stale, replayed or mismatched required approval; audit failure; changed
authority/runtime/owner; expired/cancelled sessions; extra requests/connections;
private-listener bypass; cleanup and unchanged CLI/Python replay remain required.
Record client startup, action, owner startup/teardown and whole-trial latency
including read-only preflight, with zero provider calls/spend.
Comparative benchmarking and broader workflow composition stay deferred.

After S3.2b acceptance, S3.3 adds the separately reviewed production HTTP subset
and Apache comparison. SSH, disconnected multi-host routing, DNS/TLS name
binding and combined acceptance follow in roadmap order. Network attachment,
credentials, paid/live models and proposal submission require their later gates.
