# Persistent owned lab foundation

`--workflow-assessment CASE --owned-lab` keeps one deterministic service alive
through the TCP → HTTP index → HTTP diagnostics workflow. Each new assessment
creates a new lab instance; each action still receives a fresh executor sandbox.
The original `--fixture` mode keeps its per-action fixtures and workflow card v1.

## Scope and lifecycle contract

The only service destination is `127.0.0.1:8080` inside a disconnected Linux
network namespace. Cases `a`–`f` select the existing deterministic scenarios;
they are the seed for this first foundation. There is no user-supplied topology,
service program, port list, external target, DNS, provider credential or live
model. The existing policy must explicitly permit TCP discovery and HTTP.

Construction allocates a fresh instance identity without starting services.
The first authorized action starts the lab only after the controller's policy,
fresh approval when required, budget reservation and durable execution audit.
The lab is bound to one authority session and its original monotonic deadline.
It cannot be rebound, restarted after failure or resumed from evidence.

The owner starts the fixed-case service and listening forbidden-IP/port witnesses,
installs the singleton destination firewall, drops capabilities and enables the
syscall filter before reporting readiness. Only loopback exists. A private,
bounded management pipe exposes lifecycle and aggregate counters to the trusted
host supervisor; it is not accessible to proposals, the coordinator or executors.

Each action enters the pinned lab user/network namespaces through the fixed
`nsenter` launcher. A fixed isolated Python bootstrap closes inherited namespace
descriptors before executing Bubblewrap; the action receives a fresh nested user,
mount and PID sandbox. The executor also refuses unexpected inherited descriptors.
The lab's network namespace belongs to the ancestor user namespace: action
workers cannot administer it. Workers verify namespace identities, drop their
remaining capabilities, apply resource/syscall limits and test the listening
forbidden destinations before probing the allowed service. Their mounts contain
only the fixed runtime and reviewed worker modules.

The service lives for one assessment, bounded by the session deadline and parent
process lifetime. Completion, cancellation, errors and context exit close the
owner and reap children. A dead or invalid owner poisons the instance; there is
no automatic replacement. Reset means destroy the old instance and construct a
new one with the same deterministic scenario. Approval grants, budgets, process
handles and namespace descriptors never survive reset.

## Evidence and repeatability

The canonical lab specification has an ID, version, scenario and SHA-256 digest.
A fresh UUID distinguishes each runtime instance. Workflow card v2 declares the
persistent service lifecycle while preserving the reviewed actions and evidence
gates; historical card v1 remains inspectable without changes to its digest.

The private manifest binds the lab identity. Execution artifacts carry matching
identity and service connection/request counts from the owner's management pipe.
The normal positive run consumes one TCP connection, then two HTTP connections:
the service's counters advance across the three fresh executors. The lab closure
receipt confirms process cleanup and repeats the last acknowledged service totals;
it does not claim a final counter sample after interruption. These totals can be
a lower bound when an action did not complete. The receipt is recorded before
report finalization. Independent inspection
validates identity, counter progression, closure and the usual artifact-backed
workflow decisions, without starting a lab or restoring execution authority.
Incomplete or mismatched evidence cannot produce a validated report.

Cancellation between completed actions retains their checked counters and can
finalize an inconclusive report after cleanup. An interruption during an action,
owner failure or missing runtime context leaves partial evidence instead: the
CLI may report `evidence_error`, cleanup still runs, and read-only inspection
marks completion or closure as unknown. A destroyed runtime is never reconstructed
from cached counts to claim a successful assessment.

Repeat the same scenario with new evidence/audit paths to compare semantic
outcomes. Fresh instance/session/execution UUIDs and timestamps intentionally
differ; scenario, specification digest, selected actions and expected findings
remain stable. The [evaluation runner](evaluation.md) repeats all six cases with
new instances and aggregates independently graded outcomes and resource measurements.

## Run and inspect

Run as the normal Linux user with the existing Bubblewrap/nftables prerequisites
and `nsenter` from util-linux. Kernel execution must be permitted by the calling
environment. No host firewall, routing, forwarding or interface change is needed.

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --workflow-assessment a --owned-lab \
  --policy examples/secure-agent-discovery-policy.json \
  --assessment-dir .secure-agent/lab-a-1 \
  --audit .secure-agent/lab-a-1-audit.jsonl --execute

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/lab-a-1
```

The repository policy requires a fresh human approval for each exact action.
`--dry-run` records proposals without starting the lab. An explicit unattended
owned-fixture policy may be used by the test harness; scripted grants and these
tests do not establish human consent. A second run must use fresh paths, such as
`lab-a-2`, and starts a new instance. Existing evidence directories are never
overwritten or used to resume a lab.

## Limits

The host authority, launcher, lifecycle supervisor and evidence writer remain
trusted components in one host process. Lab IDs, hashes and owner counters detect
inconsistency; they do not authenticate evidence against a malicious host owner.
Kernel enforcement and cleanup are measured separately from portable CI.

Persistence does not grant additional scope or prove general service identity.
The lab serves synthetic, repository-authored cases; it does not measure a live
model or implement a multi-service range, arbitrary seed/config loader, external
target adapter or durable daemon. Reports remain drafts requiring operator
review. The existing HTTP framing and shared-host trust limitations still apply.
See [verification.md](verification.md) for measured results and
[continue-here.md](continue-here.md) for publication state.
