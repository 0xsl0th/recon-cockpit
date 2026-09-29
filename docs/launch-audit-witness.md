# R5: independent durable-intent verification

PRs #20 and #21 moved executor and persistent-lab custody into the confined
launcher. The next necessary boundary is verification of launch preconditions.
This slice makes durable execution intent independently verifiable. The separate
[direct approval gate](launch-approval-witness.md) builds on it to authenticate
fresh grant consumption at the launcher.

`--require-launch-audit` requires the existing isolated launcher, admission,
approval and audit options. Trusted bootstrap creates a one-way Unix seqpacket
channel, transfers its sole sending endpoint to the audit worker and closes the
host copy before READY. The receiving endpoint is transferred once to the launcher
at its existing lazy startup, then closed in the host. Each endpoint's unused
direction is shut down in the kernel. No signing key, pathname lookup, socket
listener or new request authority field is introduced.

Only after appending and fsyncing an `execution_started` record does the audit
worker send a bounded witness. It binds writer, audit/witness sequence, session,
action ID/digest, policy/version, backend, decision, target/tool and event digest.
The launcher requires the exact next witness, matching its immutable bootstrap
and canonical action, within five seconds of issue and the original session
deadline. It consumes that witness before admission/redemption/executor creation.
Missing, malformed, stale, replayed, mismatched or unexpected extra witnesses,
channel loss and audit faults stop without reconnect, retry or fallback. An
uncertain write or completion remains possible and never authorizes retry.

This proves an exact durable intent from the selected writer; it does not prove
that a producer's approval claim is true or that an action completed. The host
still performs grant consumption and checks audit path identity. Trusted bootstrap,
the fixed workers and the host account/kernel remain in the trusted computing
base. This does not defend against the host replacing workers, opening their
descriptors through privileged debugging, or changing the audit file after an
acknowledged write. Tool/coordinator processes receive no witness endpoint.

All existing fixture profiles and the persistent lab use the same gate. Default
modes, card v2, evidence schemas, R5a/R5b and live-provider settings stay unchanged.
Dry-run creates no launcher/lab/tool; denial or failed controller audit exchange
prevents launch. Verify direct calls without an audit event, forged host flags,
identity/action/policy/backend changes, expiry/replay, lost fsync/ack/channel,
endpoint custody/direction, cancellation/cleanup and all six workflow outcomes
using only disconnected owned fixtures and synthetic credentials.

With the separate approval gate reviewed, follow with bounded assessment
planning on R5a/R5b and explicitly gated real-model acceptance. R6 then consolidates
evaluation, actual operator review, packaging and demonstration. Optional GUI/API,
tool and lab expansion stays deferred.

For an offline dry-run with a new private evidence directory:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --workflow-assessment a --owned-lab \
  --isolated-audit --isolated-approvals --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --policy examples/secure-agent-discovery-policy.json --dry-run \
  --assessment-dir .secure-agent/audit-witness/evidence \
  --audit .secure-agent/audit-witness/events.jsonl
```

The coordinator/parser and audit writer run normally. Dry-run does not start the
approval, admission, launcher, persistent owner or tool executor. Read-only saved
evidence inspection uses its existing command and opens no execution path.
