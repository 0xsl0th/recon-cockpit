# R5: confined persistent-lab launching

## Ownership decision

This slice depends on reviewed, unmerged PR #20 (`007f24f`). It completes launcher
custody for the other existing owned workflow profile, without expanding R4's
lab specification, cases, tools or evidence schema. `--isolated-launcher` can
compose with `--owned-lab` and the existing isolated approval/audit/admission
options. Earlier/default paths retain their behavior.

The confined launcher owns the persistent owner process, its management pipe,
pinned user/network namespace descriptors, executor construction and supervision.
It obtains/redeems permits through the separate admission worker. The host retains
an inert identity and typed execute client; it cannot send namespace handles,
commands, owner-counter claims, resets, attachment tokens or replacement deadlines.
The first approved, audited action starts the lab. Every action still uses a
fresh executor sandbox in the same fixed lab network namespace. No process or
namespace capability moves back to the host through this protocol.

Reuse the existing lab owner, executor and identity/continuity validators. Only
their trusted runtime-discovery seams change for a nested launcher: the bootstrap
provides a pinned runtime closure instead of mounting a shell or ldd. Extract the
unchanged SessionLimits value object so those runtime modules do not import the
controller, approvals, audit or evidence writer into the launcher's filesystem.
The common tool resource-limit helper now preserves stricter inherited hard
ceilings. In particular, the owner cannot raise the outer launcher's 30 CPU-second
ceiling to match a longer wall-clock session; its original deadline still applies.

The host validates each bound completion's lab identity and counter progression.
Closing the outer launcher destroys its entire private PID namespace and all
descendants before returning a closure receipt with the host's last acknowledged
totals. These are not a fresh final sample: a lost reply may follow execution.
Cleanup failures cannot manufacture a closure receipt. Cancellation and cleanup
must not renew execution controls, reconnect or create a replacement lab.

The fixed launcher intentionally retains process/namespace creation and, for this
profile only, the pinned nsenter runtime used by the existing lab path. It has
no host network, terminal, audit storage, credentials or broad host mounts. Child
admission and executor restrictions stay intact. The controller still establishes
human-grant consumption and durable intent; the launcher does not independently
authenticate those preconditions. Host/bootstrap compromise remains outside the
claim. Lab IDs and receipts are consistency evidence, not remote attestation.

## Verification and milestone limits

Use owned/mock fixtures only. Verify all six existing persistent workflow cases,
unchanged card v2 and read-only evidence inspection; strict identity/counter
binding; forged namespace, runtime, reset and authority fields; uncertain replies;
admission/owner/executor failures; cancellation/deadlines; complete child/descriptor
cleanup; inert dry-runs and no fallback. Existing fixture/default paths and R5a/R5b
remain regression references. No external provider call, real key or spend is
authorized.

This completes the bounded persistent-lab launcher integration, not all R5.
Pending merge/review gates, remaining authorization integration, bounded assessment
planning on the existing provider/cost boundary and explicitly gated real-model
acceptance still precede R6 evaluation, operator review, packaging and demonstration.
Optional GUI/session APIs, broader tools and lab scenarios stay deferred. PR #20
and this dependent change need their own explicit merge authorization.

An offline dry-run (with a new evidence directory) is:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --workflow-assessment a --owned-lab \
  --isolated-audit --isolated-approvals --isolated-launch-admission --isolated-launcher \
  --policy examples/secure-agent-discovery-policy.json --dry-run \
  --assessment-dir .secure-agent/owned-launcher/evidence \
  --audit .secure-agent/owned-launcher/events.jsonl
```

Dry-run starts no approval, admission, launcher, lab or executor process. Normal
offline coordinator/parser and audit work still run. The existing inspection
command reads the same card v2 evidence without opening any execution path.
