# Desktop execution and exact-action approval plan

This checklist guided the [graphical reviewer implementation](graphical-approvals.md).
The worker and opt-in shared-service path were accepted in PR #52; the personal
walkthrough and ordinary GUI Execute control remain outstanding.
The desktop session slice runs the existing service with `execute=False` and
`interactive_terminal=False`. Its generated policy still requires approval.
Starting a preview, viewing a proposed action, cancelling, or inspecting saved
evidence supplies no approval and cannot start a tool. Credentials, paid calls,
external targets and authenticated or intrusive actions remain deferred.

## Accepted terminal baseline

The [shared service](shared-assessment-service.md) creates fresh authority, audit,
approval, admission and launcher services for each session. Before this slice,
approval interaction used only the isolated terminal reviewer. For that default
frontend, the trusted caller must
request terminal interaction and have an actual interactive terminal; an
`approval_required` policy decision alone does not mean that a prompt exists.

`LinuxApprovalService` gives its fixed worker the intentional terminal descriptor.
The worker displays the canonical action without the planner's rationale, the
action and policy digests, policy version and session identity. It flushes earlier
input and requires a newly generated exact approval phrase. Blank input denies.
The worker owns the grant store; grants expire and are consumed once, including
when a consume attempt changes the action or policy. Its separate launch witness
proves consumption to the launcher with the original expiry and session/action/
policy bindings. The authority also requires the audit witness and admission
checks. A JSON reference or GUI success message cannot replace these witnesses.

Relevant implementation: [approval isolation](../recon_cockpit/secure_agent/approval_isolation.py),
[terminal worker](../recon_cockpit/secure_agent/approval_worker.py),
[protocol](../recon_cockpit/secure_agent/approval_protocol.py),
[grant store](../recon_cockpit/secure_agent/approvals.py), and
[launch witness](../recon_cockpit/secure_agent/approval_witness.py).

## Execution design and review requirements

Keep the first execution integration within the same four-action, disconnected
HTTP/SSH fixture workflow and its existing limits. There is no batch approval,
approval remembered across sessions, command editor or general plugin interface.
Do not enable a desktop Execute control merely by setting `interactive=True`,
adding a callback that returns a reference, forwarding text to a PTY, or weakening
the generated policy.

The graphical design uses a separate trusted review helper. That helper
owns its review window and receives the operator's input directly. The main
desktop can request review of the authority's pending action and display progress;
it cannot submit an affirmative answer, manufacture a grant, or write the launch
witness. The helper owns the challenge, grant store and witness sender. No tool,
planner, observer callback or saved report receives those capabilities.

The local application, host and desktop session remain trusted, as in the existing
service contract. This separation controls what planner/tool data and application
interfaces can authorize; it does not authenticate a human against a malicious
host-owned frontend, compositor or another privileged desktop client. Do not add
remote attestation, a hostile-frontend sandbox or desktop-wide input provenance to
this milestone.

The graphical surface is a prerequisite to review, not a solved consequence of
using a separate process. Its display/input transport and descriptor custody must
be specified and tested before implementation enables execution. Display access
alone does not establish this boundary: document the compositor or X11 capabilities
given to the helper and retain explicit trusted-desktop limitations. Application
code must not forward synthetic widget events or a main-window `approved=true`
response as the operator's answer. Document any additional desktop permissions
required; do not claim resistance to a malicious host owner or compromised compositor.
If a suitable graphical boundary cannot be established on the supported desktop,
keep graphical execution disabled and retain the existing terminal workflow.

Use the existing grant and launcher witness semantics wherever they apply. Add a
versioned, bounded review transport only where graphical ownership requires it;
keep the terminal protocol compatible. The shared assessment service remains the
only assessment entry point and constructs the selected fixed reviewer itself,
rather than accepting an arbitrary approval callback or injected approval store.

## Review transaction and lifecycle

1. Freeze the validated scope and policy when the session starts. Only the
   authority's actual pending proposal may enter review. Bind the request to the
   reviewer instance, session, increasing request sequence, canonical action and
   its digest, policy digest, and original session deadline. At most one review
   is pending. Reject unknown fields, oversize messages and extra descriptors.
2. The review helper validates those bindings and generates a fresh challenge.
   Its window shows the exact tool profile, target, port, method/path where
   applicable, timeout/output limits, session and scope identity. Technical
   digests remain available for verification. Labels come from trusted code;
   service observations and model text are separate, escaped, untrusted data.
   No retained click, default Enter action or answer to an earlier request
   approves the newly displayed action.
3. The operator explicitly approves that challenge once or denies it. Closing
   the review window, deadline expiry, cancellation, malformed input, worker
   failure or channel loss yields no approval. The helper creates any grant
   itself and returns only its opaque reference through the authority channel;
   the ordinary GUI receives display state, not a reusable authorization token.
4. The authority consumes the reference for exactly the reviewed action and
   policy. The helper sends its consumption witness directly to the launcher.
   Consumption never resets the original expiry, session deadline or budgets.
   Require the existing audit witness and final launch admission checks as well.
   Changing scope, policy, action or session requires a new review; no grant is
   restored from an evidence folder or resumed GUI state.
5. Cancel and close invalidate pending review and request service cancellation.
   The desktop waits for reviewer, authority and tool cleanup before allowing a
   new session or reporting closure. A late answer cannot reopen the session.
   Show requested cancellation separately from confirmed terminal state. Replay
   final evidence independently before presenting final usefulness metrics.

Record requested review, denial/expiry, consumption and execution outcomes with
the relevant session, action and policy bindings. Audit review outcomes without
persisting challenge answers or reusable references in ordinary GUI history.
An unanswered review is neither a successful approval nor a tool refusal inferred
from missing evidence. Automated input proves protocol behavior only; label it as
a test fixture and never as the owner's personal acceptance.

## Required evidence before enabling ordinary desktop execution

- **Custody:** demonstrate that no exposed main-GUI operation, planner or tool
  channel can submit affirmative input or a consumption witness. Verify descriptor ownership, peer
  identity, startup bindings, isolation and cleanup on the chosen graphical
  transport. Retain a working terminal approval regression suite.
- **Exact binding:** reject a stale or replayed answer; changed tool, address,
  port, path, method, limits, policy or session; duplicate/concurrent review;
  malformed or oversized input; and altered scope after review. Each rejection
  must prevent tool launch and leave an attributable audit result.
- **Lifecycle:** exercise denial, timeout, close and cancellation before review,
  while awaiting input, after approval but before launch, and during execution.
  Include a broken reviewer/channel, failed audit write, missing witness and
  observer failure. No silent fallback, fresh deadline or second launch is allowed.
- **Useful work:** in the owned lab, explicitly approve the legitimate four
  actions and show 4/4 completed with replayable structured evidence. Separately
  deny an action and verify no subsequent unauthorized launch. Retain listening
  destination witnesses and report useful completion, ungraded refusals where
  appropriate, local latency and actual zero provider cost. These measurements
  are not a comparative benchmark or proof of a professional pentest capability.
- **Human usability:** have the owner personally perform a bounded walkthrough
  that includes approval and denial, confirms the displayed destination/action,
  and observes cancellation. Keep this receipt separate from automated GUI tests.
  Do not fill or click the owner's approval on their behalf.
- **Review gate:** the separate implementation PR must review the input transport,
  authorization bindings and native evidence above before an ordinary desktop
  Execute control is enabled. Any new desktop permission or broader assessment authorization must
  be presented concretely. The current preview milestone does not satisfy this
  gate or reopen accepted offline milestones.
