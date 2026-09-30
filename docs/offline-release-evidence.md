# Offline release evidence and demo runbook

This R6 preparation slice packages the accepted deterministic baseline and owned
TLS planning evaluation into one local, independently inspectable candidate.
It does not complete R5 real-model acceptance or R6 actual operator review.
The demonstration remains explicitly offline: no paid calls, real credentials,
external targets or VPN. Accepted milestones remain closed; new tools, cases,
GUI/API work and other optional additions remain deferred.

The 30 September local candidate has since passed the actual terminal rehearsal
and received the operator's separate acceptance. See the
[review record](verification.md#r6-offline-operator-rehearsal--30-september-2026)
and [current checkpoint](continue-here.md). The immutable packet retains its
creation-time pending fields; acceptance is recorded separately. Publication
and live-model work remain deferred.

## Prepare a local candidate

Use a prepared Python 3.11+ environment with the repository dependencies already
available. Building also requires local Git and a clean checkout. It does not
install dependencies, fetch objects, build a wheel or publish anything. The
source archive is a reproducible snapshot, not a hermetic environment bundle.
The selected repository must be the checkout from which this verifier is
running; an unrelated clean repository cannot be labeled its source revision.

Finish and close both evaluation processes and every ledger writer first. The
inputs must be passing default batches (three repetitions of all six cases,
600-second batch limit) under the same policy. Dry runs, partial batches,
uncertain accounting and other evaluation settings are refused. Inspection
opens the ledger read-only only after writers have closed.

Use existing verified private bundles, or reproduce them on Linux with the
[owned lab prerequisites](owned-lab.md), [baseline command](evaluation.md) and
[planning command](planning-evaluation.md). The following commands start new
owned fixture evaluations. Their policy explicitly allows unattended owned
execution; they are not evidence of a human approving an action.

```sh
.venv/bin/python -m recon_cockpit.secure_agent --evaluate-owned-lab \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/evaluation-baseline-NEW --execute
.venv/bin/python -m recon_cockpit.secure_agent --evaluate-owned-planning \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/planning-evaluation-NEW --execute
```

The private `.secure-agent` parent must already exist (mode 0700). Choose new
output names; neither evaluation nor packet creation overwrites or resumes work.
Get the full current commit with `git rev-parse HEAD`, then substitute that
40-character value for `FULL_COMMIT` below. Commit reviewed changes first:
staged changes, changed tracked files and nonignored untracked files are refused.

```sh
.venv/bin/python -m recon_cockpit.secure_agent.release_packet build \
  --baseline .secure-agent/evaluation-baseline-NEW \
  --planning .secure-agent/planning-evaluation-NEW \
  --repository . --revision FULL_COMMIT \
  --output .secure-agent/offline-release-NEW

.venv/bin/python -m recon_cockpit.secure_agent.release_packet inspect \
  .secure-agent/offline-release-NEW
```

Both commands print the reconstructed JSON report. Exit 0 means a verified
local packet; exit 3 with `release_packet_unavailable` means refusal, with no
raw evidence or Git diagnostics disclosed. Argument errors exit 2. A failed
build may leave a partial directory; use a fresh name after correcting the
input. The inspector never repairs, extracts, executes or restores authority.

## What the packet proves

The output contains `baseline/`, `planning/`, `source.tar`, `manifest.json`,
`report.json` and `report.md`. Copies are private regular files with exclusive
creation. The bounded inventory covers every copied input and the source tar.
The original independent graders replay both source bundles and their copies;
cached scores alone cannot produce a verified packet. Inspection checks the
inventory, reruns both graders and regenerates the exact JSON/Markdown reports.

The source metadata binds each file to its Git blob, the reconstructed tree
and the full raw commit object. The sorted USTAR archive fixes timestamps and
owner fields. Only the reviewed repository source roots are accepted; symlinks,
submodules, private configuration/credential paths and unsupported tracked
paths cause refusal. Ignored runtime evidence and local configuration are not
archived. Source inspection needs no Git checkout and never extracts members.
This is a local integrity check, not a signed attestation or secret scanner.

The selected revision is the **verification/reproduction revision**. Historical
evaluation bundles did not record their execution revision; the report says
`execution_revision: not_recorded`. Do not describe this source pin as proof
that it produced the older runs. Rebuilding from the same source revision and
input bytes produces identical packet files. Fresh evaluations legitimately
have different identities, timestamps and timings; compare their six semantic
fingerprints and verified outcomes instead of claiming byte-identical runs.

Both profiles must pass 18 trials, with 51 executions, 45 successful actions,
12 correct abstentions and zero unnecessary actions. All six semantic
fingerprints must match across profiles and repetitions. Planning additionally
requires 51 owned TLS exchanges, 26,112 fixture input tokens, 6,528 output tokens,
39,678 simulated microUSD, zero unresolved holds and zero actual provider calls.
Elapsed times measure local fixture/isolation overhead, not real-model latency.

File access is bounded to 512 files, 128 directories, four directory levels,
2 MiB per evidence file and 64 MiB total. Source inspection has its own bounds:
1,000 regular source files, 1 MiB each, a 16 MiB canonical archive and a bounded
commit object. Symlinks, hardlinks, public evidence, extra entries, SQLite
sidecars, noncanonical manifests and changed data fail closed. Builders and
inspectors assume a trusted host owner and stable, closed evidence directories;
hashes cannot authenticate evidence against an owner who fabricates everything.

## Rehearse the evidence walkthrough

1. Run the read-only packet inspector, then open the root `report.md`. State
   that this is a synthetic offline candidate with live-model and operator
   acceptance pending. Point to the source revision and missing historical
   execution revision separately.
2. Follow both aggregate report links. Show case a's seeded validation, case b's
   absent endpoint and the distinct abstentions for malformed data, timeout,
   output limit and invalid discovery in cases c–f. Each finding has its saved
   trial evidence; an infrastructure failure does not count as abstention.
3. Show the matching fingerprints in `report.json`, the planning usage and
   settled simulation account. Explain that actual provider calls and spending
   are zero; fixtures establish integration, not model quality.
4. Show how a modified report or artifact causes inspection to refuse. Use a
   disposable private copy; keep the original packet unchanged. Regenerating a
   manifest cannot make a corrupt trial pass the independent grader.
5. Record the operator's actual observations and decision separately when they
   perform this review. Do not create an acceptance record on their behalf or
   relabel scripted terminal tests as a human decision.

For an actual approval-required demonstration, use the accepted
[owned TLS planning CLI](owned-tls-assessment-planning.md#explicit-cli-selection)
with the approval-required example policy and fresh paths. Changing its dry run
to execution requires the operator to choose to start the demo and answer the
real terminal prompts. Never automate those answers or reuse old grants. That
demonstration and final acceptance are separate from building or inspecting a
packet; neither can be supplied by automation. The current candidate's completed
rehearsal and decision are recorded in the checkpoint linked above.

## Remaining decisions

A later real-model experiment requires explicit authorization for the released
data, model/endpoint, credentials and spending limit. Publishing or submitting
a release requires a separate instruction. The local packet and runbook are
accepted following actual operator review/rehearsal; preserve that accepted
scope. Use the disclosed offline fallback while live validation remains deferred,
without describing it as live acceptance or a published release.
