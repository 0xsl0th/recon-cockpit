# T03 — bounded SSH advertisement policy assessment

`ssh_transport_policy_v1` is an accepted secure profile. It reuses the accepted
C14 collector bytes and adds a pinned networkless policy assessment. [PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81)
closed T03 G1–G6 at `b90a365e` after review and five passing final checks, following
accepted T02. The catalog now reports 48 accepted profiles, zero candidates and
16 programs.
Stock ssh-audit is not integrated: its pinned source performs extra host-key and
key-exchange probes before policy evaluation, even with rate testing disabled.
See the [source review and exact corpus](ssh-policy-feasibility.md).

The client sends one fixed identification/KEXINIT request to an owned disconnected
`127.0.0.1:8080`, closes its write side, and reads one bounded server packet. It
never completes key exchange or authenticates. Client operation time is two
seconds within the five-second tool cap; combined output is capped at 8,192
bytes and first capture at 4,355 bytes. One action and one fresh approval are
required. The default session stays at 60 seconds with one execution reservation.

The immutable `recon-ssh-advertisement-policy-v1` checks exact advertised names in
eight fields, including both transport directions. Conforming observations and
known deviations are useful task outcomes. Unknown algorithms, mixed known/unknown
lists and incomplete replies remain inconclusive. This local policy does not
claim complete or current industry hardening compliance, verified exploitability,
selected algorithms or host identity. Algorithm preference is not assessed.

Use the catalog to inspect the fixed recipe:

```sh
python -m recon_cockpit.secure_agent --describe-tool ssh_transport_policy_v1
```

The policy example is `examples/secure-agent-ssh-policy-policy.json`; approval is
required. Nineteen finite cases include six ordinary assessments, two separate
robustness cases, two complete-but-unknown observations and nine malformed,
partial or pressure cases. Every native negative must follow a validated request
and write EOF, preserve bounds and close the lab. Startup refusal is not success.
Both inspectors must replay original bytes and recompute every policy rule.

Credentials, paid/live models, external networks, deeper workflows and comparative
benchmarking remain deferred. This adds one accepted profile and no external
program. C14 and all earlier accepted profile contracts remain unchanged.

## Validation

Frozen production source `dbfa8b5` passed **52/52 native
tests**: 25 T03 checks, thirteen T02 observations and fourteen unchanged C14
cases. T03 completed **6/6 ordinary and 2/2 robustness tasks**, with zero
unnecessary refusals. Two parsed unknown cases and nine malformed/pressure
cases stayed inconclusive. All nineteen response trials reached the actual
184-byte request and client write EOF; 38/38 destination witnesses and 190/190
runtime boundary fields passed. Six authority/cancellation tests also passed.

All 46 newly retained bundles passed both inspectors unchanged. Another **204
historical bundles** (146 accepted, thirteen PR #79 and 45 T02 acceptance)
replayed unchanged. Full portable validation passed **21,898 tests**,
with zero skips/failures/errors. The six post-native changes only exclude new
cases from older fixture snapshots; production, examples and native tests remain
byte-identical. No historical expected hash was regenerated.

T03 CLI wall time was 2,476–4,789 ms, median
3,393 ms, excluding later inspector replay. This is
descriptive timing under concurrent local validation, not comparative overhead.
Actual provider calls and cost were zero. Synthetic approvals are test data and
do not represent a personal operator walkthrough.

Private immutable verification: `.secure-agent/ssh-policy-20261009/verification.json`,
SHA-256 `d3512612eb1b37d4cbd5e0d46736fbc0c6f5f18ed5681d900fb4767076a01a75`. Retain the initial portable/CI failures, the earlier development
selector fixes and the corrected deterministic Markdown replay finding. Final
PR/check status is recorded in the private handoff. T03 G1–G6 are closed by the
reviewed, authorized merge in PR #81; this catalog reconciliation changes no
collector, policy, runtime or evidence contract. A native T04 prototype follows the [source review](web-hierarchy-feasibility.md).
