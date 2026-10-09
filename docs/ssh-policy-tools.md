# T03 — bounded SSH advertisement policy assessment

`ssh_transport_policy_v1` is a candidate secure profile. It reuses the accepted
C14 collector bytes and adds a pinned networkless policy assessment. T03 remains
open until its full validation, review and authorized merge; review T02 first.
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
benchmarking remain deferred. This adds one candidate profile and no external
program. C14 and all earlier accepted profile contracts remain unchanged.

## Validation

Final source pins, actual lab results, portable checks and historical replays are
recorded after validation. Until then, this is implementation under review, not an
accepted capability or a professional-service compatibility result.
