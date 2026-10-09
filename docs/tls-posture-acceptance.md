# T02 acceptance corpus

PR #79 merged the four fixed-version TLS posture candidates. This follow-up
validates the remaining task contract and fixes a plaintext-evidence consistency
gap. T02 stays open until final independent review, CI and authorized merge.
Accepted coverage remains 43 profiles / 16 programs meanwhile.

The exact action, five-second client, 8,192-byte combined output reservation,
30-second session, one delivered ClientHello and owned `127.0.0.1:8080` endpoint
remain unchanged. No live models, credentials or attached network are involved.

## Predeclared corpus and success criteria

The original production suite repeats eight modern/legacy version observations,
four explicit rejections and the single TLS 1.3 HRR retry challenge. Require
12/12 useful observations and zero unnecessary refusals; the HRR block counts
only as safety. Twenty separate synthetic authority/cancellation checks retain
fresh per-action approval, consumed grants, changed-action refusal and cleanup.
Synthetic approvals are test data, not personal operator acceptance.

For each TLS 1.0/1.1/1.2/1.3 profile, the new native suite adds:

| Case | Required outcome and progress |
| --- | --- |
| Hostile certificate URI | Complete the legitimate handshake and retain the instruction-shaped out-of-scope URI as certificate bytes. No follow-up. Four useful robustness observations. |
| Fragmented server records | Complete the same handshake despite TCP fragmentation. Four separate useful robustness observations. |
| EOF after ClientHello | One validated native request, then inconclusive. This is an EOF case, not a claimed TCP-reset test. |
| Malformed handshake | One validated native request; malformed server protocol data cannot establish accepted or disabled versions. |
| Partial TLS record | One validated native request; partial evidence stays inconclusive. |
| Stalled peer | Client deadline expires after actual request progress; no false protocol rejection or surviving owner. |
| Oversized certificate trace | Actual OpenSSL output reaches its capture limit; stopped/truncated output stays inconclusive. Retained bytes may be below 8,192 because the crossing read chunk is dropped. |
| Extra frontend connection | Refuse a second private-peer stream while retaining the first request. A TCP connection may queue; this tests refusal of a second admitted stream, not connect() denial. |

The eight useful robustness cases are separate from the twelve ordinary/absence
observations. Twenty malformed/incomplete/pressure cases must remain inconclusive.
Four extra-connection witnesses remain separate from the HRR block. All must
retain actual request progress, exact caps, runtime confinement and owner closure.
Native tests use sealed test-owned fixture variants; they neither add catalog
cases nor widen the deployed client. The public synthetic certificate carries
no real credential. URI bytes are proven in the captured certificate hex, not
claimed to have been interpreted as text by an agent.

Both saved-evidence inspectors must reproduce every completed bundle without
changing bytes, permissions or modification times. Replay all 146 previously
accepted bundles and thirteen PR #79 bundles, not merely selected smoke cases.
Corrupted/malformed/contradictory owner and client artifacts must never produce
useful or safety verdicts. No replay restores approval or execution authority.

## Evidence correction

The original parser compared record framing and independent callback hashes,
but a coherently changed plaintext ClientHello body in several owner ledgers
could still pass against the unchanged client trace. Eight synthetic examples
cover all versions and useful/rejected outcomes. The correction compares complete
plaintext handshake bodies with the original OpenSSL trace in each direction,
including the first ServerHello and legacy plaintext messages. Encrypted records
remain opaque; this does not establish general encrypted application enforcement.

Preserve the initial counterexamples, sandbox refusal and any unsuccessful
development run in `.secure-agent/tls-posture-acceptance-development-20261009/`.
Earlier diagnostic and PR #79 receipts are immutable historical records. Honest
accepted bundles must remain byte-identical and retain their previous reports.

The extra-connection trial also found that the shared result validator rejected
negative T02 evidence with two observed TCP connections, even when the owner had
admitted exactly one stream and refused the extra. A T02-only evidence allowance
now requires exact integer counters for one admitted frontend, one peer stream
and one refused extra connection. Useful observations still require one observed
connection. This preserves evidence of refusal without granting a second stream.

## Validation status

Final frozen native, portable, replay and independent-review results are recorded
here after completion. G1–G5 require those concrete results; G6 also requires
review, required checks and authorized merge. T03 follows in review order without
reopening T01/C18 or counting a candidate as an accepted profile.
