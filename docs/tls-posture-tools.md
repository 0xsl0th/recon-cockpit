# T02 — owned TLS version posture candidates

Four production profiles are under review: `openssl_tls10_posture_v1`,
`openssl_tls11_posture_v1`, `openssl_tls12_posture_v1` and
`openssl_tls13_posture_v1`. T02 is open. Accepted coverage remains **43 profiles
using 16 programs**; these four candidates reuse OpenSSL and add no program.

Each profile uses the secure policy, approval, audit and consumed-permit path
for one fixed-version probe against an owned disconnected `127.0.0.1:8080`
fixture. Each action needs its own authorization. Sessions allow one step,
30 seconds and 8,192 client output bytes, with a five-second client deadline.
These candidates do not attach to real internal networks.

The owner reuses the reviewed complete-record mediator and an unnamed private
socketpair. It withholds a second plaintext ClientHello before peer delivery.
The client cannot create Unix sockets or socketpairs. Encrypted contents remain
opaque; this does not prove general encrypted application-data prevention.

Client stdout/stderr and independent owner/mediator records must corroborate the
observation. Explicit protocol rejection remains process exit 1 and a failed
execution, while the report may count it as useful protocol evidence. Preventing
a retry is a separate safety result and does not count as useful completion.
Missing, malformed, contradictory, stopped or truncated evidence is inconclusive.

The owner receipt is stored separately as `tls-owner-<execution_id>.json`, capped
at 262,144 bytes. The ordinary result artifact retains its 65,536-byte cap. Both
read-only assessment inspectors verify the original owner bytes and reconstruct
the committed authority result before replay. Diagnostic captures and their
unregistered identifiers cannot substitute for product authorization.

Use the read-only catalog to view the fixed recipe and required gates:

```sh
python -m recon_cockpit.secure_agent --describe-tool openssl_tls13_posture_v1
```

The policy example is `examples/secure-agent-tls-posture-policy.json`, with
approval required. Cases are `tls-posture-<tls1|tls1_1|tls1_2|tls1_3>-<modern|legacy|reject>`
and `tls-posture-tls1_3-hrr`. Development tests use explicitly synthetic approval
or policy settings; they do not record personal operator acceptance.

The remaining T02 acceptance corpus includes hostile-usefulness, ambiguity and
pressure, enforcement, cancellation and unchanged accepted-bundle regression.
T03–T06 follow the coverage checklist. Credentials, paid/live models, external
targets, deeper workflows and comparative benchmarking remain deferred.
