# Owned DNS NSID metadata

C10 adds `dig_dns_nsid_v1` through the existing single-action secure CLI and dig
runtime. It is a candidate pending full validation and PR review. Accepted main
has 34 profiles after C9/PR #63; this candidate has **35 profiles using 14 programs**.

## Fixed operation and meaning

One TCP connection to the disconnected owned fixture `127.0.0.1:8080` sends
`harbordesk.test. IN A` without recursion. Its EDNS0 OPT advertises size 1232 and
contains exactly one empty NSID option (code 3). The request is 48 DNS bytes plus
a two-byte TCP length; only the transaction ID varies. The owner validates every
other byte before counting the query. The advertised UDP size does not enable
UDP or bound a TCP reply. DNS request framing is capped at 512 bytes and fixture
responses at 4096 bytes. The tool has five seconds and 8192 combined output bytes,
within one action and a 60-second session.

The caller cannot choose the resolver, name, query type, EDNS options, transport,
retries, search list or credentials. The fixed invocation disables cookies, EDNS
version negotiation, malformed-message recovery, recursion, search and retries.
It uses the accepted sealed dig files, empty resolver configuration, C locale,
private namespaces, TCP scope, bounded threads and process limits. Missing
prerequisites fail closed. Returned bytes never select a new target or operation.

The closed result has `semantics: untrusted_dns_server_metadata` and
`service_identity_verified: false`. It records at most 64 opaque NSID bytes as
lowercase hex, their length, whether NSID was present, and whether EDNS was present.
A present empty option is different from an absent option. Absence means no NSID
in this one validated reply; it does not prove that the server lacks NSID support.
A returned value does not establish host, process, product or organization identity.

This first profile accepts only NOERROR, its exact question, `qr aa`, zero answer
and authority records, and zero or one supported OPT. The fixture intentionally
returns no A records: its useful result is NSID metadata. Other otherwise valid
DNS layouts remain inconclusive. REFUSED and BADVERS are not absence observations.
Duplicate or unknown options, nonzero EDNS flags/version, unsupported DNS flags,
malformed replies, overlong NSID and arbitrary diagnostics are also inconclusive.

Dig prints NSID as spaced hex and a lossy printable annotation. The parser derives
bytes from hex and checks the entire annotation against the C-locale rendering;
printable quotes and backslashes are not escaped by dig. Only hex is normalized
and displayed. Hostile text remains inert raw evidence. This is neither a model
prompt-injection evaluation nor proof of resistance to every encoding.

The reviewed installed native version is BIND 9.20.15. Its exact argv includes
`+tcp +norecurse +tries=1 +time=2 +nosearch +edns=0 +bufsize=1232 +nsid +nocookie
+noednsnegotiation +nobadcookie +nobesteffort +noadflag +nocdflag`; comments, question,
answer, authority and additional sections are enabled so unexpected records are
not silently hidden. The strict parser also permits the pinned client's single
denied startup socket-probe diagnostic. Other versions/diagnostics require review.
See the [BIND manual](https://bind9.readthedocs.io/en/v9.20.15/manpages.html),
[request construction](https://raw.githubusercontent.com/isc-projects/bind9/v9.20.15/bin/dig/dighost.c),
[output renderer](https://raw.githubusercontent.com/isc-projects/bind9/v9.20.15/lib/dns/message.c)
and [RFC 5001](https://www.rfc-editor.org/rfc/rfc5001.html).

## Run and inspect

Use the Linux isolation prerequisites and the shipped approval-required policy.
Every execution needs fresh private output paths and approval of its exact action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment dig-nsid-ok \
  --policy examples/secure-agent-dns-nsid-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-dns-nsid-audit.jsonl \
  --assessment-dir .secure-agent/NEW-dns-nsid-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-dns-nsid-evidence
```

`--describe-tool dig_dns_nsid_v1` provides the read-only recipe. Replace `--execute`
with `--dry-run` to inspect the proposal. Inspection never resumes execution or
restores approval. The initial desktop's fixed HTTP/SSH workflow is unchanged.

## Completion criteria and limitations

All five ordinary tasks must complete with zero unnecessary refusals: printable
NSID, binary NSID, a present empty option, no NSID in EDNS, and no EDNS in the reply.
A separate hostile-NSID trial must preserve useful opaque metadata without action.
Eight negative scenarios exercise refusal, malformed option length, duplicate
NSID, 65-byte NSID, stall, native output pressure, an unexpected option and BADVERS.
Every scenario must witness the fixed query and closed ownership; startup failure
or skipped execution cannot satisfy a negative test.

Require 28/28 blocked destination witnesses and 140/140 boundary fields, bounded
raw channels, structured results and unchanged read-only evidence replay. Six
additional native gates cover one-use grants, missing consumed proof, cancellation
after native exec, private input protection, UDP prohibition and the thread ceiling.
Report useful completion, unnecessary refusals, descriptive latency and zero
provider calls/cost. These trials do not measure comparative authority overhead.
The synthetic test policy is explicitly unattended; shipped policy still requires
fresh approval. Automated checks do not establish personal acceptance.

The owner counts validated requests and acknowledged connections, not an external
packet capture or authenticated DNS identity. Dig text and local hashes do not
establish external authenticity. Only this finite synthetic reply grammar is
verified. Broader DNS support, real deployments, credentials, paid/live evaluation,
deep workflows and benchmarking remain deferred. Accepted B0–B8, C1–C9, offline
R5, local R6 and the initial GUI remain closed. C9's unexplained legacy stall
failure stays recorded separately; successful C10 runs would not establish its cause.

Validation results will be recorded in [verification.md](verification.md).
Private artifacts under `.secure-agent/dns-nsid-20261007/` stay outside Git.
