# Owned SMB2 negotiation metadata

C6 adds `smb2_negotiate_metadata_v1`, a repository-owned Ruby socket adapter using
the existing secure single-action CLI, sealed runtime and evidence path. It adds
one capability to the accepted 30-profile inventory, for 31 profiles using the
same 14 external programs. Ruby remains a supporting runtime. The operation is
available through the owned CLI, not the GUI. Validation and acceptance remain
pending; the counts below are completion requirements, not reported results.

## Fixed operation and meaning

One connection to the disconnected owned endpoint `127.0.0.1:8080` sends a fixed
108-byte Direct TCP SMB2 NEGOTIATE request. The offer contains only SMB 2.1
(`0x0210`) and SMB 3.0.2 (`0x0302`), signing enabled, client capabilities zero and
a fixed client GUID. There is no hostname, share name, credential, authentication
token or caller-selected dialect. The client immediately closes its write side,
reads one bounded response frame and closes. The fixture validates every request
byte and witnesses write EOF before replying, so no response can elicit a second
client message. Direct TCP framing and the fixed request layout follow Microsoft's
[transport specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83)
and [NEGOTIATE request definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5).

The adapter has an absolute two-second socket-operation deadline, a five-second
execution limit, an 8,192-byte combined output reservation and one action in a
60-second session. It reads four transport-header bytes first, accepts an SMB2
payload length from 72 through 4,096 bytes, and reads exactly that first frame.
Raw stdout is therefore at most 4,100 bytes. An invalid transport type or declared
length stops after the header. Truncated or stalled input produces a fixed failure
diagnostic; partial bytes already read remain evidence. The adapter never waits
for peer EOF after a complete frame and never reads a second frame.

The exact Debian Ruby 3.3 x86-64 interpreter, socket library, native dependencies
and compiled adapter form a sealed 13-file closure, using the same runtime layout
as C5. Host gems, plugins, resolver files, credentials and user load paths are
excluded. Existing namespaces, scoped TCP filtering, Landlock, child-process
restrictions, transport witnesses and the 16-task ceiling apply. Other runtime
layouts fail closed. Early write-half-close is an owned-profile constraint;
compatibility with arbitrary real SMB servers is not established.

Results have `semantics: untrusted_smb2_negotiation_metadata`. A supported success
records the selected offered dialect, security-mode bits, derived signing-required
flag, capability bits and opaque security-buffer length. These are peer reports.
No signature, encryption channel, service identity, authentication requirement or
vulnerability is verified. Server GUID, clock values and transfer limits are not
released as normalized findings. Microsoft's
[response definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5)
defines these wire fields and explicitly excludes using the server GUID as secure
identity evidence.

Capability bits describe this response to the fixed offer. In particular, several
SMB3 response bits depend on corresponding client capability bits, which this
profile sets to zero. Missing response bits therefore do not establish that a
server lacks encryption, multichannel support or another capability. The server
processing rules describe those conditions in
[Receiving an SMB2 NEGOTIATE Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1).
The offer excludes SMB 3.1.1 and its negotiate contexts; it is not exhaustive
dialect or capability enumeration.

## Parser and evidence limits

The networkless parser requires one exact uncompressed, unencrypted SMB2 SYNC
response for command NEGOTIATE, message ID zero and no session, tree or compound
continuation. Success requires structure size 65, an offered dialect, security
mode 1 or 3, and capability bits defined for that dialect. Supported security
buffers are at most 256 bytes and begin immediately after the fixed response
fields; an empty buffer can also use offset zero. Reserved fields defined to be
ignored remain ignored. The header format follows Microsoft's
[SMB2 SYNC header definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4).

A correctly framed `STATUS_NOT_SUPPORTED`, `STATUS_ACCESS_DENIED` or
`STATUS_INVALID_PARAMETER` refusal completes the metadata task. It reports the
peer's status without verifying its cause. The parser validates the
[SMB2 ERROR structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa),
requires zero error contexts and caps error data at 256 bytes. It also accepts
the single undefined error byte documented for older Windows when ByteCount is
zero in Microsoft's
[product behavior notes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a64e55aa-1152-48e4-8206-edd96444e7f7).
Other statuses, dialects, unsupported bits, malformed offsets, truncation and
oversized buffers remain inconclusive, including when the native process exits
successfully. Process success alone is not useful negotiation evidence.

Raw negotiation bytes include the peer's opaque security or error data. These
bytes are retained privately and independently reparsed during inspection; no
token decoder or authentication handler runs. Only the security-buffer length is
released for supported success. The 256-byte parser limit is narrower than the
4,100-byte raw capture limit, so a rejected first frame can still be retained in
bounded raw evidence. The limits intentionally exclude larger or differently
laid-out responses rather than claim general SMB compatibility.

No SESSION_SETUP, NTLM challenge collection workflow, credentials, login, tree
connection, share access, SMB1 fallback, retry or response-directed follow-up is
authorized. The opaque-buffer fixture puts hostile text inside the first frame
and checks that it cannot become normalized instructions or new traffic. This is
not injection detection. Bytes after the first frame are outside the capture and
are neither inspected nor retained; their absence from evidence does not prove
that the peer sent none.

## Run and inspect

Use the Linux isolation prerequisites and the shipped approval-required policy.
Each execution needs fresh private paths and approval bound to its exact action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment smb2-21-optional \
  --policy examples/secure-agent-smb2-negotiation-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-smb2-audit.jsonl \
  --assessment-dir .secure-agent/NEW-smb2-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-smb2-evidence
```

`--describe-tool smb2_negotiate_metadata_v1` gives the read-only recipe. Replace
`--execute` with `--dry-run` to inspect a proposal. Read-only inspection never
restores an approval or resumes execution.

## Completion criteria and pending validation

| Group | Owned cases | Required result |
| --- | --- | --- |
| Ordinary | `smb2-21-optional`, `smb2-21-required`, `smb2-302-optional`, `smb2-302-required`, `smb2-not-supported` | 5/5 useful metadata tasks, zero unnecessary refusals. |
| Robustness | `smb2-fragmented`, `smb2-opaque` | 2/2 useful observations, measured separately, with no further client traffic. |
| Negative/bounds | `smb2-malformed`, `smb2-unoffered`, `smb2-unknown-status`, `smb2-invalid-buffer`, `smb2-truncated`, `smb2-stalled`, `smb2-oversized` | Seven inconclusive results after actual execution and a validated fixed request. |

All 14 scenarios must acknowledge one connection, one exact request and client
write EOF, close their owners, preserve bounded raw and structured evidence,
block both forbidden-destination witnesses and replay unchanged. Startup failure
cannot pass a negative case. The four complete malformed or unsupported responses
must complete transport successfully while remaining inconclusive at the parser.
Additional native tests cover grant consumption and replay denial, missing
proofs, cancellation after actual execution, private-input isolation, UDP refusal
and the task ceiling. Blocking every task fails this batch.

Final portable and native suite counts, source hashes and receipts are **pending**.
The separate clean-source verifier must complete five ordinary and two robustness
trials, block 14/14 forbidden-destination witnesses and replay all 52 accepted
bundles unchanged through both CLI and shared inspection. It pins the accepted
C5 receipt and preserves the inherited receipt chain. Its explicit unattended
synthetic policy does not claim personal approval; the shipped policy requires
approval and separate native gate tests exercise it.

Record useful completion, unnecessary refusals, blocked attempts, capture sizes,
descriptive wall times, zero provider calls and zero cost. Publish final evidence
and limits in [verification.md](verification.md) only after the checks complete.
Comparative benchmarking, deeper workflows, live-model evaluation, paid calls
and real credentials remain deferred. Accepted milestones remain closed.
