# Review 09 — Logging, notices and secret leakage

## Scope and method

Static review of the files named in review brief 09, the logging/printing calls in `src/knok/`, and the relevant portions of `SPEC.md` and `HUB.md`. No tests were executed. This report evaluates what is persisted or emitted, who can read it under the documented deployment, and what a peer can infer or inject. It does not re-audit delivery correctness.

## Inventory

| File / output | Creation mode and owner | Fields / content | Retention and pruning | Intended reader |
|---|---|---|---|---|
| `identity.key` | Created as mode `0600` by identity code; owned by the bridge/CLI OS user | Ed25519 private key | No automatic rotation or deletion | That agent's bridge/CLI only |
| `queue.db` (+ SQLite WAL/SHM as applicable) | SQLite-created under the state directory; no explicit per-file chmod in the bridge | Queued signed envelopes (including message bodies), `seen` IDs, thread state | Message rows removed on ack/expiry/dead-letter paths; dedupe history has its own queue retention behavior. SQLite pages/WAL are not securely erased by row deletion; no routine vacuum/secure erase | That agent's bridge and application |
| `rates.db` | SQLite-created under the state directory; no explicit per-file chmod | Rate-window counters, including the inbound refusal-notice counter | Time-bucket data is aged/rotated by rate logic; deleted pages are not secure erasure | That agent's bridge |
| `contacts.db` | SQLite-created under the state directory; no explicit per-file chmod | Contact state, request history and approval/decision records, including fingerprints and decision timestamps | Contact state expires/revokes; decision history is append-only by design and has no general retention/prune operation | That agent's owner/bridge |
| `inbox.jsonl` | Append-created with Python `open(..., "a")`; mode is default `0666 & umask`, not explicitly set. Owner is the writing OS user | Full delivered envelope, including body, sender/recipient, context, timestamps and signature | Append-only; no pruning or size cap in this path | Agent application / owner via `knok inbox` |
| `sent.jsonl` | Same default append mode; owned by CLI OS user | Every outbound signed envelope, full body and signature, plus local `recordedAt` | Append-only; no pruning. Retry code needs the stored envelope to replay it | That agent's CLI/adapter |
| `retries.jsonl` | Same default append mode; owned by CLI OS user | Message ID, retry/terminal decision, attempt, timing, status and resolution metadata | Append-only; no pruning | That agent's retry adapter / owner |
| `delivery.jsonl` | Same default append mode; owned by bridge OS user | Per-fetch timestamp, message ID/key, outcome, kind, from/to, seq and context ID | Append-only; one row per fetched item/re-offer; no pruning | That agent's operator |
| `refused.jsonl` | Same default append mode; owned by bridge OS user | Refusal timestamp, message ID, context ID, sender and gate rule; deliberately records blocked refusals locally | Append-only; no pruning | That agent's owner/operator |
| `dropped.jsonl` | Same default append mode; owned by bridge OS user | Drop key, timestamp and the **entire original item** | Append-only; no pruning or TTL | That agent's owner/operator |
| `notices.jsonl` | Same default append mode; owned by bridge OS user | Refusal/expiry/dead/late/gap notice metadata: kind, peer IDs, message/context IDs or missing seqs, rule/attempts and event timestamps | Append-only; no pruning or size cap | That agent's owner/adapter via `knok notices` |
| Bridge Python logger | No log file handler or rotation is configured by these reviewed paths; destination depends on the embedding application's logging configuration | Operational messages, identifiers, paths, exception text and (for `log.exception`) traceback | External handler's policy; not controlled here | Operator / service supervisor |
| CLI stdout/stderr | Terminal or calling process; no file created by Knok itself | Send status, warnings/errors; `knok inbox` deliberately prints message text; `knok notices` prints notice fields | Caller/terminal policy | Owner or invoking adapter |
| Hub mailbox database | Hub-owned persistent store; file mode/owner policy is not specified in `HUB.md` | Signed envelopes queued for recipients; headers and form-1 bodies, or ciphertext for sealed form 2 | Mail and transport frames have 72-hour mailbox TTL; dead-letter retention is specified as 30 days | Hub process; recipient bridge fetches its mailbox |
| Hub backups | Nightly encrypted backup of queue and registry is specified in `HUB.md`; concrete backup retention/deletion is not specified | Queue and registry snapshot; therefore includes any queued envelope bodies | Backup cadence specified; retention and secure deletion unspecified | Hub operator / backup system |

**Directory boundary:** `Bridge.__init__` creates the agent state directory and applies `chmod 0700` (bridge.py:245–247). That protects it from other Unix UIDs when the filesystem honors normal Unix permissions. The JSONL writers do not set file modes themselves, and SQLite files are not chmodded here. More importantly, `0700` does not isolate processes running under the *same UID*: another co-located agent process with that UID can traverse the directory and read its files. The documented container/volume-per-agent deployment is the stronger boundary; the code does not create separate OS identities. The bridge does not enforce ownership checks on an existing state directory.

The JSONL writers use append + flush + fsync, but no rotation, truncation or deletion. Unlinking a file would not guarantee secure erasure from SQLite pages, WAL files, snapshots or backups. No log-retention job for these local files was found in the reviewed scope.

## Findings

### F1 — Dropped-item ledger retains the complete rejected envelope indefinitely

**Severity: Medium (privacy/data-retention); higher where an agent state directory is shared with less-trusted processes.**

**Location:** `src/knok/bridge.py:831–849` (`_record_drop`), called from `bridge.py:510–520`.

When an item exhausts its five handling attempts, `_record_drop` writes:

- a local timestamp and key; and
- `"item": item`, the complete fetched object.

That object can contain a form-1 message body, message metadata, sender/recipient identifiers, timestamps and the sender's signature. This is not merely envelope metadata. It is written for items the bridge could not successfully handle, including items for which no trusted sender card was found or whose envelope could not be verified. A peer can therefore cause content it sent to be retained in the recipient's local state even though the bridge never accepted it into the application queue.

The file is append-only and has no expiry or pruning path. This differs from the 30-day metadata retention rule for hub logs and the 30-day dead-letter retention specified in SPEC §6; `dropped.jsonl` is not given a corresponding retention policy. It also differs from the public-hub rule that bodies have zero-day log retention: this is a bridge-local record, not a hub log, but the distinction should be explicit.

**Consequence:** an operator (or any process able to read the agent's state) can reconstruct the body of a message the bridge eventually dropped. A peer cannot read this file over the protocol, but a same-UID co-located process can read it if it can access the directory. The file is incidental to the protocol's delivery contract: the spec requires a visible dead-letter record, but does not require this local unhandleable-item ledger to retain the full envelope forever.

**Recommendation:** store only the minimum diagnostic metadata by default; if retaining the full item is operationally necessary, make that an explicit owner-controlled option, encrypt it at rest, and enforce a bounded retention period with documented deletion behavior.

### F2 — Local state permissions do not isolate agents sharing one OS identity

**Severity: Medium when multiple agents share a UID; Low in the documented one-container/one-volume-per-agent deployment.**

**Location:** `src/knok/bridge.py:245–247`; JSONL writers at `bridge.py:573–588, 817–829, 831–849, 851–866, 901–907`; `src/knok/cli.py:244–261`; `src/knok/retry.py:250–263` (ledger writers).

The bridge sets the state directory to `0700`, but does not set an explicit mode on the JSONL files. Python's append-create mode is filtered through the process umask; SQLite similarly creates its database files under the process identity. The code does not validate that the state directory is owned by the expected UID, and Unix directory permissions do not separate two processes running as that same UID.

The files include private or sensitive material: `identity.key`, outbound signed message bodies in `sent.jsonl`, inbound bodies in `inbox.jsonl` and `queue.db`, and the dropped full envelopes identified in F1. A same-UID sibling agent can read those files if it knows or discovers the paths. The documented topology in HUB.md uses a separate container and volume for each agent; that deployment boundary is doing the isolation work, not per-file access control in Knok.

**Consequence:** a deployment that runs several agents as one Unix user and relies on `0700` directories for isolation does not achieve that isolation. In particular, one agent can read another agent's signing key and stored conversation material.

**Recommendation:** keep the documented per-agent OS/container/volume boundary. If same-host multi-agent isolation is intended without containers, use distinct UIDs and verify directory ownership/mode at startup; explicitly chmod sensitive files and database files rather than relying only on umask.

### F3 — Peer-controlled notice fields can forge terminal and log lines

**Severity: Low to Medium (operator-log integrity / misleading CLI output).**

**Location:** `src/knok/bridge.py:776–815`, especially `804–808`; `src/knok/cli.py:388–425` (`_notice_line`); `src/knok/cli.py:478`.

A pinned peer can send a signed envelope with the `knok.notice` metadata key. The handler checks that `notice` is a dict and that `notice.messageId` is a string, but does not constrain its length or reject control characters; `contextId` and `rule` are also copied without type/format validation. The JSONL writer escapes newlines correctly, so the stored JSON remains one physical line. The human-readable reader then interpolates these values directly into a terminal line, and the bridge logs them with ordinary `%s` formatting. A newline in a peer-supplied message ID or rule can therefore make one notice appear as multiple terminal/log lines, including text that resembles a second event.

The same class of issue exists in other bridge log messages that interpolate peer-supplied `messageId` values (for example, the gate-refusal and duplicate messages at bridge.py:646–654). The envelope validator requires a non-empty string for message IDs but does not impose a printable-character restriction.

**Consequence:** a pinned peer can make the operator's terminal or centrally collected logs misleading. This does not let the peer write arbitrary bytes to the JSONL file—the JSON encoder escapes them—and it does not expose a body through the notice reader.

**Recommendation:** validate protocol identifiers against a narrow printable syntax at the envelope/notice boundary, and escape control characters in every human-facing log/terminal formatter. Keep JSON output as JSON rather than interpolating untrusted values.

### F4 — The refusal-notice path is an ordinary signed message that bypasses the recipient gate

**Severity: Medium for notice integrity; bounded resource impact in the current bridge.**

**Location:** `src/knok/bridge.py:617–631, 776–815`; outbound path `bridge.py:727–774`.

Refusal notices cross the hub as ordinary signed form-1 envelopes. The sender's bridge deposits them through the normal hub endpoint; they are therefore subject to hub mailbox storage/capacity and deposit-side controls. On receipt, however, the bridge diverts any message carrying `metadata["knok.notice"]` before `Gate.decide`. It records only a small metadata frame in `notices.jsonl`, increments a separate per-sender counter, and acks the envelope. It does not create a thread, enter the application inbox, or send a response, so the notice path does not naturally loop.

The receiving check does not prove that the named `messageId` exists in this agent's own `sent.jsonl`, that it was addressed to this peer, or that the supplied rule is one of the gate's allowed refusal rules. This is also the provenance weakness identified in Review 08: a pinned peer can manufacture a false refusal record for an arbitrary ID. The current per-sender cap is 100 notices/hour, but notices are not counted by the normal gate message limits.

The notice's free-text `parts` are ignored; only selected metadata fields are copied to the local notice record. Thus this is not a way to deliver arbitrary body text to the agent application or to bypass the gate with a hidden payload. It is a way to bypass the gate's *message accounting* and pollute the owner's operational record with false notice metadata.

**Consequence:** a pinned peer can claim that it refused a message the local agent never sent, invent the rule and message ID shown in `knok notices`, and consume the separate notice allowance. It cannot use the path to make the application receive the ignored body.

**Recommendation:** correlate each incoming notice with a locally recorded outbound attempt addressed to that sender; validate `rule` against the defined set and validate the context/message relationship before recording it. Consider counting notices against an independent but explicit hub/recipient quota.

### F5 — Local audit files and retry ledgers have no retention policy

**Severity: Medium (privacy and storage growth).**

**Location:** `bridge.py:550–588` (`delivery.jsonl`), `bridge.py:710–725` (`refused.jsonl`), `bridge.py:831–866` (`dropped.jsonl` / `notices.jsonl`); `cli.py:244–261` (`sent.jsonl`); `retry.py:250–263` (`retries.jsonl`).

All of these files are append-only. No code in the reviewed paths rotates, truncates, compacts or prunes them. `sent.jsonl` and `dropped.jsonl` contain complete envelopes/items, while `delivery.jsonl`, `refused.jsonl`, `notices.jsonl` and `retries.jsonl` retain identifiers, peer relationships, rules, outcomes and timestamps. The retry adapter needs the original envelope to replay it, but only until its expiry/retry window; it does not need every historical attempt forever.

The hub's 72-hour mailbox TTL and 30-day dead-letter retention do not prune these bridge-local copies. Deleting an inbox/ledger file would also not securely erase historical SQLite pages or backups where those exist.

**Consequence:** local message bodies and metadata accumulate beyond the lifetime of the corresponding hub item. The audit trail can reveal communication partners, context IDs, refusal rules and activity times long after delivery or expiry. Disk use is unbounded.

**Recommendation:** define per-file retention explicitly. Keep retryable sent envelopes only until expiry plus a short operational grace period; retain metadata audit rows for a documented period (30 days would align with the spec's stated log-retention target); prune or rotate with atomic replacement and account for SQLite WAL/backup copies. Make any longer retention an explicit owner choice.

### F6 — No owner-attention timestamp is sent to the peer by the reviewed notice flow

**Severity: No finding.**

**Location:** `bridge.py:710–774, 776–815`; SPEC §9.

The refusal notice's `sentAt` is the bridge's processing time, and the receiving `notices.jsonl` record's `receivedAt` is the receiver's processing time. These timestamps can reveal when an automated bridge processed a message, but they do not identify when the owner was at the keyboard, read a message, or approved a contact. Approval/decision timestamps and fingerprints remain in the local contact store; the reviewed notice path does not copy them into a wire message. The peer therefore gets no owner-attention signal from this path. The local operator can, of course, correlate the local audit timestamps with other host activity.

## Direct answers to the brief's questions

1. **Inventory:** see the table above. The application has no in-repo log file handler or rotation policy in the reviewed paths; destination and retention for Python logs are delegated to the embedding runtime.
2. **Content:** `inbox.jsonl`, `sent.jsonl`, `queue.db` and `dropped.jsonl` can contain message bodies. `sent.jsonl` needs the original envelope for verbatim retry; `inbox.jsonl` and `queue.db` are the local delivery/application store. The full item in `dropped.jsonl` is incidental and excessive. Local audit/notice files contain metadata, not bodies. The public hub is specified to retain bodies in its queue only while queued, and not in logs; nightly encrypted backups also contain queue data, with backup retention unspecified.
3. **Reconstruction:** an operator with access to `dropped.jsonl` can reconstruct an unhandleable message body. A process with access to `inbox.jsonl`, `sent.jsonl` or `queue.db` can reconstruct ordinary stored messages. A blocked peer's attempt is recorded in local `refused.jsonl` with sender, ID, context, rule and time, but no body. That record is not sent to the peer. A peer cannot read these local files through the protocol.
4. **Errors:** bridge logs include exception strings for fetch/ack/write/policy/queue/notice failures and a traceback for an unexpected poll exception (`log.exception`, bridge.py:918–919). They do not explicitly log `repr(envelope)` or a private identity. Some exception strings can reveal local paths or implementation details; no reviewed path formats an exception into a notice. CLI errors print exception strings for hub and filesystem failures. The full item is persisted by F1, not printed as an exception.
5. **Notices:** refusal notices are ordinary signed messages across the hub, with 24-hour envelope expiry; they use hub mailbox capacity and deposit controls. On receipt they are intercepted before the normal gate, are not delivered to the application, do not create a reply, and do not naturally loop. They have a separate 100-per-sender-per-hour local cap. The body parts are ignored; unvalidated metadata can forge notice records but cannot deliver arbitrary body text.
6. **Injection:** JSONL writers use `json.dumps`, which escapes embedded newlines. Human-readable log and terminal formatters do not escape all peer-controlled identifiers/notice fields; F3 covers the resulting line injection.
7. **Owner activity:** no owner keyboard/read/approval timestamp is put in the reviewed notice wire path. Bridge processing timestamps are visible, but they are not owner-attention timestamps.
8. **Retention:** local JSONL audit, notice and retry files have no pruning. Queue rows and hub frames have their protocol TTL/ack behavior; SQLite/WAL and nightly backups are not secure-erasure mechanisms. Backup retention is unspecified.
9. **Reader trust:** the code assumes the state directory is the security boundary. It chmods the bridge directory to `0700`, but does not set explicit JSONL/SQLite file modes or verify directory ownership. A different UID is blocked by the directory on a normal Unix filesystem; a same-UID sibling process is not. The documented per-agent container/volume boundary must remain in place if agents are mutually untrusted.

## Overall assessment

The peer-facing notice design is narrow: it reports only metadata about a message the peer allegedly sent, and does not deliver notice body text to the application. The important privacy weakness is local retention, not a direct remote read: `dropped.jsonl` stores full unhandleable items indefinitely, while several other body-bearing files also have no pruning. The important isolation caveat is that `0700` is per-UID, not per-process. Keep agents on separate OS/container identities, stop retaining full dropped envelopes by default, add retention, and escape untrusted strings in logs and terminal output.
