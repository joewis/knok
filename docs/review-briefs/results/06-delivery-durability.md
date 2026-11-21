# Review 06 — Delivery, queue and durability

## Crash matrix

Assume the documented Phase 2 deployment: one bridge process per agent, private hub, local persistent state directory, SQLite on a filesystem that honours `fsync`. The matrix distinguishes a process crash from power loss during a file write; SQLite's guarantees are conditional on the filesystem and storage stack honouring its durability requests.

| Boundary | Durable state before the next step | Crash/restart result | Loss or duplication |
|---|---|---|---|
| Hub fetch → verification | Hub still owns the message; fetch itself is read-only. | Hub offers it again. | No loss; no local duplicate. |
| Verification → gate decision | No local durable state. | Hub offers it again; signature/card check repeats. | No loss. |
| Gate decision → `Queue.put` | Rate hits have already committed to `rates.db`; thread receipt is read-only. | Hub offers it again; gate runs again and charges the rate window again. | No message loss, but a message not yet stored can consume quota more than once. |
| `Queue.put` transaction → delivery ledger | For accepted mail, `seen`, message row and thread receipt commit together in `queue.db`. For a consumed-sequence duplicate, only `seen` commits. | Hub re-offers. `queue.seen` catches the id before the gate; bridge records `duplicate`. | No second queue insert or thread decrement. A rate hit from the first pass remains. |
| Delivery-ledger fsync → hub ack | Queue state and a JSONL decision row are durable. | Hub may re-offer if ack did not land; the next pass records another row, normally `duplicate`. | Harmless duplicate ledger history. A torn ledger append is a separate risk (F4). |
| Hub ack → response received | Hub may already have deleted the row. | If the ack was committed, it is gone; if not, it is re-offered and deduped. | No message loss because queue and ledger precede ack. |
| `Queue.get` commit → inbox append | Message remains in SQLite as `delivering`, attempt count incremented, next availability set. | On queue reopen, all `delivering` rows are reset to `queued` and immediately available. Attempt count is retained. | No loss; handout repeats. |
| Inbox append → inbox fsync | Queue still owns the message. | If the append did not reach disk, replay writes it again. If a prefix reached disk, the next append can be concatenated to a torn JSONL record. | Possible malformed inbox line and unreadable/lost application delivery (F4). |
| Inbox fsync → local queue ack | Complete inbox record is durable; queue row still exists. | Queue replays the message and bridge appends it again, then acks. | Duplicate inbox record. This is at-least-once, not exactly-once; consumer-side idempotency is required. |
| Local queue ack commit → next delivery | Inbox record is durable; queue row deleted and stream advanced. | No replay of that message. | No loss or duplicate. |

A hub ack is correctly delayed until both the local queue decision and the delivery ledger are fsynced. The local inbox handoff uses the same write-before-ack ordering. The important caveat is that fsync-after-append does not make a JSONL append atomic or self-repairing.

## Findings

### F1 — A second message using an in-flight sequence is accepted, then stranded

**Severity: Medium**

**Location:** `src/knok/queue.py:508-531, 532-572, 600-610, 704-747`

**Input:** Two correctly signed messages from the same sender to the same recipient, in the same context, with different `messageId` values but the same `seq`. The first message is still queued when the second arrives.

The queue checks `seq < next_seq`; it does not reject or uniquely constrain a second message at `seq == next_seq`. Both messages are therefore inserted and both return `accepted`. After the first is delivered and acked, `next_seq` advances. The second now has `seq < next_seq`, but it was not marked `late`; `get` only selects the current `next_seq` or `late = 1`. It is no longer eligible for delivery.

There is no transition that converts this already-queued row into a duplicate or dead letter. It remains in the local queue until explicit expiry removes it. The bridge has already written `queued` to its delivery ledger and acked the hub, so the sender's hub copy is gone. If the message carried a reply expectation, the thread receipt was also applied in the original insert transaction even though the application never receives that message.

This differs from the tested #79 case: `tests/test_delivery_ledger.py` covers reuse of a sequence **after it has been consumed**. In that case `put` returns `duplicate`. It does not cover two distinct IDs competing for the same sequence while the first is still pending.

### F2 — A failed write of a hub-signed expiry/dead frame is still acknowledged

**Severity: Medium**

**Location:** `src/knok/bridge.py:672-689`, especially 688-689; `src/knok/bridge.py:850-866`

**Input:** The bridge fetches a valid hub-signed `expired` or `dead` frame, but `notices.jsonl` cannot be appended (full disk, permissions, I/O error).

`_handle_frame` calls `_record_notice(frame)` but ignores its Boolean result. It then returns `("notices", message_id)`; `poll_once` adds that ID to the ack list and, after writing the delivery ledger, acknowledges it to the hub. The hub can delete the only copy even though the recipient's local notice was never recorded.

The message body may already be gone by the time the frame arrives; losing this frame means the owner never learns that it expired or died. The ledger only says `notices`, not the frame's full contents, so it is not a substitute.

This is inconsistent with the local queue-notice path in `drain` (lines 880-890), which confirms a notice only when `_record_notice` succeeds. The hub-frame path should have the same write-success condition before returning an ackable ID.

### F3 — A recipient-side dead letter does not notify the sender as SPEC §6 requires

**Severity: Medium**

**Location:** `src/knok/queue.py:327-345`; `src/knok/bridge.py:880-890`; compare `docs/SPEC.md:330-350`

**Input:** A message reaches five failed local delivery attempts and is moved to `dead_letters`.

The queue inserts a `dead` notice into the **recipient's local** `notices` table. The bridge later writes that notice to the recipient's `notices.jsonl`. No code in this path deposits a hub-signed `dead` frame into the sender's mailbox or otherwise sends the sender a notification.

SPEC §6 says the sender is told by a hub transport frame because the prescribed recovery is that the sender explicitly re-offers the message with a new ID and `retryOf`. The current path informs the recipient's owner, not the sender. The message is inspectable in the recipient's dead-letter store, but the sender has no protocol-level trigger to retry it.

This is distinct from F2: F2 is a failure to persist a frame that was received; F3 is the absence of the required sender notification in the local dead-letter path.

### F4 — JSONL appends are fsynced but not crash-atomic or repaired on restart

**Severity: Medium**

**Location:** `src/knok/bridge.py:573-592, 901-906`

**Input:** Process or machine failure while a JSONL line is being flushed, or power loss before the append has become durable.

Both `_record_deliveries` and `_append_inbox` use text-file append, `write`, `flush`, then `fsync`. This makes a completed append durable before the corresponding ack, but it does not guarantee that a crash during the append leaves either the complete old file or one complete new line. A prefix or truncated final line can remain.

There is no startup validation/truncation of an incomplete trailing line. If the hub re-offers the message after a torn delivery-ledger append, the next JSON record can be appended immediately after the fragment. The ledger can then contain a permanently malformed line. The same issue exists for `inbox.jsonl`: the queue correctly replays the unacked message, but the next append may follow a partial JSON object and leave the application with a malformed record rather than a clean replay.

The inbox path also intentionally permits a duplicate complete line if the process crashes after inbox fsync but before queue ack. That duplicate is normal at-least-once behaviour and must be handled by the consumer; it is not the same failure as a torn line.

The tests cover kill/restart around SQLite `put` and `get`, and check that the ledger is present before hub ack. They do not inject a crash during a JSONL append or test recovery from a truncated final line.

### F5 — Rate quota commits before the message is durably stored

**Severity: Low; documented trade-off**

**Location:** `src/knok/gate.py:180-195, 199-230`; `src/knok/rates.py:47-63`; `src/knok/queue.py:532-570`

`Gate.decide` checks and commits rate hits in the separate `rates.db` before `Queue.put` commits the message and thread receipt in `queue.db`. If the process dies after the rate hit but before the queue transaction, the hub re-offers the message, `seen` is still false, and the gate charges the same message again. A queue insertion failure has the same effect on retry.

A related non-crash case is a new message ID at a sequence already consumed: the gate charges the rate budget, then `Queue.put` records the ID in `seen` and returns `duplicate` without applying the thread receipt. The hub is acked and no message is stored.

Thread state is protected correctly: the receipt is applied only in the queue transaction, so a failed insert or duplicate does not decrement it. Rate state is not atomic with that transaction. The gate module's own docstring explicitly calls out that the rate window is the one store still charged during `decide`; this review records the exact crash consequence rather than treating the split as an accidental implementation omission.

### F6 — Pending notices have strict priority and no deduplication

**Severity: Low availability risk on the private deployment**

**Location:** `src/knok/queue.py:88-105, 358-389, 574-599`

**Input:** A stream of late/gap/dead notices accumulates faster than the application drains them.

Every call to `get` returns the oldest due notice before considering any message. Each notice is stored as a new autoincremented row; there is no notice dedupe key or per-kind/stream bound. A taken notice is delayed for 60 seconds, but another pending notice can be returned immediately on the next call. A sufficiently large notice backlog therefore delays ordinary messages until the backlog is cleared. A sustained authenticated source of late arrivals or gap-producing traffic can keep that backlog non-empty.

The ordering is understandable for a gap/dead notice that should precede later messages, but the implementation applies it globally across all streams and notice types. No fairness limit or test for a sustained notice backlog is present in the scoped tests.

### F7 — The hub mailbox cap does not bound the recipient's local queue

**Severity: Low resource-exhaustion risk; deployment-dependent**

**Location:** `src/knok/queue.py:180-220, 455-572, 838-850`; `docs/HUB.md` “Mailbox cap” and “Delivery semantics”

HUB.md specifies a hub-side cap of 10,000 envelopes or 256 MiB per recipient, with over-capacity deposits refused before storage. That cap is a hub mailbox limit, not a lifetime or end-to-end storage limit.

Once the bridge commits a message to `queue.db`, records its delivery row and acks the hub, the hub copy is removed and its mailbox capacity is freed. If the application does not drain the local queue, those messages accumulate locally. `Queue.put` has no row-count or byte-size cap, and `depth` only reports the count. Thus a recipient can continue accepting mail into an unbounded local SQLite queue even while its application is stopped or stalled. Conversely, a sender can fill the shared hub mailbox before the recipient polls, causing unrelated senders' deposits to receive the same over-capacity response.

The brief excludes hub implementation files, so the hub's enforcement is reported as the HUB.md contract, not independently verified here.

## Ordering and deduplication answers

- **Order:** verify card/signature → `queue.seen(messageId)` → `gate.decide` → `queue.put` (which commits `seen`, message row and any thread receipt together) → delivery-ledger fsync → hub ack. `seen` is read-only; `decide` reads thread state but commits rate hits; `put` commits queue and thread state; ledger append is fsynced; hub ack deletes the hub copy.
- **Lost hub ack after queue commit:** re-offer is verified, `seen` returns true, and the bridge returns `duplicate` before gate evaluation. No second rate hit, no second thread decrement, no second queue row. The duplicate is written as another ledger row and acked.
- **Crash after gate decision but before queue commit:** no `seen` row and no thread decrement; the re-offer runs the gate again and charges rates again (F5).
- **Dedupe key:** `seen.message_id` is a global primary key, independent of sender, context, sequence or body. Same ID with a different body is still duplicate. SPEC requires IDs globally unique across all senders. A new ID at a consumed `seq` is recorded in `seen` and returned as duplicate. A new ID at a sequence already held but not yet consumed is currently accepted as another row, then can become stranded after the first row is acked (F1). A sequence recorded in `skipped` by a gap release is the special case accepted as a `late` arrival.
- **Thread state:** `Receipt.apply` executes on the queue connection inside the insert transaction. Duplicate-by-ID returns before the transaction; duplicate-by-consumed-sequence returns without applying the transition. Both avoid a second decrement.
- **Notices:** local notices are not deduped. A local dead-letter notice is persisted for the recipient's owner, not sent to the sender (F3).

## Durability settings and concurrency

| Store | Journal mode | Synchronous | Busy timeout |
|---|---|---|---|
| `queue.db` via `Queue` | WAL | Explicit `FULL` | 30 seconds (`sqlite3.connect(timeout=30.0)`) |
| `queue.db` via `Threads` | WAL persists for the database | Not explicitly set on this connection; SQLite default is `FULL` | 30 seconds |
| `rates.db` via `Rates` | SQLite default (normally DELETE) | SQLite default (normally FULL) | 5 seconds (`sqlite3.connect` default) |

WAL + `synchronous=FULL` is the strongest ordinary SQLite durability setting used here: a successful queue commit asks SQLite to sync the WAL before returning. The guarantee still depends on the filesystem, mount options, storage controller and virtualised volume honouring sync requests. The repository does not identify the actual filesystem/mount for every deployment, so a categorical power-loss guarantee cannot be made from source alone. The tests verify the queue connection's effective WAL and FULL settings, not physical power-cut behaviour.

The queue takes a non-blocking advisory `flock` on `queue.db.lock` for its lifetime. A second process opening the same queue gets `QueueLockedError`; the bridge constructs its queue before opening the other stores, so a second bridge using the same state directory fails at startup rather than concurrently writing the inbox. This is an enforced guard, not merely convention, assuming the underlying filesystem implements `flock` correctly. The lock does not protect against two unrelated programs writing the JSONL files directly.

## Capacity and dead-letter answers

- Hub cap, per HUB.md: 10,000 envelopes or 256 MiB per recipient; the contract says deposits at cap are refused with 429 on this private hub. This is before hub storage, but hub implementation was outside the brief.
- Local queue: no count/byte cap; it can grow after the bridge acks hub mail even if the application never drains it.
- Dead-letter after five handouts/backoffs: the row moves transactionally from `messages` to `dead_letters`, and a local `dead` notice is queued. The recipient owner can inspect it through `Queue.dead_letter()`. As noted in F3, the sender notification required by SPEC §6 is not implemented in this local path.
- A dead-lettered ID remains in `seen`, so re-putting the same ID cannot resurrect it. An explicit retry needs a new ID and next sequence as SPEC says; that sender-side workflow is outside this brief.

## Scope and method

Reviewed only the six source/test files named in brief 06, plus the specified SPEC §6 and HUB.md context. Static review; no local tests were executed and no source code was changed. The scoped tests cover SQLite restart replay, WAL/FULL settings, queue single-process locking, hub-ack ordering, and the #79 consumed-sequence duplicate. They do not cover the in-flight duplicate-sequence case, failure to persist a hub transport frame, sender notification on recipient-side dead-letter, or torn JSONL recovery.