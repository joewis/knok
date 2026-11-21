# Review 06 — Delivery, queue and durability

**Commit reviewed:** 828c9791da92704ad0c7d71dac26f4d3693aa6f3

## Crash matrix

Assume the documented Phase 2 deployment: one bridge process per agent, private hub, local persistent state directory, SQLite on a filesystem that honours `fsync`. The matrix distinguishes a process crash from power loss during a file write; SQLite's guarantees are conditional on the filesystem and storage stack honouring its durability requests. (`src/knok/queue.py:205-209` `Queue.__init__`, `timeout=30.0` at 206 and `PRAGMA synchronous=FULL` at 209; the same caveat is restated at `src/knok/queue.py:463-467`)

| Boundary | Durable state before the next step | Crash/restart result | Loss or duplication |
|---|---|---|---|
| Hub fetch → verification | Hub still owns the message; fetch itself is read-only. (`src/knok/hub.py:853-862` `Hub.fetch`, one `SELECT` with no write) | Hub offers it again. | No loss; no local duplicate. |
| Verification → gate decision | No local durable state. (`src/knok/bridge.py:608-615` `Bridge._handle`: card lookup at 608 and `verify_envelope` at 612, both before the first store) | Hub offers it again; signature/card check repeats. | No loss. |
| Gate decision → `Queue.put` | Rate hits have already committed to `rates.db`; thread receipt is read-only. (`src/knok/gate.py:194-196` `Gate._within_limits`, the `self.rates.hit` loop; `src/knok/rates.py:57-62` `Rates.hit` commits at 62; `src/knok/gate.py:46-51` `Receipt.apply` is not called by `Gate.decide` at `src/knok/gate.py:199-232`) | Hub offers it again; gate runs again and charges the rate window again. (`src/knok/gate.py:199-232` `Gate.decide`, `_within_limits` at 231) | No message loss, but a message not yet stored can consume quota more than once. |
| `Queue.put` transaction → delivery ledger | For accepted mail, `seen`, message row and thread receipt commit together in `queue.db`. (`src/knok/queue.py:532-567` `Queue.put`: `BEGIN IMMEDIATE` at 532, `seen` insert 534-538, message insert 539-547, `transition.apply` at 566, `COMMIT` at 567) For a consumed-sequence duplicate, only `seen` commits. (`src/knok/queue.py:525-531`, the `seq < next_seq and not late` branch: `INSERT INTO seen` at 526-530 then `return 'duplicate'` at 531, no transaction opened) | Hub re-offers. `queue.seen` catches the id before the gate; bridge records `duplicate`. (`src/knok/bridge.py:641-647` `Bridge._handle`, `self.queue.seen` returns `duplicate` before `gate.decide` at 649) | No second queue insert or thread decrement. A rate hit from the first pass remains. |
| Delivery-ledger fsync → hub ack | Queue state and a JSONL decision row are durable. (`src/knok/queue.py:567` the commit; `src/knok/bridge.py:584-588` `Bridge._record_deliveries`, `write`/`flush`/`fsync`) | Hub may re-offer if ack did not land; the next pass records another row, normally `duplicate`. (`src/knok/hub.py:855-859` `Hub.fetch` returns rows without deleting them, and `src/knok/bridge.py:641-647` dedupes the re-offer) | Harmless duplicate ledger history. A torn ledger append is a separate risk (F4). |
| Hub ack → response received | Hub may already have deleted the row. (`src/knok/hub.py:874-879` `Hub.ack`, `DELETE FROM mail` at 875-878) | If the ack was committed, it is gone; if not, it is re-offered and deduped. | No message loss because queue and ledger precede ack. |
| `Queue.get` commit → inbox append | Message remains in SQLite as `delivering`, attempt count incremented, next availability set. (`src/knok/queue.py:619-626` `Queue.get`, `UPDATE messages SET state = 'delivering', attempts = ?` at 621-625) | On queue reopen, all `delivering` rows are reset to `queued` and immediately available. (`src/knok/queue.py:223-232` `Queue.__init__`, the crash-recovery `UPDATE` at 228-232) Attempt count is retained. | No loss; handout repeats. |
| Inbox append → inbox fsync | Queue still owns the message. | If the append did not reach disk, replay writes it again. (`src/knok/bridge.py:892-896` `Bridge.drain`, `_append_inbox` at 893 before `queue.ack` at 897) If a prefix reached disk, the next append can be concatenated to a torn JSONL record. | Possible malformed inbox line and unreadable/lost application delivery (F4). |
| Inbox fsync → local queue ack | Complete inbox record is durable; queue row still exists. (`src/knok/bridge.py:901-906` `Bridge._append_inbox`, `os.fsync` at 906; the row is removed only by `src/knok/queue.py:723-725`) | Queue replays the message and bridge appends it again, then acks. (`src/knok/queue.py:228-232` returns the unacked row to `queued`; `src/knok/bridge.py:893-897` appends then acks) | Duplicate inbox record. This is at-least-once, not exactly-once; consumer-side idempotency is required. (`src/knok/bridge.py:893-897`: the append at 893 precedes `queue.ack` at 897, so a crash between them replays) |
| Local queue ack commit → next delivery | Inbox record is durable; queue row deleted and stream advanced. (`src/knok/queue.py:721-741` `Queue.ack`: `DELETE FROM messages` at 723-725, `UPDATE streams SET next_seq` at 736-740) | No replay of that message. (`src/knok/queue.py:723-725` deletes the row, and `src/knok/queue.py:600-611` only selects rows still present) | No loss or duplicate. |

A hub ack is correctly delayed until both the local queue decision and the delivery ledger are fsynced. (`src/knok/bridge.py:532-541` `Bridge.poll_once`: `_record_deliveries` at 532, `client.ack` at 539-541) The local inbox handoff uses the same write-before-ack ordering. (`src/knok/bridge.py:892-897` `Bridge.drain`) The important caveat is that fsync-after-append does not make a JSONL append atomic or self-repairing. (`src/knok/bridge.py:584-588` and `src/knok/bridge.py:903-906`: append mode, one `write`, no temp-file-and-rename and no read-back)

## Findings

### F1 — A second message using an in-flight sequence is accepted, then stranded

**Severity: Medium**

**Location:** `src/knok/queue.py:508-531, 532-572, 600-610, 704-747` (`src/knok/queue.py:455-572` `Queue.put`, dedupe lookup at 509-512, `seq < next_seq` branch at 525-531, message insert at 539-547; `src/knok/queue.py:574-630` `Queue.get`, eligibility predicate at 607; `src/knok/queue.py:704-747` `Queue.ack`, `next_seq` advance at 736-740; `src/knok/queue.py:96-97` `message_id TEXT PRIMARY KEY` is the only unique key on `messages`)

**Input:** Two correctly signed messages from the same sender to the same recipient, in the same context, with different `messageId` values but the same `seq`. The first message is still queued when the second arrives.

The queue checks `seq < next_seq`; it does not reject or uniquely constrain a second message at `seq == next_seq`. (`src/knok/queue.py:525` is the only sequence test, `if seq < next_seq and not late`; `src/knok/queue.py:110-111` `idx_messages_stream` is a plain non-unique index) Both messages are therefore inserted and both return `accepted`. (`src/knok/queue.py:539-547` the insert, `src/knok/queue.py:572` `return 'late' if late else 'accepted'`) After the first is delivered and acked, `next_seq` advances. (`src/knok/queue.py:731-740` `Queue.ack`, `UPDATE streams SET next_seq` at 736-740) The second now has `seq < next_seq`, but it was not marked `late`; `get` only selects the current `next_seq` or `late = 1`. (`src/knok/queue.py:607`, `AND (m.seq = s.next_seq OR m.late = 1)`) It is no longer eligible for delivery.

There is no transition that converts this already-queued row into a duplicate or dead letter. (`src/knok/queue.py:318-322` `Queue._sweep` selects only `state = 'delivering'` rows, so a row in any other state is never swept; `src/knok/queue.py:819-823` `Queue.expire` selects only `expires_at <= ?`) It remains in the local queue until explicit expiry removes it. (`src/knok/queue.py:806-843` `Queue.expire`) The bridge has already written `queued` to its delivery ledger and acked the hub, so the sender's hub copy is gone. (`src/knok/bridge.py:670` `Bridge._handle` returns `'queued'`; `src/knok/bridge.py:526-541` records then acks; `src/knok/hub.py:874-879` deletes the copy) If the message carried a reply expectation, the thread receipt was also applied in the original insert transaction even though the application never receives that message. (`src/knok/queue.py:563-566` `transition.apply`, inside the `BEGIN IMMEDIATE` opened at `src/knok/queue.py:532`)

This differs from the tested #79 case: `tests/test_delivery_ledger.py` covers reuse of a sequence **after it has been consumed**. (`tests/test_delivery_ledger.py:97-127` `test_a_message_the_queue_will_not_store_is_recorded_as_a_duplicate`; `queue.ack` at 112 advances the stream before the second deposit at 114) In that case `put` returns `duplicate`. (`src/knok/queue.py:525-531`) It does not cover two distinct IDs competing for the same sequence while the first is still pending.

### F2 — A failed write of a hub-signed expiry/dead frame is still acknowledged

**Severity: Medium**

**Location:** `src/knok/bridge.py:672-689`, especially 688-689; `src/knok/bridge.py:850-866` (`src/knok/bridge.py:672` `Bridge._handle_frame`; the bare `self._record_notice(frame)` call at 688, result discarded; `return 'notices', message_id` at 689; `src/knok/bridge.py:851-866` `Bridge._record_notice`, `return False` at 866 on `OSError`)

**Input:** The bridge fetches a valid hub-signed `expired` or `dead` frame, but `notices.jsonl` cannot be appended (full disk, permissions, I/O error).

`_handle_frame` calls `_record_notice(frame)` but ignores its Boolean result. (`src/knok/bridge.py:688`, no assignment and no test; the function's own docstring at 854-855 says the caller confirms on `True`) It then returns `("notices", message_id)`; (`src/knok/bridge.py:689`, returned regardless of whether the frame reached disk) `poll_once` adds that ID to the ack list and, after writing the delivery ledger, acknowledges it to the hub. (`src/knok/bridge.py:524-525` `handled.append(message_id)`; `src/knok/bridge.py:532` the ledger write; `src/knok/bridge.py:539-541` `self.client.ack(handled)`) The hub can delete the only copy even though the recipient's local notice was never recorded.

The message body may already be gone by the time the frame arrives; losing this frame means the owner never learns that it expired or died. The ledger only says `notices`, not the frame's full contents, so it is not a substitute. (`src/knok/bridge.py:550-571` `Bridge._delivery_record`, which copies only `kind`, `from`, `to`, `seq` and `contextId` at 566-570)

This is inconsistent with the local queue-notice path in `drain` (lines 880-890), which confirms a notice only when `_record_notice` succeeds. (`src/knok/bridge.py:885-888`: `if self._record_notice(envelope):` then `confirm_notice`) The hub-frame path should have the same write-success condition before returning an ackable ID.

### F3 — A recipient-side dead letter does not notify the sender as SPEC §6 requires

**Severity: Medium**

**Location:** `src/knok/queue.py:327-345`; `src/knok/bridge.py:880-890`; compare `docs/SPEC.md:330-350` (`src/knok/queue.py:336-342` `Queue._sweep` queues a `"kind": "dead"` notice; `src/knok/queue.py:358-364` `Queue._queue_notice` inserting into the local `notices` table at 360-364; `src/knok/bridge.py:880-891` `Bridge.drain`, record then `confirm_notice`; `docs/SPEC.md:347-350` 'The sender is told'; `src/knok/hub.py:205-213` `verify_frame`, which refuses any frame where `frame.get("kind") != "expired"` at 212)

**Input:** A message reaches five failed local delivery attempts and is moved to `dead_letters`.

The queue inserts a `dead` notice into the **recipient's local** `notices` table. (`src/knok/queue.py:336-342`; `src/knok/queue.py:125-135` the `notices` schema has no recipient column, it is this queue's own store) The bridge later writes that notice to the recipient's `notices.jsonl`. (`src/knok/bridge.py:885-888`; `src/knok/bridge.py:857-863` `Bridge._record_notice` writing `NOTICES`, defined at `src/knok/bridge.py:66`) No code in this path deposits a hub-signed `dead` frame into the sender's mailbox or otherwise sends the sender a notification. (`src/knok/bridge.py:885-890` is the whole handler and it writes locally only; the hub's only outbound frame is `src/knok/hub.py:178-202` `sign_expired_frame`, and `src/knok/hub.py:208-210` states that no hub event produces a `dead` frame)

SPEC §6 says the sender is told by a hub transport frame because the prescribed recovery is that the sender explicitly re-offers the message with a new ID and `retryOf`. (`docs/SPEC.md:347-350`; `docs/SPEC.md:351-354` for the new-`messageId` + `retryOf` recovery) The current path informs the recipient's owner, not the sender. The message is inspectable in the recipient's dead-letter store, but the sender has no protocol-level trigger to retry it. (`src/knok/queue.py:852-870` `Queue.dead_letter` is the recipient-side store; nothing in `src/knok/bridge.py:868-899` `Bridge.drain` sends a frame back)

This is distinct from F2: F2 is a failure to persist a frame that was received; F3 is the absence of the required sender notification in the local dead-letter path.

### F4 — JSONL appends are fsynced but not crash-atomic or repaired on restart

**Severity: Medium**

**Location:** `src/knok/bridge.py:573-592, 901-906` (`src/knok/bridge.py:573-592` `Bridge._record_deliveries`, `open(path, "a", encoding="utf-8")` at 584, `write` at 586, `flush` at 587, `os.fsync` at 588; `src/knok/bridge.py:901-906` `Bridge._append_inbox`, same sequence at 903-906; `src/knok/bridge.py:817-829` `Bridge._append_line` is the same pattern for the other state files)

**Input:** Process or machine failure while a JSONL line is being flushed, or power loss before the append has become durable.

Both `_record_deliveries` and `_append_inbox` use text-file append, `write`, `flush`, then `fsync`. (`src/knok/bridge.py:584-588`; `src/knok/bridge.py:903-906`) This makes a completed append durable before the corresponding ack, but it does not guarantee that a crash during the append leaves either the complete old file or one complete new line. (`src/knok/bridge.py:584-588`, append mode with no temp file and no rename; the ordering it does buy is `src/knok/bridge.py:532-541`) A prefix or truncated final line can remain.

There is no startup validation/truncation of an incomplete trailing line. (`src/knok/bridge.py:221-222` `Bridge.__init__` only creates and chmods the state directory; `delivery.jsonl` is written at `src/knok/bridge.py:582` and `inbox.jsonl` at `src/knok/bridge.py:902`, and neither file is ever read back) If the hub re-offers the message after a torn delivery-ledger append, the next JSON record can be appended immediately after the fragment. (`src/knok/bridge.py:584` `open(path, "a", encoding="utf-8")` on every call; `src/knok/bridge.py:586` emits one line per record) The ledger can then contain a permanently malformed line. The same issue exists for `inbox.jsonl`: the queue correctly replays the unacked message, but the next append may follow a partial JSON object and leave the application with a malformed record rather than a clean replay. (`src/knok/bridge.py:903-906`; the replay it then lands on comes from `src/knok/queue.py:228-232` and `src/knok/queue.py:619-626`)

The inbox path also intentionally permits a duplicate complete line if the process crashes after inbox fsync but before queue ack. (`src/knok/bridge.py:893-897`: `_append_inbox` then `self.queue.ack`) That duplicate is normal at-least-once behaviour and must be handled by the consumer; it is not the same failure as a torn line.

The tests cover kill/restart around SQLite `put` and `get`, and check that the ledger is present before hub ack. (`tests/queue/test_queue.py:205` `test_restart_replays_unacked_never_acked`, `tests/queue/test_queue.py:241` `test_kill_after_get_before_ack_replays`, `tests/test_delivery_ledger.py:71-94` `test_a_delivered_message_is_recorded_before_the_hub_may_forget_it`) They do not inject a crash during a JSONL append or test recovery from a truncated final line.

### F5 — Rate quota commits before the message is durably stored

**Severity: Low; documented trade-off**

**Location:** `src/knok/gate.py:180-195, 199-230`; `src/knok/rates.py:47-63`; `src/knok/queue.py:532-570` (`src/knok/gate.py:180-197` `Gate._within_limits`, `self.rates.count` checks at 189-193 and the `self.rates.hit` loop at 194-196; `src/knok/gate.py:199-232` `Gate.decide`; `src/knok/rates.py:55-63` `Rates.hit`, `self._conn.commit()` at 62; `src/knok/queue.py:532-567` `Queue.put`)

`Gate.decide` checks and commits rate hits in the separate `rates.db` before `Queue.put` commits the message and thread receipt in `queue.db`. (`src/knok/gate.py:194-196`; `src/knok/rates.py:57-62`; the call order is `src/knok/bridge.py:649` `gate.decide` then `src/knok/bridge.py:660` `queue.put`) If the process dies after the rate hit but before the queue transaction, the hub re-offers the message, `seen` is still false, and the gate charges the same message again. (`src/knok/queue.py:509-512` finds no `seen` row; `src/knok/bridge.py:641` `queue.seen` returns false; `src/knok/gate.py:194-196` charges again) A queue insertion failure has the same effect on retry. (`src/knok/bridge.py:661-665` `Bridge._handle` returns `unhandled` on a queue error, so the item stays unacked and is re-offered)

A related non-crash case is a new message ID at a sequence already consumed: the gate charges the rate budget, then `Queue.put` records the ID in `seen` and returns `duplicate` without applying the thread receipt. (`src/knok/queue.py:525-531`) The hub is acked and no message is stored.

Thread state is protected correctly: the receipt is applied only in the queue transaction, so a failed insert or duplicate does not decrement it. (`src/knok/queue.py:563-567`; `src/knok/gate.py:46-51` `Receipt.apply` never commits; the two duplicate returns at `src/knok/queue.py:512` and `src/knok/queue.py:531` precede `BEGIN IMMEDIATE` at 532) Rate state is not atomic with that transaction. The gate module's own docstring explicitly calls out that the rate window is the one store still charged during `decide`; this review records the exact crash consequence rather than treating the split as an accidental implementation omission. (`src/knok/gate.py:202-205`)

### F6 — Pending notices have strict priority and no deduplication

**Severity: Low availability risk on the private deployment**

**Location:** `src/knok/queue.py:88-105, 358-389, 574-599` (`src/knok/queue.py:125-135` the `notices` schema, `id INTEGER PRIMARY KEY AUTOINCREMENT` at 126 and no dedupe key; `src/knok/queue.py:358-364` `Queue._queue_notice`; `src/knok/queue.py:366-390` `Queue._take_notice`, `ORDER BY id LIMIT 1` at 378; `src/knok/queue.py:595-599` `Queue.get`, the notice returned before the message query at 600-611)

**Input:** A stream of late/gap/dead notices accumulates faster than the application drains them.

Every call to `get` returns the oldest due notice before considering any message. (`src/knok/queue.py:597-599`, `return pending` before the `messages` SELECT at 600-611) Each notice is stored as a new autoincremented row; there is no notice dedupe key or per-kind/stream bound. (`src/knok/queue.py:125-135`; `src/knok/queue.py:360-364`, a plain `INSERT INTO notices` with no conflict clause) A taken notice is delayed for 60 seconds, but another pending notice can be returned immediately on the next call. (`src/knok/queue.py:93` `NOTICE_BACKOFF_SECONDS = 60`, applied at `src/knok/queue.py:384-387`; the predicate at `src/knok/queue.py:376-379` is `state != 'delivered'`, so a second pending row is due at once) A sufficiently large notice backlog therefore delays ordinary messages until the backlog is cleared. A sustained authenticated source of late arrivals or gap-producing traffic can keep that backlog non-empty.

The ordering is understandable for a gap/dead notice that should precede later messages, but the implementation applies it globally across all streams and notice types. (`src/knok/queue.py:377`, no notice-type filter and no stream column in the notice `SELECT`) No fairness limit or test for a sustained notice backlog is present in the scoped tests.

### F7 — The hub mailbox cap does not bound the recipient's local queue

**Severity: Low resource-exhaustion risk; deployment-dependent**

**Location:** `src/knok/queue.py:180-220, 455-572, 838-850`; `docs/HUB.md` “Mailbox cap” and “Delivery semantics” (`src/knok/queue.py:96-109` the `messages` schema has no size or byte column; `src/knok/queue.py:455-572` `Queue.put` has no count or byte check; `src/knok/queue.py:845-850` `Queue.depth` is `SELECT COUNT(*)`; `docs/HUB.md:132` 'Mailbox cap: 10,000 envelopes or 256 MiB per agent'; `docs/HUB.md:122` the 429 answer; `src/knok/hub.py:748-750` `Hub._at_cap`, raised at `src/knok/hub.py:812-813`)

HUB.md specifies a hub-side cap of 10,000 envelopes or 256 MiB per recipient, with over-capacity deposits refused before storage. (`docs/HUB.md:132`; `docs/HUB.md:122`; enforcement `src/knok/hub.py:748-750` `Hub._at_cap`, `raise _OverCapacity()` at 812-813) That cap is a hub mailbox limit, not a lifetime or end-to-end storage limit. (`src/knok/hub.py:741-746` `Hub._mailbox_usage` counts only rows still in `mail`)

Once the bridge commits a message to `queue.db`, records its delivery row and acks the hub, the hub copy is removed and its mailbox capacity is freed. (`src/knok/bridge.py:532-541`; `src/knok/hub.py:874-879` `DELETE FROM mail`) If the application does not drain the local queue, those messages accumulate locally. `Queue.put` has no row-count or byte-size cap, and `depth` only reports the count. (`src/knok/queue.py:455-572`; `src/knok/queue.py:845-850`) Thus a recipient can continue accepting mail into an unbounded local SQLite queue even while its application is stopped or stalled. (`src/knok/queue.py:96-109`, no size column exists to bound it) Conversely, a sender can fill the shared hub mailbox before the recipient polls, causing unrelated senders' deposits to receive the same over-capacity response. (`src/knok/hub.py:748-750`, the cap is per recipient and blind to which sender filled it)

The brief excludes hub implementation files, so the hub's enforcement is reported as the HUB.md contract, not independently verified here.

## Ordering and deduplication answers

- **Order:** verify card/signature → `queue.seen(messageId)` → `gate.decide` → `queue.put` (which commits `seen`, message row and any thread receipt together) (`src/knok/queue.py:532-567`) → delivery-ledger fsync → hub ack. `seen` is read-only; `decide` reads thread state but commits rate hits; `put` commits queue and thread state; ledger append is fsynced; hub ack deletes the hub copy. (`src/knok/queue.py:441-453` `Queue.seen`, one `SELECT` under the lock; `src/knok/gate.py:199-232` `Gate.decide` reads thread state while `src/knok/rates.py:62` commits the hit; `src/knok/bridge.py:586-588`; `src/knok/hub.py:874-879`)
- **Lost hub ack after queue commit:** re-offer is verified, `seen` returns true, and the bridge returns `duplicate` before gate evaluation. (`src/knok/bridge.py:641-647`, before `gate.decide` at 649) No second rate hit, no second thread decrement, no second queue row. The duplicate is written as another ledger row and acked. (`src/knok/bridge.py:526-541`)
- **Crash after gate decision but before queue commit:** no `seen` row and no thread decrement; the re-offer runs the gate again and charges rates again (F5). (`src/knok/queue.py:509-512`; `src/knok/gate.py:194-196`)
- **Dedupe key:** `seen.message_id` is a global primary key, independent of sender, context, sequence or body. (`src/knok/queue.py:112-116`) Same ID with a different body is still duplicate. SPEC requires IDs globally unique across all senders. A new ID at a consumed `seq` is recorded in `seen` and returned as duplicate. (`src/knok/queue.py:526-531`) A new ID at a sequence already held but not yet consumed is currently accepted as another row, then can become stranded after the first row is acked (F1). (`src/knok/queue.py:525` is the only guard and `src/knok/queue.py:607` the only eligibility test) A sequence recorded in `skipped` by a gap release is the special case accepted as a `late` arrival. (`src/knok/queue.py:522-524` calling `_was_skipped`; recorded at `src/knok/queue.py:680-686`; read at `src/knok/queue.py:402-408`)
- **Thread state:** `Receipt.apply` executes on the queue connection inside the insert transaction. (`src/knok/gate.py:46-51`; called at `src/knok/queue.py:566`) Duplicate-by-ID returns before the transaction; duplicate-by-consumed-sequence returns without applying the transition. Both avoid a second decrement. (`src/knok/queue.py:509-512` and `src/knok/queue.py:525-531` both return before `BEGIN IMMEDIATE` at 532)
- **Notices:** local notices are not deduped. (`src/knok/queue.py:360-364`) A local dead-letter notice is persisted for the recipient's owner, not sent to the sender (F3).

## Durability settings and concurrency

| Store | Journal mode | Synchronous | Busy timeout |
|---|---|---|---|
| `queue.db` via `Queue` | WAL | Explicit `FULL` | 30 seconds (`sqlite3.connect(timeout=30.0)`) (`src/knok/queue.py:205-207` `timeout=30.0`; `src/knok/queue.py:208` `PRAGMA journal_mode=WAL`; `src/knok/queue.py:209` `PRAGMA synchronous=FULL`) |
| `queue.db` via `Threads` | WAL persists for the database | Not explicitly set on this connection; SQLite default is `FULL` | 30 seconds (`src/knok/gate.py:95` `sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)`; no journal or synchronous pragma is executed at 96-100, so the mode is whatever the queue set on the shared file) |
| `rates.db` via `Rates` | SQLite default (normally DELETE) | SQLite default (normally FULL) | 5 seconds (`sqlite3.connect` default) (`src/knok/rates.py:31` `sqlite3.connect(str(path), check_same_thread=False)`, no timeout and no pragma; schema and commit at 32-36) |

WAL + `synchronous=FULL` is the strongest ordinary SQLite durability setting used here: a successful queue commit asks SQLite to sync the WAL before returning. (`src/knok/queue.py:208-209`) The guarantee still depends on the filesystem, mount options, storage controller and virtualised volume honouring sync requests. The repository does not identify the actual filesystem/mount for every deployment, so a categorical power-loss guarantee cannot be made from source alone. The tests verify the queue connection's effective WAL and FULL settings, not physical power-cut behaviour. (`tests/queue/test_queue.py:258-259`, `PRAGMA journal_mode` is `'wal'` and `PRAGMA synchronous` is 2)

The queue takes a non-blocking advisory `flock` on `queue.db.lock` for its lifetime. (`src/knok/queue.py:197-203` `Queue.__init__`, `fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)` at 200) A second process opening the same queue gets `QueueLockedError`; (`src/knok/queue.py:200-203`; the covering test is `tests/queue/test_queue.py:267`) the bridge constructs its queue before opening the other stores, so a second bridge using the same state directory fails at startup rather than concurrently writing the inbox. (`src/knok/bridge.py:235-240` `Bridge.__init__` opens `Queue` at 235, `Rates` at 236, `Contacts` at 237 and `Threads` at 240, in that order) This is an enforced guard, not merely convention, assuming the underlying filesystem implements `flock` correctly. The lock does not protect against two unrelated programs writing the JSONL files directly.

## Capacity and dead-letter answers

- Hub cap, per HUB.md: 10,000 envelopes or 256 MiB per recipient; the contract says deposits at cap are refused with 429 on this private hub. (`docs/HUB.md:132`; `docs/HUB.md:122`; `src/knok/hub.py:748-750` `Hub._at_cap`) This is before hub storage, but hub implementation was outside the brief.
- Local queue: no count/byte cap; it can grow after the bridge acks hub mail even if the application never drains it. (`src/knok/queue.py:455-572`; `src/knok/bridge.py:532-541`)
- Dead-letter after five handouts/backoffs: the row moves transactionally from `messages` to `dead_letters`, and a local `dead` notice is queued. (`src/knok/queue.py:81-82` `BACKOFF_SECONDS` and `MAX_ATTEMPTS`; `src/knok/queue.py:328-345` `Queue._sweep`, `INSERT INTO dead_letters` at 329-335, notice at 336-342, `DELETE FROM messages` at 343-345) The recipient owner can inspect it through `Queue.dead_letter()`. (`src/knok/queue.py:852-870`) As noted in F3, the sender notification required by SPEC §6 is not implemented in this local path.
- A dead-lettered ID remains in `seen`, so re-putting the same ID cannot resurrect it. (`src/knok/queue.py:509-512` the dedupe lookup; `src/knok/queue.py:423-427` `_prune_seen` is what bounds how long that row survives) An explicit retry needs a new ID and next sequence as SPEC says; that sender-side workflow is outside this brief.

## Scope and method

Reviewed only the six source/test files named in brief 06, plus the specified SPEC §6 and HUB.md context. Static review; no local tests were executed and no source code was changed. The scoped tests cover SQLite restart replay, WAL/FULL settings, queue single-process locking, hub-ack ordering, and the #79 consumed-sequence duplicate. (`tests/queue/test_queue.py:205` and `tests/queue/test_queue.py:241`; `tests/queue/test_queue.py:258-259`; `tests/queue/test_queue.py:267`; `tests/test_delivery_ledger.py:71-94`; `tests/test_delivery_ledger.py:97-127`) They do not cover the in-flight duplicate-sequence case, failure to persist a hub transport frame, sender notification on recipient-side dead-letter, or torn JSONL recovery.