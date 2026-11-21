# Review 08 — Gate, contact policy and abuse

**Scope:** `gate.py` (`decide`, `_within_limits`, receipts), `policy.py`, `rates.py`, `contacts.py`, the named gate/policy/reload/refusal/contact tests, and SPEC §9. Static review only; tests were not executed. Deployment assumption: the current private, single-owner bridge setup. Public-hub requirements are called out separately where the scoped code does not implement them.

## Refusal and admission table

| Case | Gate / contact result | What the sender can observe | Recorded state |
|---|---|---|---|
| Not allowed / no accepted contact | `policy` refusal | Same generic gate reason as other refusals. A pinned, verifiable sender receives a signed refusal notice identifying `policy`; an unpinned/unverifiable sender gets no notice. | Recipient `refused.jsonl`; sender `notices.jsonl` if notice succeeds. No queue insert or thread receipt. |
| Rate-limited | `limits` refusal | Same generic gate reason; pinned sender's notice identifies `limits`. | Rate counters are not charged for the refused message. Refusal and notice records as above. |
| Needs approval | Contact state is local `held`; wire state is `requested`. Until accepted, the gate treats it as `policy`. | Peer sees `requested`, not `held`. A pinned sender can receive a `policy` refusal notice for a message sent before approval. | Owner's pending list contains peer, request text, timestamp and presented fingerprint. |
| Thread closed / no reply expected | `thread` refusal | Generic gate reason; pinned sender's notice identifies `thread`. | Refusal/notice records; no queue insert and no receipt decrement. |
| Malformed | `malformed` refusal if it reaches the gate | Generic gate reason; a pinned sender can receive a `malformed` notice. Invalid signatures or items that fail before the gate are unhandled instead and do not receive a gate notice. | Refusal/notice records only for gate-level malformed items. |
| Mailbox full | Not a gate decision; hub deposit returns 429 | Sender sees the exhausted 429 path (CLI exit 5 after in-process retries); there is no recipient refusal notice because the deposit was not accepted. | No recipient gate record. Sender-side retry policy may retry later. |
| Blocked | `blocked` refusal, checked before allow/accepted | Generic gate reason, but deliberately no refusal notice. | Recipient records `blocked` in `refused.jsonl`; sender gets silence. |

The gate's public `reason` is the same string for every refusal. The internal `rule` is distinguishable only in a refusal notice sent to a pinned correspondent, which is the distinction SPEC §9 intends. A blocked peer receives no notice. The gate itself does not return an HTTP 403; it is a recipient-side decision after the envelope has reached the bridge.

## Findings

### F1 — The implemented rate limits do not match the limits specified in §9

**Severity: High for a public deployment; Medium for the current private deployment**

**Evidence:** `policy.py:KNOWN_LIMITS` accepts only `messages_per_hour`, `per_sender_per_hour`, `messages_per_day`, and `contact_requests_per_day`. `gate.py:Gate._within_limits` counts `messages_per_hour` under the single key `("messages", "all")` and `per_sender_per_hour` under `("sender", sender)`. `Gate.__init__` does not use `Policy.probation` to alter limits. The policy parser defaults `probation` to false, but no gate decision reads it.

**Demonstrating sequence:** Configure the policy with the documented-looking values `messages_per_hour: 100` and `per_sender_per_hour: 20`. Have one sender send 20 messages to this recipient, then send to a second recipient; repeat across recipients.

**Observed behaviour:** The first recipient enforces a 20-per-sender limit locally, but there is no counter shared across recipients enforcing the §9 limit of 100 messages/hour per sender. The 100 value is instead applied as an aggregate inbound limit for this one recipient. There is also no hub-wide 10,000/hour counter in the scoped implementation. The probation flag has no effect: the §9 probation limits (20 contact requests/day and 50 messages/day) are not selected or enforced by `Gate` based on that flag, and the §9 5/hour low-engagement throttle is absent.

**Attacker gain / contract violated:** A sender can spread a spray across recipients without hitting the specified per-sender aggregate limit. Probationary agents are not throttled by the specified probation profile. SPEC §9 specifies 100 messages/hour per sender, 20/hour from one sender to one recipient, 10,000/hour per hub, and stricter probation limits. The current limit names and scopes do not implement that model. The hub-wide and low-engagement controls require hub-side work outside this review's scoped files; they are not present in the reviewed gate/policy/rates path.

### F2 — A refusal notice is accepted without proving it describes a message the sender actually sent

**Severity: Medium**

**Evidence:** `bridge.py` is outside the listed source scope, but the notice receiver is exercised by `tests/test_refusal_notice.py`. In `_handle_refusal_notice`, the code checks only that the metadata value is a dict and `notice["messageId"]` is a string. It does not check that the ID exists in the receiver's `sent.jsonl`, that the stored envelope was addressed to this peer, or that the notice rule is one of the defined refusal rules. The test `test_a_notice_flood_is_bounded` itself constructs a notice naming the arbitrary ID `m-x`.

**Demonstrating sequence:** A pinned peer sends a correctly signed ordinary message with `metadata["knok.notice"] = {"kind":"refused","messageId":"some-other-id","rule":"policy"}`. The receiver diverts it to the notice handler before the ordinary gate.

**Observed behaviour:** The receiver records a refusal notice for `some-other-id`, even if it never sent that message to the peer. The `rule` is also accepted as arbitrary metadata rather than checked against the known rule set.

**Attacker gain / contract violated:** A pinned peer can inject false failure records into the owner's `notices.jsonl`, mislead the owner about which messages were refused, and create misleading input for the retry CLI. The per-sender cap limits volume but does not establish provenance. SPEC §9 says a notice may describe only the sender's own message; the receiver should correlate the notice's message ID with a locally recorded attempt addressed to that sender, and validate the notice kind/rule before recording it.

### F3 — Approval is keyed to the peer ID, not the key that is current when approval is granted

**Severity: High if a peer can rotate its key while a request is held**

**Evidence:** `contacts.py:pending` returns the fingerprint stored when the request arrived. `Contacts.approve` checks that the caller-supplied fingerprint equals that stored fingerprint, then records the same value as both `presented_fingerprint` and `decided_fingerprint`. It has no current-registry fingerprint input or lookup. `Contacts.accept` then changes the contact state to `accepted` based on the peer ID and approval row alone. `Gate.decide` admits an accepted peer by sender ID; it does not bind that accepted state to the approved fingerprint.

**Demonstrating sequence:** Peer P sends a contact request under key K1. While the request remains held, P rotates to K2 and the local registry is updated. The owner approves the pending request using the fingerprint returned by `pending()` (K1), then the contact is accepted. P sends a message signed by K2.

**Observed behaviour:** The approval audit says K1 was presented and approved, but the accepted contact state is attached to P's agent ID. The gate therefore admits the message signed by K2 once the bridge's registry trusts K2.

**Attacker gain / contract violated:** A peer can obtain accepted-contact status for a replacement key that was not the key the owner approved. The code's fingerprint equality check only compares the caller's value with the original request record; it does not establish that this is still the key currently attached to the peer. SPEC §9 says approval must be for the key on screen when the owner decides, and that rotation while held must be visible and require refusal plus a fresh request. The approval operation needs the current pinned fingerprint as an independently supplied value and must refuse if it differs from the presented fingerprint; acceptance should remain bound to that approved fingerprint, not just the peer ID.

### F4 — Contact-request state is committed before the owner-presentation record

**Severity: Medium (durability / recoverability)**

**Evidence:** `Contacts.request` calls `_set(peer, LOCAL_HELD, ...)` at `contacts.py` before inserting the `approvals` presentation row and `contact_requests` history row. `_set` commits its own transaction. The presentation and request-history inserts are committed only afterwards. `pending()` uses an inner join between `contacts` and `approvals`.

**Demonstrating sequence:** A contact request reaches `Contacts.request`. The process or database fails after `_set` commits but before the approval row is inserted.

**Observed behaviour:** The contact remains `held` (wire state `requested`), but `pending()` cannot display it because there is no matching `approvals` row. A repeated request is rejected as a duplicate while the held request remains live. The owner has no pending item to approve or deny, and the peer cannot retry until the seven-day expiry.

**Attacker gain / contract violated:** A failure at this boundary can strand a contact request in an owner-invisible state. The owner cannot make the decision §9 requires, while the peer is prevented from submitting a replacement request. The contact row, presentation row and request-history row should be one transaction.

### F5 — Message rate limits are fixed calendar buckets, not rolling windows

**Severity: Low to Medium; §9 leaves the window semantics unspecified**

**Evidence:** `rates.py:_bucket` uses `%Y-%m-%dT%H` for hourly counters and `%Y-%m-%d` for daily counters. Its docstring explicitly notes that a fixed bucket can admit nearly twice the configured limit across a boundary.

**Demonstrating sequence:** Send up to the configured limit immediately before an hour boundary, then send up to the limit again immediately after it.

**Observed behaviour:** Both batches are admitted, so almost twice the nominal hourly allowance can pass within seconds. Restart and policy reload do not reset the counters because they are stored in SQLite; moving the wall clock into a new bucket does reset the applicable count. A backward clock step can return to an earlier bucket and its prior count.

**Attacker gain / contract violated:** A sender can time a burst around bucket boundaries. SPEC §9 says “per hour” but does not define fixed versus rolling windows, so this is a policy/spec ambiguity rather than a clear code violation. If the intent is a hard rolling-hour ceiling, use a rolling window or explicitly document the fixed-bucket burst allowance.

## Trust derivation and contact state

There is no numeric `min(person_trust, harness_trust)` calculation in the reviewed implementation. Admission is a boolean decision:

1. A local `block` entry always refuses, even if the peer is allow-listed or accepted.
2. A local `allow` entry admits without a contact handshake.
3. Otherwise, a contact in `accepted` state admits.
4. Otherwise, `contact_policy: direct` admits (policy validation permits this only for private/local deployment).
5. Everything else is refused before limits and thread checks.

The only inputs that raise an unlisted peer to accepted status are the local owner approval followed by `Contacts.accept`. No message field or wire state can call either operation. A policy edit can add a peer to `allow`, or switch a private/local policy to direct delivery; those are local configuration actions. A peer's own request only creates local `held` state, exposed on the wire as `requested`.

State transitions: `requested/held` expires after seven days; `expired` may request again. `refused` is terminal. `accepted` persists until local `revoke`, which deletes the contact row and returns the peer to `none`. A policy block overrides allow and accepted status. A policy reload rebuilds the gate around the same contact/rate/thread stores, so it does not itself erase accepted contacts or counters.

## Limits and concurrency notes

- Message counters persist across process restart and policy reload because they live in `rates.db`. The bridge's shared `Rates` object serializes each individual `count` and `hit`, but `Gate._within_limits` performs all checks and then all increments as separate operations. There is no transaction spanning check-and-hit. Concurrent calls to `decide` can both observe a remaining slot and both consume it.
- The message counters are charged only after basic gate validation and only if all configured windows pass. A refusal does not consume message quota. The thread receipt is not applied until the queue insert transaction, which correctly prevents a failed insert or duplicate offer from spending reply credit.
- Contact requests use a rolling 30-day per-peer request history and a three-request cap. The owner-presentation cap is five distinct pending/presented peer rows in the rolling 24-hour query. The global daily request limit is optional policy configuration, not a built-in default. The request history and `Rates` daily counter are separate commits, so a crash between them can leave the contact request recorded without charging the daily rate counter.
- A second process using the same bridge queue should be excluded by the queue's process lock, but the rate store itself has no cross-process reservation transaction. The scoped rate implementation should not be treated as a hub-wide limiter.

## Blocked-sender cost and silence

The gate refuses blocked and unapproved messages only after the bridge has a verified envelope to evaluate. The gate itself cannot prevent that envelope from first occupying the hub mailbox or causing the recipient bridge to poll and inspect it. That is different from the §9 public-hub requirement that recipient blocklists be published to the hub and blocked delivery refused before the message reaches the recipient bridge. Hub-side blocklist publication/enforcement is outside this review's source scope, so this report does not claim it is absent from every hub component; it is not implemented by the reviewed gate/policy/contact code.

Within the gate, blocked messages do not enter the local application queue or spend thread receipts/rate quota. They are written to the recipient's local refusal log and produce no sender notice. Unapproved but pinned messages are refused with a `policy` notice; unknown/unverifiable senders do not receive a gate notice. Malformed or unverifiable items that fail before the gate follow the separate unhandled/drop path and may leave no sender-visible refusal.

## Policy reload

The bridge reloads policy at the start of each poll. It parses a changed file into a new immutable `Policy`, verifies the `agent_id`, and swaps the policy and gate together. Invalid, unreadable or wrong-agent files leave the old policy active; a changed file is logged once rather than re-parsed every poll. Existing `Contacts`, `Threads` and `Rates` objects are retained. A rewrite that is syntactically valid and widens `allow` or changes `contact_policy` takes effect on the next poll. The tests cover valid allow/block changes, invalid JSON, wrong-agent policy and store preservation.

The file reader does not use an atomic snapshot protocol. A writer that edits the policy in place can expose a partially written file to the reader; the current behaviour is to retain the previous policy if that intermediate content is invalid. Provisioning should write a complete temporary file and atomically rename it into place. A syntactically valid intermediate document could otherwise be adopted.

## Test coverage

The named tests cover allow-list admission, accepted-contact admission, block-over-allow, private direct delivery, thread expectations/closure, malformed and sealed refusal, configured rate limits, refusal notices, blocked silence, notice flood caps, contact lifecycle, request cooldown/text length, approval fingerprint matching, and policy reload behaviour.

Gaps: no test for the mismatch between §9 rate scopes and policy scopes; no probation-limit test; no cross-recipient sender quota test; no concurrent check-and-hit test; no fabricated notice ID/rule test; no key rotation between request and approval; no crash between the held-state commit and presentation-row commit; and no test for fixed-bucket boundary bursts. Static review only; no test suite was run.
