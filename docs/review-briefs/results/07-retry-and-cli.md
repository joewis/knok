# Review 07 — Retry policy and CLI contract

**Scope:** `src/knok/retry.py`, the `send`, `retry`, and `notices` paths in `src/knok/cli.py`, and the four test files named by the brief. Static review only; tests were not executed. Deployment assumption: private, single-owner tailnet deployment with trusted hosts, authenticated peers that are not trusted, and the CLI potentially invoked by more than one local process.

## Outcome table

The CLI's `_try_deposit` classifies the result of a deposit as follows. HTTP response rows assume the client raises `HubRefused` for a non-success HTTP response; the retry code itself only treats `exc.retryable` (the 429 path) specially.

| Condition | Classification | CLI exit | Retry ledger |
|---|---|---:|---|
| HTTP 400 | Permanent refusal | 2 | `terminal` if evaluated by `retry --send-failed`; no reservation |
| HTTP 401 / 403 | Permanent refusal | 2 | `terminal`; no reservation |
| HTTP 404 | Permanent refusal | 2 | `terminal`; no reservation |
| HTTP 409 | Permanent refusal | 2 | `terminal`; no reservation |
| HTTP 429 after three in-process attempts | Rate-limited, retryable later | 5 | `reserved` before retry; then `retry` outcome |
| HTTP 500 | Permanent refusal under this policy (not specially retryable) | 2 | `terminal`; no reservation |
| Timeout | Transport failure if surfaced as `HubError` | 3 | `reserved` then `retry` outcome when retry is due |
| Connection refused | Transport failure (`HubError`) | 3 | Same as timeout |
| DNS failure | Transport failure if surfaced as `HubError` | 3 | Same as timeout |
| TLS failure | Transport failure if surfaced as `HubError` | 3 | Same as timeout |

The exact network-exception-to-`HubError` mapping is owned by `HubClient`, outside this brief. The retry/CLI layer collapses every caught `HubError` to 3. It retries 429 in-process twice (with 2s and 4s sleeps); a third 429 returns 5. Other `HubRefused` responses return 2 without an in-process retry.

For notice-driven retries: `refused/limits` is retryable (one hour, then one day); `refused/policy|thread|malformed|blocked|unknown`, `expired`, and `dead` are terminal; `gap` and `late` are not send retries. A due retry is reserved before deposit. Single-message exits are 0 for hub acceptance, 1 deferred/not performed, 2 refusal, 3 unreachable, 4 terminal/unknown, and 5 exhausted 429. Scan mode returns 1 if due work could not be performed, otherwise the worst performed status (3 > 2 > 5 > 0).

## Findings

### F1 — Concurrent retry commands can both spend the same budget slot

**Severity: Medium**

**Evidence:** `retry.py:289-309` counts reservations by the set of attempt numbers. `cli.py:626-630` reads the retry ledger once at scan start. `cli.py:799-817` later appends a reservation and deposits without re-reading or locking the ledger.

**Demonstrating command:** Run two `knok retry --message-id <same-id>` processes concurrently after the same `refused/limits` notice is due.

**Observed code path:** Both processes can read a ledger with zero retries and independently decide attempt 1. Both append a `reserved` record with `attempt: 1`, then both call `_retry_envelope`. The set-based count treats those two reservations as one retry. A later scan can therefore still see only one budget unit spent even though two deposits were performed. The same race can occur on attempt 2 and exceed the two-retry ceiling.

The receiver's message-ID dedupe reduces the chance of duplicate application delivery, but it does not make the budget reservation atomic: both processes perform network work, and both can consume the same slot. No lock or compare-and-reserve operation protects `retries.jsonl`.

### F2 — A terminal decision for an old notice permanently masks newer notices for that message

**Severity: Medium**

**Evidence:** `retry.py:317-325` finds a terminal record using only `messageId`; it does not compare the notice timestamp. `cli.py:632-638` selects the latest notice per message ID, and `cli.py:719-733` checks the message-wide terminal record before checking whether the current notice is new. This conflicts with the stated per-notice resolution model at `retry.py:328-337` and the comment at `cli.py:734-736` that a newer notice is a new failure.

**Demonstrating command:** First run `knok retry --message-id m-1` against a terminal notice (for example, `refused/policy`). Then, after a later event produces a newer `refused/limits` notice for the same `messageId`, run `knok retry --message-id m-1` again.

**Observed output:** The second run reports the old terminal reason and exits 4; it never evaluates the newer limits notice or schedules its retry.

A later notice is explicitly supposed to be a new failure, but terminal records are keyed only by message ID. This can suppress a legitimate later retry for the lifetime of the ledger.

### F3 — If the post-deposit outcome append fails, a successful retry is not remembered as resolved

**Severity: Medium**

**Evidence:** `cli.py:803-816` fsyncs a reservation before the deposit. `cli.py:817-833` performs the deposit and reports `delivered: true` for status 0. `cli.py:834-841` then attempts to append the outcome record. If that append fails, only the reservation remains. But `retry.py:328-349` recognises resolution only from a `decision == "retry"`, `status == 0` outcome carrying the matching `noticeAt`; a reservation cannot satisfy it.

**Demonstrating command:** Run a due `knok retry --message-id m-1` with the hub accepting the replay, and make the second `record_retry` call (the outcome append, after the reservation) fail.

**Observed output:** The current invocation reports the retry as successful (status 0 / `delivered: true`), but the ledger contains only `decision: "reserved"`. The next scan does not find a resolved record. It treats the same notice as a fresh retry candidate and, if the next backoff is due, deposits the same envelope again as attempt 2.

The reservation does protect the numeric budget, but it does not preserve the successful outcome. This is precisely the crash/write-failure boundary where the command knows it sent successfully but loses the evidence needed to stop replaying.

### F4 — The `delivered` field means “hub accepted the deposit”, not “recipient received the message”

**Severity: Medium (caller-contract ambiguity)**

**Evidence:** `cli.py:212-238` returns status 0 as soon as `client.deposit(envelope)` returns. `cli.py:170-208` prints `"delivered": status == 0` for `send`; `cli.py:325-344` does the same for `send --retry-of`. In the retry command, `cli.py:822-833` and `cli.py:837-840` also set `delivered` from that deposit status. Yet the CLI's own `notices` documentation says a send exits 0 when the hub accepted the envelope and a later gate refusal, expiry, or dead-letter can still occur (`cli.py:390-400`).

**Demonstrating command:** `knok send --to <peer> --text <body>`, where the hub accepts the envelope but the recipient later refuses it or the message expires.

**Observed output:** The immediate JSON line contains `"delivered": true` and the command exits 0. A later `knok notices` can report that the same message was refused or expired.

The transport operation has succeeded, but end-to-end delivery has not been established. The field therefore overstates what the CLI knows. A caller that treats `delivered: true` as proof that the peer received the message can stop monitoring or fail to surface a later failure. The output should distinguish hub acceptance from recipient delivery (for example, `accepted` versus a later delivery notice).

## Other checks

- **Retry identity:** Correct. `send` stores the signed envelope before its initial deposit (`cli.py:245-259`). `_retry_envelope` reads that envelope and passes it unchanged to `_try_deposit` (`cli.py:285-310`). No new ID, context, sequence, timestamp, or signature is minted. `tests/test_send_retry.py` and the retry-policy integration tests assert the same message ID and context at the recipient. A retry is a verbatim envelope replay.
- **Budget reservation order:** Reservation is fsynced before the deposit. If that write fails, the retry is not performed and the command marks the work unperformed. This is the correct fail-closed ordering for a single process; F1 is the concurrent-process gap.
- **Notice provenance:** A notice for an ID absent from `sent.jsonl` becomes a terminal decision with `record=False`; it is not added to the retry ledger. A successful retry is resolved only when its outcome record matches the notice timestamp. The stale-notice success path is otherwise correct when timestamps are present; F3 covers loss of that outcome record.
- **Exit-code contract:** The documented scan severity ordering is implemented explicitly; a performed failure does not exit 0 in scan mode. Single-message mode returns the performed status directly. A due retry that cannot be started because identity/state loading or reservation writing fails exits 1. Unknown IDs and terminal decisions exit 4. No disagreement was found in the normal paths for codes 0, 1, 2, 3, 4, and 5.
- **Clock:** Backoff and TTL comparisons use wall-clock UTC timestamps. A backward clock step delays a retry until wall time catches up; it does not itself double-count a retry. A forward step can make a retry due early or make an envelope appear expired. No monotonic-clock protection exists, which is an operational assumption for this file-backed policy.
- **Ledger growth:** There is no pruning or compaction path for `retries.jsonl`; each performed retry adds a reservation and an outcome, and terminal decisions add records too. The file grows with the agent's history. The broader `sent.jsonl` growth was already explicitly noted in issue #68; the new retry ledger inherits the same unbounded-retention property. This is a storage/maintenance limitation rather than a loop: the retry budget bounds deposits per message, but not ledger size across messages.
- **Corrupt/truncated ledger:** JSONL readers skip malformed lines independently, so one torn line does not hide later valid records. An unreadable retry ledger produces a warning and is treated as empty for decisions; the actual reservation append then fails and prevents the deposit. A torn reservation is safe to lose because it is written before the deposit. A torn outcome after a successful deposit is the F3 case.
- **`notices` command:** The read-only command filters the five bridge notice kinds, preserves JSON records, reports unreadable lines, and rejects non-positive limits. No issue found in the scoped tests.

## Test coverage

The named tests cover verbatim replay, retry budget and backoff, TTL, notice classification, missing attempt handling, terminal and waiting outcomes, resolution after successful retry, the 429-versus-403 distinction, and scan exit-code severity. Tests do not cover concurrent retry processes, a terminal record followed by a newer notice for the same ID, or failure of the post-deposit outcome append. Static review only; no test suite was run during this review.
