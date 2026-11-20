# Review brief 6 — Delivery, queue and durability

You are reviewing the path a message takes from the hub to the agent's inbox, and what survives a
crash at each point. Report findings, not a summary.

## Scope — read only these

- `src/knok/queue.py` — `seen`, `put`, `get`, `ack`, `resend`, `expire`, `dead_letter`,
  `_queue_notice`, `confirm_notice`, `_prune_seen`
- `src/knok/bridge.py` — `poll_once`, `_handle`, `_handle_frame`, `drain`, `_record_deliveries`,
  `_delivery_record`, `_append_inbox`
- `src/knok/gate.py` — `decide` and `apply` (the read-only/commit split)
- `tests/queue/test_queue.py`, `tests/test_delivery_ledger.py`, `tests/test_phase2.py`

## Context

- `docs/SPEC.md` §6 (delivery, at-least-once, dead letter)
- `docs/HUB.md` (what the hub keeps, TTL, mailbox cap)
- Issues **#69** (gate ordering), **#79** (messages lost with a counter that said fine),
  **#80** (the delivery ledger)

## Deliberately outside this brief

Retry policy after a send failure (brief 7). The gate's policy decisions (brief 8) — here, only the
*ordering* between decision and storage matters.

## Questions

1. **The crash matrix.** Trace one message from `fetch` to `_append_inbox`. List every step that
   changes state. Then, for a crash exactly between each pair of steps, say what survives, what is
   lost, and what is duplicated. Put it in a table.
2. **Ordering.** What is the order of: dedupe check, gate decision, queue write, hub ack? Which of
   those are read-only and which commit? Can any two disagree after a crash, and what does the
   recipient observe if they do?
3. **The lost ack.** If the hub re-offers a message that was already written, what happens to the
   reply counter, the rate budget and the thread state? Show the code path (`seen` → `decide` →
   `put` → `confirm`) and say where a second application is prevented.
4. **Dedupe key.** What exactly is deduped, and what happens when a sender reuses `seq` in an
   existing context, mints a new `messageId` at a consumed `seq`, or re-sends an identical body with
   the same `messageId`? Which of those is a duplicate and which is a new message?
5. **Capacity.** Is the mailbox cap enforced before or after storage? Can a sender fill a mailbox so
   that the messages it needs are refused? What happens to the cap when the queue is not drained?
6. **Durability.** What are the SQLite settings (`journal_mode`, `synchronous`, busy timeout), and
   what do they guarantee on this filesystem? Is the delivery ledger fsynced before the ack? Is
   `inbox.jsonl` appended with a single write, and what does a partial line do to readers?
7. **Concurrency.** Can two bridge processes run against the same state directory, and what breaks —
   duplicate delivery, a lock error, a half-written inbox? Is there any guard, or is it convention?
8. **Dead letters.** What reaches the dead-letter path, what does the sender learn, and can the same
   message re-enter delivery twice?
9. **Notices.** Notices share the queue with messages. Can a flood of notices starve real messages,
   and is a notice deduped like a message?

## Report

Start with the crash matrix — it is the finding, even when every cell says "correct". Then `F1`,
`F2`, … with `file:line`, the crash point or input, what is lost or duplicated, and how the recipient
would notice. A cell that is duplicated but harmless is worth stating as such rather than omitting.
