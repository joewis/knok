# Review brief 7 — Retry policy and the CLI contract

You are reviewing what happens after a send fails: whether a retry is the same message, whether the
budget is real, and whether the exit code tells the truth. Report findings, not a summary.

## Scope — read only these

- `src/knok/retry.py` — `read_notices`, `read_attempts`, `read_retries`, `decide_notice`,
  `decide_send`, `due`, `record_retry`, `terminal_decided`, `_retryable`
- `src/knok/cli.py` — `send` (including `--retry-of` and `--send-failed`), `retry`, `notices`
- `tests/test_retry_policy.py`, `tests/test_send_retry.py`, `tests/test_notices_cli.py`,
  `tests/test_cli_send.py`

## Context

- `docs/SPEC.md` §6 (delivery, at-least-once)
- Issue **#68** — the policy this implements
- `retry.py`'s module docstring, which states the exit-code contract

## Deliberately outside this brief

What the receiver does with a duplicate (brief 6). Transport authentication (brief 1).

## Questions

1. **Identity of a retry.** When a retry is performed, is the stored envelope replayed byte-for-byte
   — same `messageId`, `contextId`, `seq`, `sentAt` — or is anything re-minted? Show the code path
   and the JSON written to the hub.
2. **Budget reservation.** How is the retry budget reserved, and in what order relative to the send?
   If the ledger cannot be written, is the retry performed, refused, or counted afterwards? Can two
   concurrent `retry` runs both spend the last unit?
3. **Classification.** Build the table: 400, 401/403, 404, 409, 429, 500, timeout, connection
   refused, DNS failure, TLS failure. For each: retryable or terminal, which record is written, which
   exit code. Then check the table against `decide_send` and `_retryable` — every disagreement is a
   finding.
4. **Exit codes.** What does each code mean, and can two different outcomes share one? In scan mode,
   is the code the outcome of the scan or of the worst retry inside it? Does a *performed and failed*
   retry ever exit 0?
5. **Notice provenance.** What happens to a notice whose message the adapter never sent? To a retry
   whose message was already delivered? Can a stale notice cause a second copy of a delivered
   message?
6. **Termination.** Can a retry loop forever, or grow the ledger without bound? What prunes it, and
   what happens when the file is truncated, unreadable, or contains a half-written line?
7. **Atomicity.** Is the ledger read-modify-written atomically? What does a concurrent writer do to
   the budget? Is any decision recorded before the action it describes, or after?
8. **Clock.** Which decisions depend on wall-clock time, and what does a backward step do — retry
   immediately, never retry, or double count?
9. **The contract with a caller.** Is `delivered` present and accurate for every outcome? Does the
   CLI ever print a success line for a message that was not delivered?

## Report

Start with the outcome table (condition → classification → exit code → what the ledger says). Then
findings where the three disagree: `F1`, `F2`, … with `file:line`, the command that demonstrates it,
and the observed output rather than a description of it.
