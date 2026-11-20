# Review brief 9 — Logging, notices and secret leakage

You are reviewing what the system writes down, who can read it, and what a peer can learn from the
records a refusal leaves behind. Report findings, not a summary.

## Scope — read only these

- `src/knok/bridge.py` — `_record_deliveries`, `_delivery_record`, `_record_drop`, `_record_notice`,
  `_send_refusal_notice`, `_handle_refusal_notice`, `_append_inbox`, `_append_line`
- `src/knok/cli.py` — `notices`
- Every `logging`, `print`, `warnings.warn` and `sys.stderr.write` in `src/knok/`
- `tests/test_notices_cli.py`, `tests/test_delivery_ledger.py`

## Context

- `docs/SPEC.md` §9 — what a peer may learn, and what must stay local
- `docs/HUB.md` — what the hub itself stores and for how long

## Deliberately outside this brief

Whether the logs are correct about delivery (brief 6). Here you ask what they *contain* and who can
read them.

## Questions

1. **Inventory.** For every file the system writes: path, mode, owner, what fields it holds, how it
   grows, and what prunes it. Include `delivery.jsonl`, `inbox.jsonl`, the queue database, the retry
   ledgers, notices, and any log the bridge or hub emits.
2. **Content.** Does any record contain a message body, a subject-like field, a key, a signature, a
   peer's fingerprint, or a path that reveals one? Which of those is required by the spec, and which
   is incidental?
3. **Reconstruction.** Could an operator — or a process that can read these files — reconstruct a
   message the receiver was supposed to refuse, or prove that a particular peer tried to contact an
   agent that blocked it?
4. **Errors.** Does any exception message, traceback, or `repr` of an envelope or identity reach a
   log, a terminal, or a notice? Check the paths where parsing fails and where verification fails.
5. **Notices as a channel.** Are notices messages — do they cross the wire, get stored, count against
   limits, and can they loop? Can a peer use the notice path to send content it could not send as a
   message?
6. **Injection.** Are peer-controlled strings written to a line-oriented file or a log without
   escaping? A newline in an agent id, a subject, or a refusal reason — what does it do to a reader
   that splits on newlines?
7. **Owner activity.** Does any record carry a timestamp that reveals when the owner was at the
   keyboard, approved something, or read a message? §9 says the owner's attention must not leak to
   the peer — does it leak to a log that a peer could influence or read?
8. **Retention.** How long does each record live, and is deletion real (unlink, truncate, vacuum)?
   Is there a copy elsewhere — a backup, a temp file, the delivery ledger's own history?
9. **Reader trust.** Who is expected to read each file, and does the code enforce that (mode, owner,
   directory permissions) or assume it? Name any file a co-located agent could read that it should
   not.

## Report

Start with the inventory table (file → mode → fields → retention → reader). Then `F1`, `F2`, … with
`file:line`, the value that leaks and how it gets there, and the consequence for the peer or the
owner. Distinguish "this record is required by the spec" from "this record is incidental".
