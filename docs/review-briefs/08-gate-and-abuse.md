# Review brief 8 — Contact gate, policy and abuse

You are reviewing what a peer is allowed to make the system do: the contact policy, the gate, the
limits, and what a refused or blocked sender can still learn and consume. Report findings, not a
summary.

## Scope — read only these

- `src/knok/gate.py` — `decide`, `apply`, `_within_limits`
- `src/knok/policy.py` — policy loading and validation
- `src/knok/rates.py` — limit accounting
- `src/knok/contacts.py` — `request`, `approve`, `deny`, `accept`, `refuse`, `revoke`, `expire`,
  `local_state`, `wire_state`
- `tests/test_gate.py`, `tests/test_policy.py`, `tests/test_policy_reload.py`,
  `tests/test_refusal_notice.py`, `tests/test_contacts.py`

## Context

- `docs/SPEC.md` §9 (the whole section: trust levels, approval, refusals, limits)
- `docs/TESTING.md` — the abuse scenarios the team intends to run
- Issues **#42** (approval held locally) and **#65** (what a decision records)

## Deliberately outside this brief

Who a key belongs to and how rotation is proved (brief 4). Delivery mechanics (brief 6).

## Questions

1. **Trust derivation.** Where does a peer's effective level come from? Show the arithmetic for
   `min(person_trust, harness_trust)` and every input that can raise it. Can any wire input raise a
   level without a local owner action? What resets it, and when?
2. **Refusals.** Build the table: not-allowed, rate-limited, needs-approval, thread-closed,
   malformed, mailbox-full. For each: what the sender observes (bytes, status, notice, silence), what
   is recorded, and whether the refusals are distinguishable from each other. Distinguishable where
   they should not be is an oracle; indistinguishable where the sender needs the difference is a
   usability defect — say which you are claiming.
3. **Limits.** What is counted, per what, over what window? What resets a counter — restart, clock
   step, policy reload, a second bridge? Can two processes each spend the same budget?
4. **Approval surface.** What can a peer cause to appear on the owner's screen, how often, and with
   what information? Is there a cap, and is it enforced before or after the presentation? Can a peer
   cause a decision to be recorded against a key the owner did not see?
5. **Blocked-sender cost.** Can a blocked or unapproved sender consume storage, wake the agent, hold
   a thread, or delay a legitimate sender? Is there any path where its message is stored and then
   refused, rather than refused before storage?
6. **Policy reload.** When the policy file changes, which requests see the old rules and which see
   the new? Is the file parsed atomically, and what happens if it is invalid mid-flight? Can a
   reload widen a policy by accident?
7. **Silence.** Enumerate every path where a message is dropped with no record on either side. For
   each, say what the sender sees and what the receiver could later learn. `#79` is one of these;
   look for the others.
8. **Timing.** From timing alone, what can a peer infer about: hold vs refuse vs approve, whether the
   owner is at the keyboard, and whether a message was delivered? Which of those does §9 say must not
   leak?
9. **Notices.** Notices are exempted from the gate in places so a sender can learn its message died.
   Can a peer exploit that exemption — as a channel, as a flood, or as a way to bypass a limit?

## Report

Start with the refusal table. Then `F1`, `F2`, … with `file:line`, the sequence of messages that
demonstrates it, what the attacker gains, and which §9 sentence it violates. Where §9 is silent,
say so — a missing rule is a finding about the spec, not the code.
