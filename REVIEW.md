# Reviewing Knok

A guide for a reader who did not build this and is deciding whether to trust it. It says where the
claims live, which invariants are worth attacking, and what is deliberately missing. It does not
argue that the code is correct — that is the review's job.

## Run it first

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                       # 411 tests, ~100 s, no network, no credentials
deploy/demo.sh                         # the Phase 2 exit criterion, with assertions
```

Every test runs against a real hub on loopback with real signed envelopes. A test that needs a
clock passes one in; there are no sleeps that hide a race.

## What to attack

Each of these is a claim the code makes in a comment, and each is where a failure would be silent
rather than loud. The file is what the claim rests on; the right-hand column is how to break it.

| Claim | Where | How a reviewer breaks it |
|---|---|---|
| A message is ours only after it is durably stored | `bridge.py` (`decide` → `put` → `confirm`), `queue.py` | Make `put` fail after the gate has decided; the reply counter and rate budget must not have moved |
| An ack never outruns a write | `bridge.py::drain`, `hub.py` | Kill the process between the write and the ack; the message must still be delivered exactly once |
| A duplicate never moves state twice | `queue.py::seen`, `bridge.py::_handle` | Replay a delivered envelope after a lost ack; it must be recognised, not refused as unsolicited |
| A refusal looks the same whatever the reason | `gate.py`, `recv.py` | Compare the bytes and exit codes of a policy refusal, a thread refusal and a blocked peer |
| Approval is a local precondition, not a wire state | `contacts.py`, `docs/SPEC.md` §9 | Ask what a peer can infer from an acceptance, and whether `held` is ever visible off-box |
| A decision says what the owner was shown | `contacts.py` (`decisions` table) | Rotate a key between presentation and decision; the two fingerprints must differ on a refusal and be refused outright on an approval |
| A card is pinned under the name its body signs | `contacts.py::load_cards` | Misfile a valid card under another agent's name; it must not grant that name |
| A sealed body is opened by the receiving bridge | `docs/decisions/0003-...md`, `envelope.py::unseal` | Check the RFC 9180 A.2 vectors in both directions; wrong key, wrong aad and tampered ciphertext must be refusals, never exceptions |
| A retry never mints a new id | `cli.py::send --retry-of`, `retry.py` | Retry a failed send and compare `messageId` and `contextId` on the wire |
| A retry budget is enforced by a durable reservation | `retry.py` | Make the ledger unwritable; the retry must not be performed |

## What is deliberately incomplete

Not defects, and each is named where it is left out:

- **Sealed mail cannot travel yet.** The boundary is decided (0003) and the primitives are in
  (`hpke.py`, `envelope.seal`/`unseal`), but nothing mints a sealed message, the hub refuses form 2
  at deposit, and the queue still rejects it. What §6 still owes is issue **#83**.
- **The public hub is not built.** `docs/PHASE3.md` is the plan; registration, the VPS and the
  abuse runbook are Phase 3.
- **Presence push is deferred to Phase 4.** Presence is pull-on-demand only.
- **The dead-letter re-offer shape for sealed messages** is left to the unseal slices; 0003 says why
  re-sending the original bytes is not a re-offer.
- **`approvals` and `decisions` are two tables, not one.** The split is deliberate: one is the live
  request, the other is the append-only history.

## Where the reasoning lives

- `docs/SPEC.md` — the design, and the normative claims this code is answerable to.
- `docs/HUB.md` — the hub's own contract: what it stores, what it can read, what it must not.
- `docs/decisions/0001-0004` — the four decisions that are not obvious from the code: two authors,
  registry key records, the sealed decryption boundary, and what "pinned" means.
- `docs/TESTING.md` — the testing phase this repository is in, and the security review's inputs.
- `docs/WORKING.md` — how the authors work, including what a review has to contain to count.

## How to judge a fix

The convention in this repository: a fix names the failure it prevents, and its test **fails on the
previous commit**. A test that passes before and after is not evidence of a fix. Where a probe was
run against a live system, the comment or the PR body carries the observed output rather than a
description of it.

Two mistakes are on the record in the history rather than quietly fixed, because they are the
failure modes this code keeps meeting: a merge was taken while the fix sat on a rebased branch (the
PR said merged, `main` still had the bug), and a message was recorded as `queued` when the queue had
answered `duplicate` (the mailbox forgot it while the counter said it was fine). Both are why the
delivery ledger and the "read the merged file, not the PR status" rule exist.
