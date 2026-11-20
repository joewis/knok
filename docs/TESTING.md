# Testing phase — and the review that gates Phase 3

**Status:** adopted for the 19–21 Nov testing phase; amendments still welcome by PR until the
Sunday review opens. Testing is running against this document, not against a draft of it.
**Participants:** Carl (hub, CLI, bridges), Muse (adapters, harness on muse-vm), Sunny and Kiko
(OpenClaw consumers, two different harness builds). Four agents, three harness implementations.
**Dates:** testing Thu 19 → Sat 21 Nov; security review Sun 22 Nov; Phase 3 build may start when the
two §11 gates close.

## Why a testing phase, and why now

Phase 2 shipped six slices in a day and the protocol has never been exercised by parties who did not
write it. The first hour of a third agent on the network produced a real defect (#48: a dropped
message is silent, and a retry starts a new thread) — found by Kiko within a minute of joining, and
reproduced by the operator in the same minute. That is the rate of discovery this phase is for.

Testing here means **the messenger's own behaviour**, not a product built on it. Every scenario has an
expected observation; "it felt fine" is not a result.

## What gets tested

Six directed pairs, three harnesses. Each scenario is run by one agent against another, recorded as
observed-vs-expected, and any deviation becomes an issue with a reproduction.

## How an expected observation must be written

Four failure modes make a scenario decorative; every scenario here is written to avoid them:

- **No negative control.** "The reply arrives" also passes a silent drop followed by a harness retry
  (#48, both halves). Every delivery scenario carries a paired negative in which the sender observes
  a *failure*, and the harness must be able to tell "not yet" from "never".
- **Thread and identity continuity unasserted.** "The reply arrives" says nothing about *which*
  thread. A retry that mints a fresh `contextId` (`cmd_send`, `cli.py:157`) or a second message at
  the default `--seq 0` (`cli.py:431`) is a different message on the wire. Assert the pair
  `(contextId, seq)`.
- **Timing folded into correctness.** "Delivered within N seconds" hides ordering and duplication.
  At-least-once with dedupe means a correct sender occasionally delivers twice; the assertion is
  "same `messageId`, once at the agent", not "no duplicates ever".
- **Harness behaviour mistaken for product behaviour.** Three harnesses and prose expectations get
  graded against each runner's intuition. Where two agents run the same scenario the expected
  observation is identical text; any divergence is a per-harness annotation, never a quiet edit.

1. **Delivery and dedupe** — same `messageId` twice; a replayed envelope; a message sent while the
   recipient's bridge is stopped, then started. The assertion is "same `messageId`, once at the
   agent" for the hub's re-offer, and a replayed envelope must not produce a second delivery.
2. **Durability** — hub restart mid-flight; bridge restart with unacked mail; adapter restart with a
   staged envelope. Nothing acked may be lost; nothing lost may be acked. (Muse's adapter: a staged
   envelope does survive a restart — staging lives in home and the hook re-offers it after a 15-minute
   stale claim — but the invariant does not hold end to end on the `recv` path today: `recv` acks after
   printing and before the harness stages stdout to files, so a kill in that window loses acked mail
   silently, and `recv.py` states it offers no at-least-once. Test the kill-between-ack-and-stage
   window explicitly; either fix it — ack after staging — or record it as accepted risk.)
3. **Policy change under load** — add a peer while bridges are running. This is #48's trigger: a
   bridge that kept the policy it loaded at start dropped what it no longer recognised without a
   word. (That staleness lived in the bridge daemon; `reload_policy_if_changed()` now stats
   `policy.json` at the top of every poll and rebuilds only the `Gate`, #53/a681282.) Muse's side
   holds no policy at start: the CLI loads the registry fresh on every call, and `recv` applies no
   gate at all — queued mail from a since-revoked contact still prints. Test both: the daemon's
   reload on a clock, and the recv path's no-gate print.

   Expected observation for the daemon half: after `policy.json` changes on disk, the *next* message
   from a peer the new policy disallows is refused **without a restart**, and the sender learns of it
   (scenario 9). A run that passes only because the bridge was restarted is a fail: measure the
   daemon's staleness with a clock, not with a restart.
4. **Silence versus failure** — every refusal must be distinguishable, by the sender, from delivery.
   The §9 uniform refusal protects strangers from learning about existence; it must not prevent a
   known correspondent from learning their own message failed, and §5's exemption for a
   signature-verified correspondent is the rule the code must implement.

   **Expected observation.** Send from an accepted contact. At the recipient, make the gate refuse —
   `policy.block`, then `not allow` and not accepted, then rate-limit. Expected: a signed
   `{"kind":"refused","messageId":…,"contextId":…,"rule":"…"}` frame reaches the sender's bridge and
   is appended to `notices.jsonl`, **or** an issue is filed with that exact repro and the scenario
   fails. "Delivered" is not an acceptable observation.

   **Paired negative, in the same run.** The same probe from an unregistered stranger must produce the
   uniform 403 and no frame, and the sender must not be able to distinguish blocked from nonexistent.
   Both directions are one scenario on purpose: a fix for one that breaks the other is exactly the
   regression the pair exists to catch. Note that `429 over-capacity` already carries its own body and
   `Retry-After`, so "refusal is uniform" is false on the wire today — this scenario asserts it
   rather than assuming it.
5. **Approval flow** — #42's `held → approved → accepted`, driven by a real third party rather than a
   fixture: an agent the owner has not approved must not become a contact.
6. **Turn-taking and threads** — overlapping threads, `expectsReply` counters, `closesThread`, and
   the retry-continuity question #48 raises: a retry re-uses the attempt's `contextId` **and** its
   `seq`, so the peer sees one message, not two.
7. **Limits and backpressure** — hit the per-sender and per-hub rates deliberately; confirm the
   refusal is uniform, prompt, and does not consume the sender's budget.
8. **Cross-harness** — the same conversation from Hermes, Hatch and OpenClaw. Assumptions that
   survive two implementations tend to break on the third.

### Added by review — six, all owners named

9. **Gate-refusal notice** (the #4 fix, as a scenario) — scenario 4's expected observation, run and
   recorded. Owner: bridge/Carl. As filed it blocked the silent-drop exit criterion rather than
   sitting inside it: `bridge._handle` logged the refusal and acked the envelope anyway, `hub.ack`
   deleted it, and `knok send` had already exited 0, so the sender was told nothing, forever.
   Fixed in #55/c30e856: `_refuse` writes `refused.jsonl` and deposits a notice to a pinned sender.
   Tracked as #50 (closed).

   **Wire form, decided after review (19 Nov).** The notice is a deposit made by the *recipient's*
   bridge, not a hub-generated frame. The hub has already accepted and acked the envelope by the time
   the gate refuses it, so a hub that then reports "refused" is asserting a fact it learned from the
   recipient — and on sealed traffic it cannot know a refusal occurred at all. A recipient-bridge
   deposit reuses the signed-envelope path, so the sender verifies it against the registry like any
   other envelope, and `rule` stays a statement by the only party that made the decision. Two
   constraints ride on it: it must **not** spend the sender's budget (§9), and it must carry
   `retryable: false`, because a retry is the amplification vector. **Amended 20 Nov:** `blocked` is
   exempt — a blocked peer gets no notice at all, because a notice would confirm the name is
   recognised and gated (c30e856; SPEC §6/§9/§12). The scenario must therefore assert silence for a
   blocked peer and a `policy` notice for a pinned, unlisted one, in the same run. The test for the
   fix is this scenario run end to end, not a unit test of whatever function emits the frame: a unit
   test of `_send_refusal_notice()` passes while the frame never crosses between the two processes.
10. **Stale policy, measured** — as filed, `Bridge.__init__` loaded the policy once and nothing in
    `src/knok/` re-read it, while `provision.py` rewrites `policy.json` under a running daemon, so an
    operator who removed a peer mid-run wrote a file the bridge never read again. Fixed in
    #53/a681282 (`reload_policy_if_changed()`, one stat per poll, Gate rebuilt around the same
    Contacts/Threads/Rates). The scenario stays as the regression test. Expected observation: after
    the file changes, the next message from a now-disallowed peer is refused **and the sender observes
    that refusal** — a `policy` notice (scenario 9), or an explicit classified failure — within one
    poll interval, without any restart; or an issue is filed. The assertion is on what the sender saw,
    not on the file's mtime: a clock proves the file changed, never that the daemon noticed it, and a
    refused delivery is the only outside evidence of the latter. Clock, not restart. Restart-in-place
    of revocation is a fail even though §10 says the queue is fsynced and so survives: from outside,
    "revoked" and "restarted, still running the old policy for another 50 polls" look identical.
    Owner: bridge/Carl. Tracked as #52 (closed).
11. **`recv` applies no gate** — `recv_once` (`recv.py:51-70`, function `recv_once`) fetches, prints and acks with no
    `Gate.decide` in the path, so revocation and blocking are enforced at deposit only and a blocked
    sender's queued mail still reaches stdout. That is a §9 claim violated, not a harness detail:
    expected observation is that blocked mail does not print; if it does, it is a defect against
    `recv` (with a written accepted-risk note if the owner accepts it), never a passing test.
    Owner: recv/Muse. Tracked as #51.
12. **Cross-harness parity, per scenario, as a table** — the table below. The point is not agreement;
    it is that every disagreement is written down and attributed, so it cannot evaporate. Kiko owns
    the OpenClaw-B column and drafts the table; Sunny owns hers.
13. **Hub down at send, as a distinct failure** — `knok send` exits 3 when the hub is unreachable and
    2 on refusal (`_try_deposit`, `cli.py:196-200`), and both are deposit signals, not delivery signals. Scenario: hub
    unreachable, `send` exits 3, then the hub returns. Expected: nothing was delivered, and the
    harness's staging layer re-offers with the *same* ids. `send` exiting 3 with no retry is a silent
    drop by the caller; the scenario states which side is responsible, or its pass is luck.
14. **Pinned-card reload** (added 20 Nov, after #54 shipped) — the same failure class as scenario 10
    one layer down: the registry behind the trust anchor was read once, so a peer provisioned later
    was invisible until a restart and its mail was dropped as unverifiable. Fixed in #58/97bb8e6
    (`reload_registry_if_changed()`, one stat per card per poll, the dict swapped in one assignment).
    Scenario: a peer is provisioned into the registry directory while both bridges run; expected
    observation is that its next message is delivered without a restart, and that deleting a card
    mid-run makes the next message from that name unverifiable — again with no restart. Clock, not
    restart, for the same reason as scenario 10. Owner: bridge/Carl.

## Parity table

Filled in as scenarios are run. An empty cell means *not run* — never "passed". Where two agents run
the same scenario the expected-observation text is identical; a divergence is annotated per harness.

| # | Expected, one line | Hermes | Hatch | OpenClaw-A (Sunny) | OpenClaw-B (Kiko) | Verdict |
|---|---|---|---|---|---|---|
| 1 | same `messageId`, once at the agent; replay not re-delivered | | | | | |
| 2 | nothing acked is lost; nothing lost is acked, incl. the recv ack-before-stage window | | | | | |
| 3 | policy change takes effect without a restart | | | | | |
| 4 | gate refusal reaches the sender as a signed notice; stranger sees the uniform 403 | | | | | |
| 5 | an unapproved agent never becomes a contact | | | | | |
| 6 | retry keeps `(contextId, seq)` | | | | | |
| 7 | refusal uniform, prompt, does not consume budget | | | | | |
| 8 | same conversation across three harnesses | | | | | |
| 9 | signed `refused` notice in `notices.jsonl`; a blocked peer gets none | | | | | |
| 10 | revocation observable by the sender on the next message, clock only | | | | | |
| 11 | blocked mail never reaches `recv` stdout | | | | | |
| 12 | this table | | | | | |
| 13 | exit 3 delivers nothing; retry re-offers the same ids | | | | | |
| 14 | a card added or removed mid-run is trusted or refused without a restart | | | | | |

## Roles

- **Carl** — hub, CLI, bridge; owns the send/thread half of #48.
- **Muse** — adapters and the muse-vm harness; owns the retry half of #48: a retry must carry the
  attempt's `contextId`, not mint a new one. No wire change is needed — `knok send` already takes
  `--context`/`--message-id` and its in-process retry re-deposits the same signed envelope — but a
  fresh invocation mints a new `contextId` and nothing persists an attempt's ids, so the fix is
  harness-side: record the attempt and reuse its ids on retry.
- **Sunny** — OpenClaw consumer inside a product workflow (travel), the least synthetic user we have.
- **Kiko** — third harness, adversarial reader; her job is to describe what the protocol looks like
  from the outside without knowing why it was built that way.

Everyone runs scenarios against everyone. Findings are filed as issues with the repro, not fixed
silently.

## Exit criteria

- Every scenario above has an observed result written down, including the ones that passed.
- No scenario is recorded as a pass on a requirement that states no observation. A requirement the
  code does not meet fails its scenario and becomes an issue; a checkmark is not a result.
- Zero open **silent-drop** classes: no path where a message is discarded and the sender is not told
  — except a `blocked` refusal, which is silent by design (SPEC §9, amended 20 Nov), so the criterion
  counts it as a deliberate class with the operator's record in `refused.jsonl`, not an open one.
- Every defect found has either a merged fix or an issue with an accepted-risk note.
- A written record exists of what was *not* tested, so the gap is visible rather than implied.

## What is not tested

Kept visible rather than implied, and updated as the phase runs. As of this amendment:

- **Sealed traffic end to end.** §6's gap-release and late-arrival notices, §8 sealing and `RESEND`
  are not exercised by any scenario above, and the hub's opaque-blob behaviour is where the ordering
  guarantees actually live. Either a scenario covers it before Sunday, or the review is assessing a
  spec whose most delicate section has no evidence behind it — and the review document says so.

## The security review — Sunday 22 November

§11 asks for a reviewer who wrote neither the spec nor the implementation. With four agents who have
all touched the repo, that reviewer cannot be any of us, and the honest options are:

1. **A fresh model instance with no authorship and no repo history** (proposed). Cheap to stand up,
   no conflicted interests, able to read the whole surface in one pass. It reviews the artefacts, not
   the people.
2. An external human, if one is available on the day. Strictly better on judgement, much slower.
3. One of us with the conflict declared in writing and a narrowed scope. Weakest option; if it is
   chosen, say so in the review document rather than in chat.

**Inputs:** `docs/SPEC.md` (v0.5.1), `docs/HUB.md`, `docs/decisions/0001-0004`, `main`, and every
testing-phase finding.

**Method:** for each normative claim in the spec, try to break the code's version of it; then
threat-model the deployed topology — hub on the tailnet, bridges as host processes, deploy keys with
no branch protection, agent state directories. Each finding is marked *violates a claim* or
*accepted risk*, with file:line or wire evidence and a severity.

**Output:** one findings document plus issues for anything real, delivered the same day. Cost is
bounded to one day of review, not an open-ended pass.

## Decisions for the team, with defaults

These were put to the owner and he returned them to the team. If nobody objects by Saturday, the
default stands.

1. **Who reviews (§11).** Default: a fresh model instance, no authorship, run Sunday. The team picks
   which model; the strongest available, since the review's value is judgement, not throughput.
   (Muse's view: a fresh instance of a different model family is worth more than a fresh instance of
   the same model that wrote the code — shared blind spots are the risk. If no other frontier model
   can run Sunday, a fresh Muse with no repo history is the fallback, with that limit declared in
   the review document.)
   Order: the review runs **before** the §11(b) abuse-runbook exercise — two gates, one after the
   other, both before launch, never in parallel — because a runbook exercised once and graded by the
   people who wrote the spray detection inherits their blind spots.
2. **Where it lives.** Default: nothing leaves the tailnet during testing. The domain and VPS
   decision waits until the review closes, so a launch decision is not made twice.
3. **Push presence.** Default: Phase 4. Polling is correct and the long-poll is not built (§7).
4. **Testing scope.** Default: the eight scenarios above plus the five added here (9, 10, 11, 13, 14) and
   the parity table (12) — not an open-ended soak. Adding a scenario is one line in this file and a
   message; removing one needs a reason recorded here. The "what is not tested" record names sealed
   traffic end to end.
