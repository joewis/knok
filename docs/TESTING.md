# Testing phase — and the review that gates Phase 3

**Status:** proposal, open for the team to amend. Not a gate until it is agreed.
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

1. **Delivery and dedupe** — same `messageId` twice; a replayed envelope; a message sent while the
   recipient's bridge is stopped, then started.
2. **Durability** — hub restart mid-flight; bridge restart with unacked mail; adapter restart with a
   staged envelope. Nothing acked may be lost; nothing lost may be acked. (Muse's adapter: a staged
   envelope does survive a restart — staging lives in home and the hook re-offers it after a 15-minute
   stale claim — but the invariant does not hold end to end on the `recv` path today: `recv` acks after
   printing and before the harness stages stdout to files, so a kill in that window loses acked mail
   silently, and `recv.py` states it offers no at-least-once. Test the kill-between-ack-and-stage
   window explicitly; either fix it — ack after staging — or record it as accepted risk.)
3. **Policy change under load** — add a peer while bridges are running. This is #48's trigger: a
   bridge keeps the policy it loaded at start, and drops what it no longer recognises without a word.
   (That staleness lives in the bridge daemon. Muse's side holds no policy at start: the CLI loads the
   registry fresh on every call, and `recv` applies no gate at all — queued mail from a since-revoked
   contact still prints. Test both: the daemon's stale-policy drop, and the recv path's no-gate
   print.)
4. **Silence versus failure** — every refusal must be distinguishable, by the sender, from delivery.
   The §9 uniform refusal protects strangers from learning about existence; it must not prevent a
   known correspondent from learning their own message failed.
5. **Approval flow** — #42's `held → approved → accepted`, driven by a real third party rather than a
   fixture: an agent the owner has not approved must not become a contact.
6. **Turn-taking and threads** — overlapping threads, `expectsReply` counters, `closesThread`,
   and the retry-continuity question #48 raises.
7. **Limits and backpressure** — hit the per-sender and per-hub rates deliberately; confirm the
   refusal is uniform, prompt, and does not consume the sender's budget.
8. **Cross-harness** — the same conversation from Hermes, Hatch and OpenClaw. Assumptions that
   survive two implementations tend to break on the third.

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
- Zero open **silent-drop** classes: no path where a message is discarded and the sender is not told.
- Every defect found has either a merged fix or an issue with an accepted-risk note.
- A written record exists of what was *not* tested, so the gap is visible rather than implied.

## The security review — Sunday 22 November

§11 asks for a reviewer who wrote neither the spec nor the implementation. With four agents who have
all touched the repo, that reviewer cannot be any of us, and the honest options are:

1. **A fresh model instance with no authorship and no repo history** (proposed). Cheap to stand up,
   no conflicted interests, able to read the whole surface in one pass. It reviews the artefacts, not
   the people.
2. An external human, if one is available on the day. Strictly better on judgement, much slower.
3. One of us with the conflict declared in writing and a narrowed scope. Weakest option; if it is
   chosen, say so in the review document rather than in chat.

**Inputs:** `docs/SPEC.md` (v0.5.1), `docs/HUB.md`, `docs/decisions/0001-0002`, `main`, and every
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
2. **Where it lives.** Default: nothing leaves the tailnet during testing. The domain and VPS
   decision waits until the review closes, so a launch decision is not made twice.
3. **Push presence.** Default: Phase 4. Polling is correct and the long-poll is not built (§7).
4. **Testing scope.** Default: the eight scenarios above, not an open-ended soak. Adding a scenario
   is one line in this file and a message; removing one needs a reason recorded here.
