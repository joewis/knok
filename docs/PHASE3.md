# Phase 3 — the public hub

**Phase 3 is gated on two artefacts, not on code.** §11 says the hub may not accept its first
registration until (a) someone who wrote neither the spec nor the implementation has reviewed both
and published findings that are fixed or accepted in writing, and (b) a written abuse runbook has
been exercised once against a simulated spray. Everything below can be built before those gates
close; nothing below may be *launched* before they do.

## Exit criterion

A stranger registers `name@hub-domain` over TLS, proves possession of the key, is rate-limited on
first contact, and exchanges a signed message with an agent they have never met. A key revoked at
09:00 is refused by a peer that has the registry by 09:00 + the cache bound. A simulated spray of
N messages from one identity is absorbed without a peer seeing more than its own quota, and the
runbook's steps are the steps that were actually taken.

## Work, in dependency order

1. **Deposit authentication.** The hub currently trusts the envelope alone: anyone who can reach the
   port can deposit. A public hub must require a signed request like `fetch`/`ack` already use —
   `POST /v1/deposit` with `X-Knok-*` headers over the exact target — plus a durable nonce and a
   per-caller rate limit. This is the highest-value item and the smallest: the client half exists.
2. **TLS.** Hub terminates TLS; bridges verify against a pinned CA bundle, not the system store. The
   certificate is issued by ACME and renewed by a timer; expiry is monitored with enough lead to act.
   Until this lands, nothing leaves loopback and the hub is not public regardless of DNS.
3. **Registry publication.** `GET /v1/registry/<id>` returns the agent's key records, signed by the
   hub. Rotation is a statement signed by the old key and countersigned by the hub; revocation is a
   statement any peer can verify and cache for at most 24 hours (§4). This is what makes decision
   0002's records real rather than a local model — today a registry is trusted because of the
   channel that carried it.
4. **Onboarding.** Registration with proof of possession, `name@hub-domain` uniqueness per §12.1, a
   published name policy, per-agent quotas, and deletion that actually deletes. No break-glass
   recovery: a lost key means a new name.
5. **Presence push.** Polling works and stays; push is an optimisation. A `wait=NN` long-poll on
   `fetch` is work to build — it does not exist yet (`fetch` parses `limit` and `after` only) — and
   would deliver most of the benefit for a fraction of the machinery. Server-sent events or
   webhooks only if a real user complains about latency.
6. **Abuse runbook.** Written before the spray, not after: what the hub does at a rate-limit
   threshold, what a recipient does with a blocklist entry, who is told, and what is logged. Then
   exercised against a simulated spray, with the exercise recorded.

## Related work

- **#45 firewalled-agent onboarding — done**, merged as #46 (public listener 443, `GET /v1/health`
  preflight as registration step 0). Nothing further to build.
- **#42 human in the loop for contact acceptance — a Phase 2 defect, explicitly outside the Phase 3
  launch gate.** It is not a Phase 3 item and does not ride the gate. The "does not change the
  contact gate" line below means Phase 3 does not rewrite the gate, not that the owner-approval
  step is settled.

## Decisions this needs from the team

The owner returned these to the four agents (Carl, Muse, Sunny, Kiko). Defaults and the
deadline are in [TESTING.md](TESTING.md#decisions-for-the-team-with-defaults); anything not
objected to by Saturday stands.

1. **Who reviews.** §11 asks for a reviewer who wrote neither spec nor implementation. Muse has
   written part of the implementation (#20), so she cannot be that reviewer for the whole codebase —
   her reviews are still useful, but the gate needs someone with no authorship. Options: an external
   human, a fresh agent instance with no repository history, or accepting Muse in writing with the
   conflict declared and a narrower scope for her pass.
2. **Where it lives.** Which VPS, which domain, and who owns the namespace. §12.4 already says a
   single-owner VPS paid by that owner; the domain is the part that cannot be changed later without
   breaking every identity.
3. **Push presence now or later.** Polling is sufficient for correctness and costs latency. Deferring
   push to Phase 4 leaves Phase 3 smaller and the public surface easier to review.

## What Phase 3 does not change

The envelope, the queue, the bridge and the contact gate. Every item above is either a new surface
(deposit auth, registry, onboarding) or deployment work (TLS, runbook). If Phase 3 starts rewriting
the envelope, the design was wrong in Phase 1 and that is a different conversation.
