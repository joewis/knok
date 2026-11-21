# 0005 — No freshness window on `sentAt`; the hub refuses deposits from a key revoked as of deposit time

Date: 2026-11-21
Status: proposed — for review, not accepted
Authors: Muse
Addresses: #90
Blocks: public-hub launch (not Phase 3 on a private hub, per #90)
Relates to: 0002 (`status(fingerprint, at)`), 0004 (key validity read at the envelope's `sentAt`)

## The hole

`envelope.validate` caps an envelope's lifetime (`expiresAt` no more than 30 days after `sentAt`)
and refuses an expired envelope, but places no lower bound on `sentAt` (`src/knok/envelope.py`).
The 30-day cap bounds how far into the future an envelope may live, not how old its claimed send
time may be. The hub and the receiving bridge both verify the sender's key as of the envelope's own
`sentAt` (`hub.py: deposit`, `bridge.py`, `transport.py`) and neither compares `sentAt` to a real
clock; §7's five-minute freshness bound is on the request, not the envelope.

So a holder of a revoked key can mint a new message, backdate `sentAt` past the revocation, set a
future `expiresAt`, and be accepted — the key was valid at the forged instant. Exact replays are
deduped, so this is a revocation problem, not a replay problem. SPEC §4 already says so
("`sentAt` is asserted by the sender, and that bounds what revocation can do") and points at a
receiver freshness window nobody implements. This record decides what replaces that pointer.

## The trade

A window must satisfy two constraints that pull in opposite directions:

- **Shorter than the revocation-to-notice interval**, or it does not bound revocation. Revocation
  is published to the hub registry and to every peer with the agent in its contact list, and the hub
  serves it with a 24-hour cache (§4). A window longer than ~24 hours lets a revoked key send after
  every peer could have known.
- **Longer than the longest legitimate time a message spends between send and receipt**, or it
  refuses honest mail. That time is hours here, not minutes: a cell reboots without warning and
  egress needs a human per boot, so messages sit for hours — scenario 15 assumes a bridge stopped
  for six. The default TTL is 72 hours and the maximum 30 days; the protocol expects mail to sit.

A one-hour window breaks store-and-forward; a 72-hour window gives a revoked key most of three
days and exceeds the 24-hour cache, so it bounds nothing. No number satisfies both in the worst
case, and a bound that is wrong half the time is worse than none, because it looks like protection.
Worse, the failure mode of a too-short window is silent loss: a freshness refusal at admission is a
verification failure, not a gate refusal, so it carries no notice; the envelope is acked as handled,
`send` exited 0 hours earlier, and the sender never learns the message died — the defect §6's
"never dropped silently" rule was written against.

## Options

**A. Short window — 1 hour back, 5 minutes forward skew.** The only window that actually bounds
revocation: a revoked key can send for at most an hour after revocation. Cost: it silently kills
honest mail whenever a bridge is down longer than an hour, which here is routine. Rejected: it
trades everyday mail loss for a bound against an attack that has never happened, on a private hub
where a revoked key is an incident, not an attack surface.

**B. Long window — 72 hours, matching the default TTL.** Preserves store-and-forward as it works
today. Cost: it does not bound revocation at all (72h > 24h cache), so it is option C with a number
on it. It also refuses honest mail that sat longer than 72 hours, the case where the message most
deserves delivery. Rejected: a tripwire against absurd backdating is not worth a new refusal
condition.

**C. No window; the spec says so plainly (issue option 2).** Revocation cannot stop a compromised
key from sending; the receiving side's only defence is out-of-band. Costs nothing and is honest.
The hole stays open until the public hub, where it becomes a launch blocker. Acceptable as a
fallback, but it leaves the hole with nothing in its place.

**D. No window on the receiver; the hub refuses a deposit from a key revoked as of deposit time.**
The deposit is the one moment the network sees the mail while the key's current status is knowable.
The hub already looks the key up as of `sentAt` (the audit property: a key revoked this morning
must not refuse a message signed yesterday); D adds one check — is this key revoked as of *now*?
If yes, refuse the deposit with the uniform 403. A revoked key cannot inject new mail through the
hub, whatever `sentAt` it claims: no clock comparison on the receiver, no window, no
store-and-forward breakage. Cost: one fresh registry read at deposit — the hub reads its own store,
not the 24-hour peer cache, so the check is fresh by construction. The residual hole is only the
interval between compromise and publication of the revocation, which no window can fix either.

## The retry interaction

A retry mints a fresh envelope — same thread, same `seq`, a `retryOf` marker naming the original,
and a fresh `sentAt`/`expiresAt` (`src/knok/retry.py`). Under a window, a retry passes because its
`sentAt` is the mint time; the window must be applied to the minted `sentAt`, never to the
original's, or retries would be punished for the original message's age. Under D no special handling
is needed: a retry from a live key deposits fine; a retry from a revoked key is refused at deposit,
which is correct — and loud, at deposit, rather than silent at delivery.

## Recommendation

**Adopt D.** It is the only option that closes the hole (a revoked key cannot mint new mail)
without a clock comparison anywhere, so it cannot refuse honest mail for being old. The spec change
is small: §4 gains the deposit-time rule and the sentence pointing at a receiver window is replaced
with it; §6/§7 gain the deposit refusal condition; HUB.md states the deposit-time read is fresh.
The receiver keeps the `sentAt` check as it is — the audit property stands, and mail deposited
before revocation and delivered after is still accepted: it was legitimate when sent.

This is a protocol decision, not a product one. No product question is being absorbed: the choice is
about what the wire guarantees, and it belongs in the spec.

## What stays open

- **Topology A (direct, no hub).** D only helps mail that passes through the hub. Direct mail still
  relies on the receiver's `sentAt` check; on a private hub that is mail between known peers, where
  revocation is an incident handled out-of-band. Before a public hub, direct mail between strangers
  needs its own answer — this record does not give it.
- **Publication lag.** D binds revocation only once it reaches the hub's registry. How fast a
  compromise becomes a published revocation is an operational property of the hub, and the same lag
  a window would have faced.
