# 0004 — A "pinned" card is a signed body, verified for name and deadline at adoption

Date: 2026-11-20
Status: accepted
Authors: Carl
Addresses: #62 (a pinned card is never re-verified), #63, #58

## Decision

A registry pin is the card's **signed body**, not the file it came from. Adoption — `load_cards`,
and the reload that #58 runs when the directory changes — checks three things before a key becomes
trustable:

1. **The document verifies** under the key it carries (`card_body` → `verify_card`).
2. **The body names an agent**, `name@hub`, and the key is pinned under *that* id. The file name is
   not evidence and `bridge.agent` is not a field the spec defines; both were, and a card filed as
   `mallory@…` could hold a body for `carl@…`.
3. **A stated `validUntil` parses and has not passed.** A deadline that cannot be read refuses the
   card; `None` is reserved for "no deadline stated".

After adoption, the only question asked per message is the deadline, re-read from the signed body at
the envelope's `sentAt` (decision 0002), which is what #63 landed. Nothing else about the pinned body
can change inside a process, because nothing writes it: a reload replaces the dict wholesale with
freshly verified bodies, and it refuses a directory whose reload would remove everyone.

## Alternatives considered

**Re-verify the whole JWS per message (keep the document in the registry entry).** *Rejected.* The
pinned body is immutable for the life of the process; re-checking a signature over bytes that have not
changed cannot change the verdict, so the cost is one Ed25519 verification per inbound message and the
delta is zero. The failure mode it would catch — a body mutated after load — needs code execution
inside the bridge process, which already holds the agent's private key. Keeping the document becomes
necessary when a *Registry* installs entries at runtime (0002): then the install path is where a
document must be verified, and that is a new slice, not a per-message tax on the current one.

**Pin under the file name, as before.** *Rejected.* A name that no signature covers is authority the
operator did not intend to grant: whoever can drop a file in the directory could file an existing
card under a name its key never signed for, and every envelope claiming that name would verify against
a key its owner never granted it. The signed body is the only statement of "who this key is for".

**Treat an unreadable `validUntil` as no deadline (the previous reading).** *Rejected.* It made the
field decoration exactly where it was meant to bind: a card could state an expiry, be written with a
typo in it, and be trusted forever. Refusing is the same rule as everywhere else in §9 — fail closed.

## Consequences

- A card whose file name disagrees with its body still pins (the body wins) but logs a warning: it is
  an operator mistake, not a forgery.
- A card that names no agent is dropped. Every provisioned card names `name@hub`, so nothing in a
  normal deployment changes; a hand-written card must now say who it is about.
- An unreadable `validUntil` refuses the card at adoption *and* per message. This inverts one test
  from #63, deliberately, and the test now states the inverted rule.
- `bridge.agent` no longer grants a name. Nothing provisioned ever set it, and SPEC §5 does not
  define it.

## Left out

- **Revocation.** It needs a `Registry` (0002) whose `status(fingerprint, at)` answers for an instant,
  wired into the bridge in place of the legacy dict. That changes what "the registry in force" means —
  the reload currently re-reads a directory; a Registry is a served log — so it is its own slice.
  Until then revocation is the operator removing the card file, which #58's reload notices per poll.
- **Per-message document verification**, for the reason above: no delta until entries can be installed
  at runtime.
- **`validFor`.** SPEC §5 mentions a cache bound of at most 24 hours; nothing schedules a re-fetch.
  It is a serving policy for Phase 3 (a peer fetching cards from a hub), not a bridge check.
