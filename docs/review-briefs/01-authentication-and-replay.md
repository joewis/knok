# Review brief 1 — Authentication and request replay protection

You are reviewing how Knok authenticates an HTTP request, and whether a request that was valid once
can be used twice. Report findings, not a summary of the code.

## Scope — read only these

- `src/knok/hub.py` — `authenticate`, `_claim_nonce`, `_note_seen`, `_parse_iso`, `_card_public_key`,
  and the handlers it guards: `_deposit`, `_fetch`, `_ack`, `_presence`, `_registry`, `_health`
- `src/knok/identity.py` — the signing and verification primitives
- `src/knok/hubclient.py` — how a client builds and signs a request
- `src/knok/registry.py` — what a key lookup resolves to
- `tests/hub/test_hub.py`, `tests/test_hubclient.py`

## Context — read before the code

- `docs/HUB.md` §Authentication, and the known-risks list at the end
- `docs/SPEC.md` §7
- `docs/decisions/0002-registry-and-key-records.md` (what a key lookup means, and as of when)

## Deliberately outside this brief

The envelope's own signature (brief 3), HPKE (brief 5), and the owner-approval UX (brief 4). Mention
them only where they change an authentication answer.

## Known-deliberate, do not report as an oversight

Deposit is authenticated by the envelope alone, with no request nonce — `docs/HUB.md`, known risk 4.
Review it **as a design**: state what it gives up and what a public hub would need. If you think it
is wrong for the current deployment, say so explicitly as a design objection.

## Questions

1. **The endpoint table.** Every HTTP endpoint × what authenticates it (request signature, envelope
   signature, nothing). Mark the rows that mutate state. Which of those mutate state without a nonce?
2. **What is signed.** Exactly which bytes does a request signature cover: method, raw target with
   query, body, headers? Show them in concatenation order. What happens if a proxy reorders query
   parameters or re-encodes them — does the server verify what it dispatches, or what it received?
3. **Replay.** Can a captured request be replayed: inside the skew window, after the nonce is pruned,
   after a hub restart, against a second hub process sharing the database? Name the input each time.
4. **Time.** What is the relationship between the accepted skew and the nonce retention window, and
   what breaks if the hub clock steps backward by more than the skew between two requests from the
   same agent? Can a client choose a timestamp that keeps a nonce alive longer than intended?
5. **Binding.** Is a nonce bound to its request, or only to the agent? Can agent A's nonce make agent
   B's request fail? Does the nonce table have a per-agent or global bound?
6. **Work before auth.** Trace one unauthenticated request: what is read, parsed, verified and
   written before `authenticate` returns? Is any of it unbounded in size or time? What does an
   attacker get for free by being unauthenticated?
7. **Refusal uniformity.** Compare the response for: unknown agent, bad signature, replayed nonce,
   stale timestamp, malformed header, and a valid request to a path that does not exist. Same bytes,
   same status, same shape? Any place one is distinguishable when it should not be?
8. **Headers.** Are the header values used in verification the same ones the signature covered?
   What does the server do with a duplicate header, and does that change under a reverse proxy that
   normalises differently?
9. **Key selection.** When the hub resolves a key, what instant does it use, and who chooses that
   instant? What does the sender's control of it allow — see issue #90 for the known consequence on
   backdating, and say whether this path widens it.

## Report

Start with the endpoint table. Then findings as `F1`, `F2`, … each with:

- `file:line`
- the failing input (a request, a sequence, a clock step)
- the consequence, and who can reach it
- whether the design intended it (cite the document) or the code departs from the spec

State which deployment you are assuming: the private tailnet hub described in `README.md`, or a
public hub. Severity is consequence × reachability on that deployment, not on a hypothetical one.
