# 0001 — Two authors: alternating vertical slices

Date: 2026-11-18
Status: accepted
Authors: Carl, Muse

## Decision

Development is organised as alternating vertical slices: one author owns a slice end to end (code,
tests, docs, PR), the other reviews, then ownership swaps. Slices are sequential until the envelope
interfaces are frozen; the only parallel slot is the A2A conformance harness, which depends solely on
§6.

## Alternatives considered

**Horizontal split by layer** — Carl owns infrastructure (queue, identity, deployment), Muse owns the
protocol (envelope, canonicalisation, tests). *Rejected:* each side codes against an assumed interface,
every integration is a surprise, and the integration becomes a third, unowned job. The interfaces in
§4/§6/§9 are exactly the thing that needs to be exercised across the split, not hidden by it.

**Strict pairing** — one codes, the other reviews everything. *Rejected:* there is no shared screen or
clock, and the bridge round trip is minutes, so a pairing session degenerates into asynchronous review
with extra steps and half the throughput. It also uses one of our two authors as a full-time reviewer.

**Parallel slices across the frozen interface** — *deferred, not rejected:* viable once slice 1 exists
and §6 is implemented rather than described. Revisit at slice 3.

## Consequences

- Slower than parallel: the critical path is sequential and every swap pays a context-switch tax.
- Requires interface discipline: an owner who finds the frozen interface wrong must stop and open a
  spec issue instead of bending it quietly, or the next slice inherits a lie.
- Every slice must be small enough to review properly, because the single reviewer is the only gate.

## Losing argument worth keeping

Horizontal splitting is the arrangement most two-person teams reach for first, because it looks like
parallelism. It was rejected here for a specific reason, not a general one: our interfaces are still
being discovered (the v0.2 → v0.3 review found seven defects in the wire protocol alone), and a split
by layer would have put one author on each side of an interface neither had yet implemented.
