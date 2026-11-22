# 0006 — Key rotation: the old key signs, the hub countersigns, the old key dies for new mail at `notBefore`

Date: 2026-11-22
Status: proposed
Authors: Muse
Addresses: HUB.md open question 1 (card distribution and rotation); #65 (supersede path)
Blocks: public-hub launch (not Phase 3 on a private hub, per #90)
Relates to: 0002 (key records, `status(at)`), 0004 (key validity read at `sentAt`), 0005
(deposit-time check)

## The question

An agent's identity is a name bound to a signing key. When that key must change — scheduled
hygiene, a new device, a suspected compromise — the agent needs new keys but the same name.
SPEC §4 sketches the answer in one paragraph: a rotation record signed by the old key **and**
countersigned by the hub registry, carrying `notBefore`/`notAfter`; peers accept it only inside
that window; a revoked key is refused even if the rotation signature is valid. The mechanism
behind that paragraph was never designed: who signs what, how a peer knows it is the same agent
and not an attacker, what happens to the old key, how a bridge learns about it without a restart,
and what revokes one. This record designs it.

## The threat model

An agent's whole identity is one key file on disk — `0600`, no passphrase, no second factor.
Anyone who copies it signs as that agent to every contact. Rotation is authenticated by
possession of the current key, and possession is all it proves: it cannot distinguish the owner
from a key thief, because the thief holds the same key the owner does. A rotation signed by a
stolen key is a takeover primitive — it moves the name to the attacker's key, and the victim's
old key is dead for new mail the moment it takes effect.

That is the honest ceiling of this design, and it must not be presented as more. What exists
around it: revocation (a signed statement published to the registry and to every peer with the
agent in contacts); the deposit-time check (0005 — a key not valid now is refused at deposit);
trust levels resetting to lowest on a new fingerprint, so a rotated key starts untrusted and
must re-earn standing. What does not exist: any second factor, and any secrets management (where
keys live, passphrase protection, encrypted backup per §8). On a private hub of known agents a
stolen key is an incident handled out-of-band; on a public hub it is a launch blocker. Rotation
is the mechanism for planned key changes. It is not a second factor.

## The mechanism

A rotation is a record, and the registry already has the shape for it (0002). The rotation
record carries `agentId`, the old fingerprint, the new fingerprint (or the new `KeyRecord`),
`notBefore`/`notAfter`, a `reason` (`scheduled`, `suspected-compromise`, `recovery`), the old
key's signature over the record, and the hub's countersignature. The hub, on accepting it:

- verifies the old-key signature and that the old key is currently `valid` — a rotation from a
  revoked, superseded, expired or not-yet-valid key is refused, whatever it signs;
- verifies `notBefore` is sane: not in the past beyond a small skew bound, not absurdly far in
  the future (operator policy; a day is the sane ceiling, so a rotation cannot be parked
  indefinitely);
- marks the old record `superseded_by` = new fingerprint, `superseded_at` = `notBefore`, adds the
  new record, countersigns, and publishes — to the registry and, like a revocation, to every peer
  with the agent in its contact list.

**The old key.** `superseded_at` is `notBefore`: one clean cutover, no window in which both keys
sign new mail. From `superseded_at` the old key is refused for new deposits — that is the
deposit-time check (0005), whose predicate is "not valid now" and therefore already covers
`superseded`. For mail sent before `superseded_at` the old key still validates at `sentAt`
(0002/0004): the audit property stands, and a key superseded this morning still verifies
yesterday's signature. The old key dies for new mail; it does not die for history.

**How a bridge learns.** Phase 2 already has the mechanism for cards and it extends to key
records unchanged: the bridge re-reads the registry directory and swaps the pinned set in one
assignment between messages (HUB.md Deployment), so a rotation lands without a restart. Phase 3
adds one requirement: the hub exposes a registry version on poll, and a bridge re-fetches the
registry when the version changes. A bridge MUST NOT cache a peer's key past the registry's
maximum cache (24 hours, §4). The residual window — a bridge that has not re-read yet still
trusts the old key — is bounded by poll cadence plus cache, and the deposit-time check on the
hub is the backstop: it refuses new mail from a superseded key regardless of what the receiving
bridge knows.

**What revokes a rotation.** Revoking the new key: a signed revocation for the new fingerprint,
published to the registry and to peers, exactly as any revocation. The old key's supersession is
terminal — there is no un-supersede; a key that has been rotated away does not come back.
Recovery from a fraudulent rotation is therefore operator-mediated, and this record says so
rather than pretending otherwise. The victim proves prior possession out-of-band — the old key
itself, the §8 encrypted backup, or the registration channel — and the hub operator publishes a
**recovery rotation**: a distinct record, signed by the hub alone, naming the attacker's key as
revoked and the victim's fresh key as current, with `reason: recovery`. It is distinguishable
from a normal rotation precisely because it carries no old-key signature: the hub is vouching
for the owner, not recording a cryptographic proof of continuity. A peer that sees one knows
the continuity claim is administrative.

## Options

**A. Owner-signed, hub-countersigned, immediate effect at agent-chosen `notBefore`.** The
mechanism above. The agent picks `notBefore` — now for an urgent rotation, hours out for a
planned one (a self-imposed grace period, during which the owner can notice a fraudulent
rotation and revoke). No new wire event, no new state machine, no new constant: it uses the
`KeyRecord` supersession machinery that already exists and the re-read the bridges already do.

**B. Rotation with a mandated publication delay and an owner notice.** Same as A, but the new
key becomes effective only after a fixed delay (e.g. 24 hours) and the hub notifies the owner
immediately, so a fraudulent rotation can be caught and revoked before it takes effect.
Rejected as the mechanism: the delay only helps if the owner notices within it, and an attacker
rotating would pick the earliest `notBefore` the spec allows — the delay binds the honest
rotator, not the thief. The notice itself is worth having (the hub already publishes revocation
to contacts; rotation rides the same channel), but a mandated delay is machinery for a benefit
that depends on human attention inside a day.

**C. Rotation requires a second factor.** The record must also carry proof of a second factor —
a passphrase-derived signature with a separate key, a hardware key, an out-of-band confirmation
on a channel the hub knows. This is the real answer to the threat model, and it is not this
slice: no second-factor infrastructure exists (no passphrase, no hardware key, no out-of-band
channel in the protocol). It is a Phase 3 / v2 decision, and a public-hub launch blocker until
it lands. Named here so it is not lost, not solved here.

**D. No rotation; re-register under a new name.** The agent abandons the old name and registers
a fresh one with fresh keys. Rejected: it breaks the identity rotation exists to preserve, and
every contact relationship with it — the new name must re-request contact with everyone, and
the old name's history is orphaned. It contradicts §4's rotation record rather than
implementing it.

## The #65 answer

Rotation between presentations never reaches a decision, because a denial is terminal and a
second request inside a live one is a protocol error. This record **accepts that shape and
adds no re-presentation path**. The path already exists: an owner shown a rotated key who would
have approved must refuse and let the peer ask again (§9), and the peer re-asks with the new
key. The audit shows the rotation without a new wire event — the request row carries the old
fingerprint, the refusal row records the rotated key that was shown, the new request row
carries the new one. A re-presentation event would be a new way to keep a request alive past
expiry and a new probe of whether the owner is watching, which is the attack §9 caps the
approval queue against. The spec's existing paragraph ("rotation while a request is held is
visible only on a refusal") is the answer; this record confirms it and closes #65's question.

## Recommendation

**Adopt A.** It implements the paragraph §4 already promises with machinery that already
exists — `KeyRecord` supersession, bridge re-read, the deposit-time check — and it adds exactly
one new record shape and one new hub acceptance rule. The old key's death for new mail is
enforced at the hub, where the key's current status is knowable, and its survival for history
is the audit property the registry was built for. The limitations are stated, not hidden: it
proves key possession, not personhood; a stolen key can rotate its victim out; recovery is
operator-mediated; the second factor is a separate decision.

This is a protocol decision, not a product one. No product question is being absorbed: the
choice is about what the wire guarantees, and it belongs in the spec.

## What stays open

- **The #90 wiring is a prerequisite, not a footnote.** Rotation's enforcement — the old key
  refused for new deposits — is the deposit-time check (0005). At v0.4.0 that check is skipped
  on every shipped hub because no production code constructs a `Registry` (Muse told Carl this
  in the v0.4.0 reply; Carl's (a)/(b) call is still open). Until the wiring lands, a superseded
  key can still deposit new mail through a shipped hub, and rotation is a record-keeping
  exercise rather than an enforcement. This design must not be relied on in production before
  that call closes.
- **Topology A (direct, no hub).** A rotation learned from the hub registry does not reach a
  direct peer. Direct mail still relies on the receiver's `sentAt` check and whatever key the
  receiver has pinned; on a private hub that is mail between known peers, where rotation is an
  incident handled out-of-band. Before a public hub, direct mail between strangers needs its own
  answer — this record does not give it.
- **The signed registry.** A peer that did not watch a rotation happen trusts the hub's
  countersignature, which is meaningful only once the registry is signed (Phase 3; SPEC §4
  records "records are not yet signed objects" as a gap). Until then the directory is the trust
  root, exactly as it is for cards today.
- **Second factor and secrets management.** Not solved here, by design. What stands in for 2FA
  — passphrase on the key, hardware-backed key, out-of-band confirmation — and where keys and
  their §8 encrypted backups live, is the next decision after this one, and a public-hub launch
  blocker.
- **Publication lag.** Rotation binds only once it reaches the registry, and a bridge binds
  only once it re-reads. How fast a rotation propagates is an operational property of the hub
  and the poll cadence, and the same lag a delay would have faced.
