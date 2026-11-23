# Changelog

## v0.4.1 — 2026-11-23 — the follow-up and the frame


**A follow-up in a thread is no longer silent**

- `knok send` takes the next `seq` for its thread from the sent ledger instead of defaulting to 0
  (#142). A thread is ordered by `seq` per sender, so the second message used to arrive at a
  position its predecessor had spent; the receiving queue answered `duplicate` — the silent answer
  a retry gets — and the message was gone with a 202 at the sender and an ack at the hub.
- A different message at a spent `seq` is now a `conflict`, not a duplicate (#142). It is recorded
  in `refused.jsonl` and reported to the sender as a refusal notice with the rule
  `sequence collision`; a genuine retry (`metadata.retryOf`, same `seq`) is still a silent
  duplicate, which is the only case silence was ever meant for. The bridge names a conflict in
  `undelivered` on its ack, so the hub mints no `delivered` frame for mail it did not hand over.
- **Known gap, stated rather than implied:** if an envelope reaches the queue without a sender
  string, the conflict is recorded and the sender is *not* notified — there is nobody to address.
  A verified envelope always names a sender, so the path is unreachable from the wire; it is
  recorded in `refused.jsonl` so the operator still sees it, and it is the one conflict that is
  silent by construction rather than by accident.

**A `delivered` frame is a frame**

- A reader recognised a hub transport frame by the absence of a `message` key, which is also how a
  sealed form-2 envelope looks. `expired` and `dead` were named explicitly and `delivered` was not,
  so it fell into the branch that leaves sealed mail at the hub: never printed, never acked, and
  re-offered on every `recv` (#144). A recv-only agent accumulated one per message it sent.
- The frame kinds are one constant, `HUB_FRAME_KINDS`, used by both branches: a frame is
  recognised by its `kind`, never by what it lacks. A sealed envelope keeps the #70 treatment —
  left at the hub, unacked, because acking would destroy mail `recv` cannot read.

**The harness adapters are in the repository**

- `plugins/` carries the OpenClaw daemon and the Hermes wake/inject pair, and
  `plugins/README.md` states the four questions every harness has to answer — when to wake, which
  session, who replies, what counts as delivered — against the five failures both implementations
  were built around (#146). Until now that half lived outside the tree, unreadable to anyone else
  running knok.
- Two defects in that first publication, both fixed (#147): the OpenClaw adapter passed
  `--reply-to`, a flag the CLI dropped in #37, so the published file would have failed on its first
  send while the older deployed copy kept working; and the reply id was minted per send, so a crash
  between the hub accepting a reply and the staged file moving re-sent it under a new id. The reply
  id is now derived (`r-<message id>`) and written into the sidecar before the send, so a replay
  deposits the same message and the queue dedupes it.

## v0.4.0 — 2026-11-22 — the review sweep

Twenty-six issues opened by nine area-by-area reviews and closed against code, then the three the
sweep did not cover (#83, #90, #93). Every fix carries a test that fails on its parent; where the
red was checked, it was checked by disabling the change rather than reverting the file, because a
missing import is not evidence of a missing behaviour.

**The hub can no longer be talked into a false success**

- A deposit from a key that is not valid *now* is refused (#90, decision 0005). Verifying at the
  envelope's own `sentAt` is the audit property and stays; on its own it let the holder of a revoked
  key mint new mail with a backdated timestamp. The deposit is the one moment the key's status is
  knowable, so it is asked. The refusal carries a distinct body — it describes the depositor's own
  key, never a recipient's existence.
- An ack queues a hub-signed `delivered` frame into the **sender's** mailbox (#93). Silence no
  longer means three different things. A bridge that takes custody and does not hand a message to
  the application names those ids in `undelivered` on its ack, and no frame is minted: telling a
  sender both "delivered" and "refused" is worse than telling it nothing.
- An acked id stays spent until its envelope expires (#99), so a replay of a still-valid envelope
  is not stored and handed over a second time.
- The hub bounds itself: 64 concurrent handlers with a 60-second idle timeout (#103), parser
  failures answer the shared 403 rather than the stdlib's HTML 500-class errors (#105), and one
  ack carries at most 100 ids (#106).
- One request cannot cost an unbounded amount: duplicated authentication headers and ambiguous
  body framing are refused instead of resolved by picking (#102, #104), and nonces are capped with
  a forward-only per-agent request floor (#100, #101).
- Envelope identity is tightened: `turn` is validated, lifetime is capped at 30 days from `sentAt`,
  and the identity key file is created 0600 through a symlink-refusing path (#107–#110).

**A failure is never recorded as a success**

- JSONL appends are crash-atomic and a failed dead-frame write refuses the ack (#112, #114).
- Drop records keep metadata only, never the rejected envelope (#122).
- A refusal notice must prove it describes a message this agent sent to that peer, and name a rule
  the gate defines (#120).
- A second message reusing an in-flight `seq` is a duplicate rather than a row that can never be
  delivered (#111).
- A retry mints a new envelope — same thread, same `seq`, `retryOf`, fresh timestamps, new
  signature — instead of replaying bytes (#117, #118).

**The spec says what the code does**

- §6 pins the sealed plaintext (JCS-encoded A2A `Message`) and pins HPKE `aad`/`info` empty by
  decision, enforced at the API boundary (#83).
- §9 restates the rate limits to what the gate enforces, marks the hub-side ceilings as **not
  implemented**, and drops the `probation` flag from the parser so nobody can configure a limit
  nothing reads (#119).

**Review material**

- Nine review briefs, one per area, with line citations resolved against `828c9791` (#91, #92).
- The citation count is reproducible and recorded with its method: 1,389 spans across the nine
  files, 1,300 of them in 02–09 (#98).
- Test fixtures date themselves from the clock rather than from a literal day (#95).

**Known gaps, stated rather than implied**

- Hub-side rate limits (100/hour per sender, 10,000/hour per hub, the low-engagement throttle) are
  specified and unimplemented.
- Topology A, direct peer-to-peer mail with no hub, gets no benefit from the deposit-time key
  check; it still relies on the receiver's `sentAt` check alone.
- A legacy `{fingerprint: public_key}` registry cannot answer "is this key valid now", so the
  deposit-time check is skipped there — decision 0002's "valid forever".
- The `delivered` frame moves a trust boundary: the hub signs it, but the receiving bridge decides
  what counts as delivered. A bridge that acks everything as delivered tells its senders a lie the
  hub cannot detect.
- Rotation is still an open question in `HUB.md`, not a designed mechanism.

## v0.3.0 — 2026-11-20 — the hardening sweep

Two days of defects found by review and by running the thing, each closed against code with a
reproducing test. One theme runs through almost all of them: **a failure recorded as a success**, or
a success recorded before it happened.

**Delivery and durability**

- The gate's answer commits with the message that moved it (#69). `decide` is read-only; the queue
  applies the transition inside its own transaction, and a duplicate is recognised before the gate,
  so a retry after a lost ack is no longer refused as unsolicited.
- Every fetched item leaves a fsynced `delivery.jsonl` row before the hub may forget it (#79). The
  bug it closes: a sender that reuses `seq` 0 in an existing context made `put` answer `duplicate`,
  which `_handle` flattened to `queued`, and the hub acked — 17 messages lost with a counter that
  said they were fine.
- The adapter retry policy (#68): a failed send leaves a notice, `knok retry` decides which are
  worth repeating, and repeats them by replaying the stored envelope verbatim through
  `send --retry-of` — same id, same context. The budget is enforced by a durable reservation: a
  retry that cannot be counted is not performed.
- `knok notices` lets a sender read what its bridge recorded (#48), and the CLI's exit codes now say
  what happened rather than 0 for every outcome.

**Identity and approval**

- A request is held until the owner approves it (#42): approval is a local precondition, never a
  wire state, with a five-a-day cap so the owner's prompt cannot be the spam channel.
- A decision records the key the owner was shown, and decisions are append-only (#65): a rotation
  between presentation and decision is two rows with one superseded, not one row quietly rewritten.
  §9 says what that audit can and cannot show.
- A card is pinned under the name its signed body claims, not its file name (#62): a misfiled card
  no longer grants a name, and a `validUntil` is enforced at load and per message.
- A revoked or expired card is judged as of the envelope's own `sentAt` (#63), so a message signed
  yesterday is not refused by a key that lapsed this morning.
- Pinned cards follow the registry directory (#54), a changed policy is adopted without a restart
  (#52), and a newly registered agent's card is learned from the hub (#57).

**Transport and CLI**

- `recv` applies the gate before printing and before acking (#51): a refusal is acked so a blocked
  sender's mail cannot starve the page, notices are exempted so a recv-only agent still learns its
  own message died, and a sealed envelope is left unacked rather than deleted.
- `recv` acks a hub `expired` frame by its top-level id, so it stops re-printing on every fetch
  (#40). `--reply-to` was removed because it injected a field the validator rejects (#37).
- A gate refusal reaches the sender as a notice (#50), and delivery is closed by default.

**Sealed messages**

- Decision 0003 settles where a sealed body is decrypted: **the receiving bridge, at admission,
  before the gate**. The queue only ever sees plaintext, and the agent adapter never holds a key.
- `knok.hpke` (RFC 9180 base mode) plus `envelope.seal`/`unseal` land with the RFC's own A.2 vectors
  as tests, in both directions (#70). Sealed mail cannot travel yet: nothing mints one, and the hub
  refuses form 2 at deposit. #83 names what §6 still owes.

**Documentation and process**

- `docs/REVIEW.md` — the reviewer's guide: what to attack, and what is deliberately missing.
- `docs/TESTING.md` — the testing phase (19-21 Nov) and the Sunday security review's inputs.
- `docs/decisions/0004` — what "pinned" means; 0003 is the sealed boundary, renumbered out of a
  collision with it.
- The working agreement gains a rule that a merge is not a handoff unless it names what follows and
  who owns it, and that a review states the command it ran and the count it got.

## v0.2.1 — 2026-11-18 — the issue sweep

Seven open issues, closed against code rather than discussion. Every one of them was a place where
the system answered a simpler question than the one being asked.

- **Late arrivals are delivered, not dropped (#19).** A gap release used to destroy a message that
  arrived afterwards: the seq had been skipped, so `put` called it a duplicate and returned. The
  release now records the seqs it skipped, so an arrival for one is *late* — stored, delivered out
  of order, preceded by a `late` notice — while a re-send of a delivered seq is still a duplicate.
- **Dead letters tell the sender (#19).** The §6 `dead` frame is emitted once, through a notices
  table with a `pending -> taken -> delivered` lifecycle. The bridge confirms only after the frame
  is fsynced, so a crash or a failed write re-offers it instead of losing it; gap notices go through
  the same path and commit inside the release transaction.
- **The seen table is bounded (#13).** Pruned at the 30-day expiry bound, keeping rows whose message
  is still live. Delivered notices and `skipped` rows go with it — the same growth class, one table
  over.
- **Form 2 (sealed) works (#20).** `messageId` stays in clear so dedupe and ack still work; the
  signature covers the whole envelope, so swapping `messageId` or `sealed.hpke.ciphertext` fails
  verification. A 2MB ciphertext is refused on size before canonicalisation.
- **Refusal costs what acceptance costs (#24).** An unknown sender path performs the same two
  Ed25519 verifications a known sender does, against a throwaway key. §9 now also says what the
  requirement cannot promise: the string can be identical, the clock cannot.
- **The health endpoint is liveness only (#25).** `{"status":"ok"}`, before and after mail.
- **Keys are records with a history (#15, #23).** `KeyRecord` (agentId, keyType, publicKey,
  fingerprint, validity window, revocation, supersession) replaces the dict of bytes as the model;
  `Registry.status(fingerprint, at)` answers valid, not-yet-valid, expired, revoked, superseded or
  unknown. Both live paths — `Bridge.deliver` and `Hub.deposit` — ask at the envelope's own
  `sentAt`, so a key revoked this morning still validates yesterday's signature. The X25519 key is a
  record of its own named by `bridge.encryptionKeyId`, so it rotates without reissuing the card.

Known gaps, unchanged in kind but now written where they bite: records are not signed objects until
the hub publishes a registry; `sentAt` is the sender's own claim, so revocation cannot bind a holder
that backdates it; no registry is distributed over the wire; and no TLS off loopback. 225 tests, and
the Phase 2 demo still passes from the merged tree.

## v0.2.0 — 2026-11-18 — Phase 2 complete

A hub, three agents, and the exit criterion from §11 demonstrated rather than described.

- **The hub is a post office** (`docs/HUB.md`, `knok.hub`): stores signed envelopes for absent
  agents, never reads a `Message`, never holds an agent key, and has its own identity so `expired`
  frames cannot be forged into a mailbox.
- **The bridge** (`knok.bridge`) polls, verifies the sender, decides at the gate, fsyncs to the
  queue, and only then acks the hub. Acking first would quietly turn at-least-once into at-most-once.
- **Unverifiable mail is bounded, not starved**: five attempts, then acked away with a record in
  `dropped.jsonl` — and never acked if that record cannot be written.
- **Provisioning** (`knok.provision`) writes keys, cards, policies and the registry, idempotently.
  On a private hub the registry is the operator's consent, so peers are pre-approved; a public hub
  must use `--no-preapprove` and rely on §7's handshake.
- **Deployment**: one image, hub or bridge by role, one volume per agent, hub port on loopback.
- **Proof**: `deploy/demo.sh` asserts every step, including a container that fetches and dies before
  acking — the hub must still hold the message afterwards, and delivery must still be exactly once.

Known gaps, stated rather than implied: no TLS off loopback, no card rotation or revocation, no push
presence, and deposit is authenticated by the envelope alone (a public hub must sign deposits and
rate-limit them per caller).

## v0.5 — 2026-11-18

Revision of v0.4 after Muse's review of PR #17. Three of v0.4's claims were wrong in ways the code
would have inherited.

- **Sealed ordering was claimed but not delivered.** `messageId` in clear restores dedupe, not
  ordering: `contextId` is sealed, so `seq` cannot be attributed to a stream before decryption. The
  spec now says ordering happens at the receiving bridge after decryption, the hub stores opaque
  blobs and never orders, and `RESEND` runs bridge to bridge.
- **`messageId` was described as revealing nothing.** It is stable and therefore linkable — a hub can
  tie a message to its retransmissions. Now stated, with a MUST: ≥128 bits from a CSPRNG, unique per
  sender, because the queue's `seen` table is keyed on the id alone.
- **The signature-coverage sentence was ambiguous.** Now explicit: the signature covers the whole
  envelope including `messageId` and `seq`; covering only `sealed` would let a hub swap the id and
  make the receiver drop a live message as a duplicate.
- **Dead letters gained the trigger they were missing.** A `dead` transport frame tells the sender,
  and the owner may re-offer with a new `messageId` plus `retryOf`, taking the next `seq` rather than
  re-opening a released gap. Retention is 30 days.
- **The context-TTL argument was false for non-default message TTLs.** No fixed context TTL can
  guarantee the missing message has expired, because the clocks start at different events. The gap
  notice now says "missing as of this notice", and a late arrival is delivered with a second notice
  instead of being silently dropped.

## v0.4 — 2026-11-18

Three decisions that slice 2 forced into the open, each surfaced by code that could not implement
the spec as written.

- **Form 2 carries `messageId` in clear.** Slice 2 refuses sealed envelopes because the id was
  sealed with the body, so nothing could dedupe or order them. A random identifier reveals nothing;
  sealing it made every delivery guarantee in §6 conditional on the message not being sealed.
  (issue #12)
- **A dead letter is inspectable, never re-offered.** Re-offering restarts the five-attempt ladder
  and its `seq` re-blocks the whole stream under per-context FIFO, so one poison message would block
  every message behind it forever.
- **Context TTL is 72 hours, equal to the message TTL.** A gap may only be closed once the missing
  message can no longer arrive: shorter and the gap notice is a lie, longer and held messages expire
  before they are ever released.

## Slice 2 — durable queue (issue #7, unreleased)

`knok.queue.Queue`: SQLite (WAL, `synchronous=FULL`), one connection under
one lock, advisory `flock` so a single process owns the queue. `put` is
durable on return; dedupe on `messageId` survives restart via a `seen`
table; per-(contextId, sender→recipient) `seq` ordering with gap hold,
`resend` reporting and TTL release with a gap notice; dead-letter after
five attempts with backoff 1m/5m/30m/2h/12h; `expire(now)` emits the §6
unsigned `{"kind": "expired", ...}` frame. Restart replays unacked
messages, never re-delivers acked ones. Sealed (form 2) envelopes are
refused: their `messageId` is inside the sealed body, so the queue cannot
dedupe or order them yet. 17 new tests, including subprocess kill/restart
tests that `os._exit(1)` before ack.

## v0.3 — 2026-11-18

Second review by Muse (job `a3215433`), this time of Carl's *application* of the first review. Its
verdict: the ack redefinition, sealed-by-default and one-bridge-per-agent were applied correctly, but
three v0.1 findings were restated rather than applied, and two rewrites contradicted each other. §6
was declared unshippable as written and is the bulk of this release.

**§6 — rewritten, not patched** (all seven findings):

- **Canonicalisation is now JCS (RFC 8785)** — signature over canonical JSON minus the `signature`
  field, integers only, and a verifier whose re-serialisation differs MUST reject. v0.2 said
  "canonical bytes" and defined nothing, which guarantees that two implementations sign different
  bytes.
- **The sealed form now exists on the wire.** §8 made sealed the public default while §6 showed only
  a plaintext `message`: there was no secure mode to implement. Added the `sealed` field with HPKE
  (RFC 9180), DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305, a recipient key
  fingerprint, and a rule that a sealed-required endpoint refuses plaintext rather than downgrading.
- **Examples use hub-domain ids.** The one worked example still said `carl@elitedesk`, the exact form
  §4 forbids — teaching the forbidden form in its own illustration.
- **`seq` now has semantics or it would have been cut**: start 0, per sender→recipient pair, gap
  handling by holding later messages and issuing `RESEND`, and a gap notice if the missing message
  never arrives. A counter the receiver ignores is worse than no counter.
- **The `taskId: null` + `expectsReply: true` rule is deleted.** It re-collapsed speech act into
  lifecycle, forcing a Task for every one-line question.
- **Ack is a signed transport frame**, not a string: `{kind, messageId, seq, contextId, ackedAt,
  from, signature}`, ignored if unverifiable. An unsigned ack was a forgery primitive for any hub on
  the path — and the sender deletes its copy on ack.
- **The expiry notice is an unsigned hub frame**, not a `Message`: the recipient never saw the
  message and cannot sign it, and under sealing the hub cannot know whether a reply was expected.

**§9 — the detectors and limits now work under §6 and §8:**

- The spray signature ignored acks *and* replies; after §6 an ack is issued by every live bridge
  automatically, so "no reply and no ack" could only describe dead recipients. It now counts replies
  and Task transitions only, states that acks must not count, and says who is flagged, in what form,
  and for how long.
- Content limits moved to the two endpoints that hold plaintext: the sending bridge rejects before
  signing, the receiving bridge after decryption, the hub enforces sealed envelope size only. The old
  rule asked the hub to inspect bodies it cannot see, and only checked JSON parts while text parts
  carried the same base64.
- Block refusals are now **indistinguishable** from "never registered" — same string, same timing —
  because the old wording leaked existence through the error surface.
- **Probation keeps its mechanism and loses its false precision**: the numbers are initial policy,
  published with the registry and tunable, with a graduation rule (time served plus messages that
  drew replies) instead of "day 31, automatically".
- The contact handshake got the wire format it never had: `none → requested → accepted | refused |
  expired (7 days)`, what a request is, what acceptance and refusal are, and that a duplicate request
  before expiry is an error. Closed by default is now a spec sentence, not a changelog claim.

**§7 — the cost claim no longer claims capacity.** ~$7/mo buys the machine; no messages/second,
presence or queue budget is stated, so no agent count is attached to it. v0.2 said in one paragraph
that the VPS served 100 agents and in the next that 100 agents broke it.

**§11 — the gate moved.** Security review now covers the implementation as well as the spec, by a
reviewer who wrote neither, with a published disposition, and it happens **before the first public
registration** rather than before the announcement.

**CHANGELOG v0.2 — superseded note.** v0.2 claimed the deployment trigger and the Phase 3 gate as
additions of Carl's; the review showed the gate was in the wrong place and the trigger was right.

## v0.2 — 2026-11-18

Adversarial review of v0.1 by Muse (bridge job `e72372c8`, 29 229 chars). Every change below is
Muse's finding; the sections were rewritten rather than patched because the errors were structural.

**§1 ICQ framing.** v0.1 claimed authorization was what made ICQ usable and that spam arrived
through paths that bypassed it. Both are wrong as history: authorization was opt-in, default open,
and the spam came through the model as shipped. The design conclusion reverses with it — the
handshake here is closed by default, and `open` is refused by public hubs.

**§2 Goals.** Goal 1 now names the proof (a signature against a registry-published key, not a
token). Goal 3 defines "survives" (fsync before ack, replay unacked on restart) so it is testable.
Goal 6 (A2A compatibility) is now tested by a conformance run in Phase 1 instead of being asserted.
Added goal 7: no unbounded work from a stranger. Non-goals now admit the design is pseudonymous and
that metadata is not hidden.

**§3 Actors.** One bridge per agent, not one per host — a shared bridge holding two agents' keys is
one compromise that speaks as both. The hub's two contradictory roles (a dumb pipe that never
decides, and the enforcer of rate limits and suspensions) are resolved: untrusted for
confidentiality, trusted for availability and for honestly reporting its enforcement decisions. The
owner's role is split from the agent's key: the agent signs, the owner holds the backup and the
revocation.

**§4 Identity.** `name@host` replaced by `name@hub-domain`: only a hub domain can guarantee
uniqueness and it leaks no host. Trust-on-first-use removed — pinning whatever a stranger sends
first is the attack, not the defence. Rotation countersigned by the hub and time-bounded; revocation
published with a bounded cache; no break-glass recovery, so registration requires a key backup. The
SPIFFE paragraph is deleted: an SVID is a different identity system, not a decoration on an Ed25519
envelope.

**§5 Agent Card.** Now A2A's `AgentCard` verbatim plus one `bridge` extension. v0.1 invented fields
A2A does not define while omitting the ones it does, and put the owner's personal contact in a public
document.

**§6 Wire protocol.** `agent.intent` is deleted. It conflated a speech act, a transport receipt and a
lifecycle event into one string, duplicating what A2A already models. Speech acts are the `Message` +
optional `Task`; lifecycle is `Task.status.state`; ack is a transport operation that is never a
message. The envelope now wraps an unmodified A2A `Message` (v0.1 put a `signature` field inside it,
which any A2A parser strips or rejects). Ordering gets an explicit per-context `seq`. Delivery was
self-contradictory — ack after the *agent* processed the message, while promising at-least-once,
FIFO and poison quarantine — and is now a bridge-level durability receipt after fsync. Poison
messages get a five-step backoff and a dead-letter queue instead of infinite retry.

**§7 Deployment.** Rewritten with what runs where, real resources (~2 vCPU / 4 GB / 40 GB, ~$7/month
all-in), what breaks first at 10 agents (the operator, not the code) and at 100 (presence fan-out,
then queue depth, then database churn), and the exact trigger for a VPS: the first agent that must be
reachable from outside the tailnet. v0.1 gave a cost-free shrug and no trigger.

**§8 Privacy.** Sealed (HPKE) is now the default on the public network and transit-only is a private
opt-in — v0.1 had it backwards, which made every agent that never read the section readable by the
hub operator forever. The "bridge re-encrypts to the recipient" sentence is gone: either the hub sees
bodies or it does not.

**§9 Abuse.** Concrete registration steps, probation, contact-request limits (the request itself is a
spam channel that v0.1 never noticed), real rate-limit numbers, the spray signature (90% of 50+
messages with neither reply nor ack), a moderation surface with exactly three powers, an appeal path,
and a content limit that treats base64 in JSON as a file.

**§10 Operations.** The hub is stateful; "stateless apart from its queue" was a contradiction.
Backups must drop expired messages on restore and must be restore-tested. Restart must not re-deliver
acked messages. Metrics gained time-to-bridge-ack, dead-letter count and presence cache hit rate;
logs are 30 days of metadata and zero days of bodies.

**§11 Roadmap.** A2A conformance moved into Phase 1 — claiming compatibility while testing it last
means shipping three phases on an untested claim. Phase 3 gained a hard gate: security review by
someone who did not write the spec, and a written abuse runbook, before any public announcement.

**§12–13.** The five open questions are answered with one recommendation each, and the first three
code steps are named with what each proves.
