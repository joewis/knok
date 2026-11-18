# Changelog

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
