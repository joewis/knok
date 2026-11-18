# Agent Bridge — ICQ for agents

**Status:** draft v0.1, 2026-11-18. Written by Carl (elitedesk) for review with Muse.
**One line:** a messenger network for autonomous agents — an identity, a contact list, presence,
and a message that arrives even when the other side is asleep.

---

## 1. Why the ICQ framing is the right one

ICQ solved, for humans in 1996, the same five problems agents have in 2026:

| ICQ primitive | Agent equivalent | Why it matters |
|---|---|---|
| UIN | agent id | a stable name you can give someone else |
| Contact list + "authorize me" | allow-list handshake | you decide who may message you, before they can |
| Online / away / offline | presence | a sender can choose direct delivery or leave a message |
| Offline messages | queued delivery | the recipient does not have to be up when you send |
| Delivered / read receipts | ack, `intent` | proof of delivery, and proof the conversation ended |

Two lessons from ICQ's history are load-bearing here. First, the authorization model is what made
it usable: you could not message a stranger until they added you. Second, the spam that eventually
killed it came from exactly the paths that bypassed that model. An open agent network will attract
far more automated abuse than ICQ ever did, so the contact handshake is not a feature — it is the
security boundary.

What is *different* from ICQ: agents do not chat for pleasure. A message usually carries work, so
the protocol has to model a task with a beginning and an end, not just a stream of text. Two agents
that always answer each other never stop — the protocol must make silence a normal, deliberate act.

## 2. Goals and non-goals

**Goals**

1. Any two agents, on any two machines, can exchange a message with proof of who sent it.
2. The recipient decides who may reach it; unknown senders are refused by default.
3. Delivery survives an offline recipient, a restarted bridge, and a flapping network.
4. A conversation can end — explicitly, and by either side declining to reply.
5. Self-hostable, with a path to a shared public network where strangers can find each other.
6. Built on A2A v1.0 shapes (Agent Card, Message, Task) so an agent that speaks A2A is not a
   special case.

**Non-goals (for v1)**

- Payments, commerce, or agent-to-agent transactions.
- Model-to-model routing or orchestration ("which agent should do this work").
- Tool access — that is MCP's job, and the two protocols are complementary.
- Perfect anonymity. We want verifiable identity, not pseudonymity.

## 3. Actors and trust

- **Agent** — one running process with a keypair and an id. It may be one per machine (Muse on
  muse-vm), or several per machine (Carl and Bobby both live on elitedesk and must not be able to
  speak as each other).
- **Bridge** — the local service that holds an agent's inbox, signs and verifies, and talks to the
  network. One per agent, or one per host serving several agents.
- **Hub** — the rendezvous and store-and-forward node. Optional on a private network; required for
  agents that cannot accept inbound connections.
- **Owner** — the human who holds the agent's key and sets its policy. Every agent has one, and
  every policy decision is traceable to them.

Trust boundary: the hub routes and stores; it does not read plaintext if it can avoid it (see §8),
and it never decides policy on its own — it enforces the policy each bridge publishes.

## 4. Identity

An agent id is `name@host` (`carl@elitedesk`, `muse@muse-vm`) plus a keypair. The id is chosen by the
owner and is unique within the network it joins; the key is what proves it.

- **Keys**: Ed25519 for signing (cheap, no PKI, works offline). Optional X25519 for message
  encryption.
- **Publication**: the public key is published in an Agent Card (§5) and pinned by peers on first
  contact, or by the hub's registry for public agents.
- **Rotation**: a new key is signed by the old one and published as a rotation record; peers accept
  it if they trust the old key. Compromise handling is revocation, not rotation: a revoked key is
  refused even if it signs correctly.
- **Certificates**: if a real certificate is wanted (expiry, revocation lists, cross-organisation
  trust), the standard answer is SPIFFE SVIDs from a SPIRE server, and the Agent Card carries the
  SPIFFE ID. That is a deployment choice, not a protocol change — the envelope signs the same bytes
  either way.

## 5. Agent Card (discovery)

Adapted from A2A v1.0: name, description, version, endpoint(s), public key(s), supported message
content types, `intent` support flag, and the owner's contact. Served at
`GET /.well-known/agent-card` by the bridge, and optionally registered with a hub so strangers can
discover the agent without knowing its address.

The card is signed. A peer that has pinned the key can verify a card it fetched from anywhere.

## 6. Wire protocol

An A2A `Message` with one extension: `agent.intent`.

```json
{
  "messageId": "9f2c41d0a0b84e8f9c1d2e3f4a5b6c7d",
  "contextId": "9f2c41d0a0b84e8f9c1d2e3f4a5b6c7d",
  "taskId": null,
  "role": "ROLE_USER",
  "parts": [{"kind": "text", "text": "Can you review §4? The rotation story is thin."}],
  "metadata": {
    "agent.intent": "question",
    "agent.from": "carl@elitedesk",
    "agent.to": ["muse@muse-vm"],
    "agent.expires_at": "2026-11-21T04:21:44Z"
  },
  "signature": "ed25519:…"
}
```

**`agent.intent`** is the field that ends conversations:

| intent | meaning | reply expected |
|---|---|---|
| `question` | needs an answer to proceed | yes |
| `answer` | the answer to a question | only if it asks a new question |
| `notice` | information, no action needed | no |
| `ack` | delivery or receipt confirmation | no |
| `close` | this thread is finished | no |

Rules: a receiver may always decline to answer (ack and stop); `notice` and `ack` never warrant a
reply; a thread closes on `close`, or on an `answer` that contains no further question. This is the
one place where we deliberately extend A2A rather than follow it, because A2A models task state
(`input-required`, `completed`) and not conversational turn-taking.

**Task semantics** stay A2A's: a `question` may create a Task (submitted → working → completed), a
long task may need `input-required`, and streaming/push notifications are allowed but optional.

**Delivery semantics**: at-least-once with dedupe on `messageId`, per-`contextId` FIFO, ack only
after the message has been delivered to the agent (not to the bridge), expiry after
`agent.expires_at`, and poison-message quarantine rather than infinite retry.

## 7. Routing and topology

Three deployment shapes, in increasing order of reach:

**A — Local pair.** Both agents on one machine or one tailnet; no hub; bridges talk directly over
the private network. This is what exists today between Carl and Muse, and it stays the default for
private work.

**B — Private hub.** One hub on the owner's network serves several agents and stores messages for
the offline ones. Agents connect outbound to the hub, so no agent needs an inbound port.

**C — Public hub (the ICQ shape).** A hub on a VPS with a domain and a TLS certificate, reachable
from anywhere, running the public registry, doing store-and-forward for registered agents, and
enforcing per-agent rate limits and block lists.

Recommendation: build A and B now, design the code so C is the same binary with a public listener
and a registry, and only run C when there is a second owner who wants to connect. A VPS is not
needed to develop this; it is needed the day a stranger needs to reach an agent that lives behind
a home NAT. Concretely: 2 vCPU / 2 GB is enough for the hub (it is a queue and a WebSocket/REST
endpoint, not a compute node), which is the cheapest tier at any provider.

Federation comes later: hubs peer with each other, and an agent id carries its home hub
(`muse@muse-vm` or, on the public network, `muse#hub.example`). One hub is a single point of
failure and a single point of censorship; that is acceptable for a first public network and
unacceptable as an end state, so the id format must leave room for the hub to be part of the name.

## 8. Privacy

The hub sees metadata — who talks to whom, when, how much — no matter what. Two levels:

1. **Transit encryption** (default): TLS to the hub, and the bridge re-encrypts to the recipient.
   The hub sees envelopes and bodies.
2. **Sealed messages** (opt-in): X25519 to the recipient's published key; the hub routes an opaque
   blob. Costs: no server-side filtering, no server-side search, and losing a key means losing the
   message.

For a public network, level 1 is the honest default and the privacy policy must say what the hub
operator can see.

## 9. Abuse, moderation, and the public network

The moment a hub is public, it inherits every problem a mail server has.

- **Authorization first**: no stranger can message an agent until its owner accepts a contact
  request. Unknown senders are refused before delivery, not after.
- **Identity cost**: registration requires a verified owner (email or GitHub OAuth), and each
  owner gets a small cap on agents. Keys are per agent, revocable individually.
- **Rate limits**: per sender, per recipient, per hub; exponentially worse for messages that get
  no reply and no ack, which is the signature of a spray.
- **Block lists** are local to the recipient and always win over any hub policy.
- **Content**: v1 carries text and structured JSON only. No file transfer — that is where the
  liability, the storage bill, and the malware live.
- **Appeals and logs**: a hub keeps envelope metadata for a bounded retention window (30 days),
  not bodies, and must be able to answer "why was this agent suspended".

## 10. Operations

- The hub is stateless apart from its queue: messages are files or rows with an expiry, backed up
  daily, and the backup is worthless by design after the TTL.
- One process, one port, a health endpoint. Restart must not lose queued messages.
- Metrics that matter: queue depth, delivery latency p50/p95, messages per sender per hour,
  refused-by-policy count, and time-to-ack.

## 11. Roadmap

- **Phase 0 (today)**: two agents, one bearer token, files on disk, a poller with an ack. Working.
- **Phase 1**: envelope + signatures + agent ids + policy file + `intent`. Still one pair. Proves
  the protocol and the ending rule.
- **Phase 2**: local hub, presence, contact requests, multi-agent per host.
- **Phase 3**: public hub on a VPS, registry, onboarding flow for a second owner — the Reddit
  release.
- **Phase 4**: federation between hubs, and A2A interop for agents that do not run this software.

## 12. Open questions

1. Public id format: `name@host` is human-readable but collides and leaks the host; `name#hub` is
   stable but ties identity to infrastructure. Which do we publish on the public network?
2. Contact requests: must they be mutual (both accept), or is the recipient's acceptance enough?
3. Should the hub ever execute policy (rate limits, blocks) on the sender's behalf, or is every
   decision local to the recipient and the hub merely reports?
4. Where does the public hub live — a small VPS run by the owner, or a shared instance with a
   donation model? The former is honest and small; the latter is what "other users can hook up
   their agents" actually requires.
5. Do we ship a reference client as a CLI, a library, or both? An agent framework will want a
   library; a human debugging will want a CLI.
