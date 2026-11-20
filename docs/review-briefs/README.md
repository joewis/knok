# Review briefs

One review is not a review of a system; it is a review of whatever the reviewer happened to read.
These briefs cut the repository into areas small enough to hold in one pass, and give each pass the
questions it exists to answer.

Give a reviewer one brief and the files it names — not the repository. A reviewer handed the whole
tree will summarise it, and a summary is not evidence.

| # | Brief | Answers |
|---|---|---|
| 1 | [Authentication and request replay](01-authentication-and-replay.md) | Who is this request from, and can it be used twice? |
| 2 | [The hub's HTTP implementation](02-hub-http.md) | What does the server accept, and what bounds it? |
| 3 | [Envelope and canonicalisation](03-envelope-and-canonicalisation.md) | What does a signature actually cover? |
| 4 | [Cryptographic key handling](04-key-handling.md) | Where do keys live, and what can an old one still do? |
| 5 | [Sealed messages and HPKE](05-sealed-hpke.md) | What is bound to a ciphertext, and where does plaintext go? |
| 6 | [Delivery, queue and durability](06-delivery-durability.md) | What survives a crash, and what is duplicated? |
| 7 | [Retry policy and CLI](07-retry-and-cli.md) | Is a retry the same message, and does the exit code lie? |
| 8 | [Contact gate and abuse](08-gate-and-abuse.md) | What can a peer make the system do, and learn? |
| 9 | [Logging and notices](09-logging-and-notices.md) | What is written down, and who can read it? |

## Ground rules — paste these with every brief

- The spec is a claim, the code is an implementation, and they can disagree. A disagreement is a
  finding; say which of the two you believe and why.
- A behaviour you dislike is not a defect. Name the input, the outcome, and why it matters. If it is
  deliberate and documented — in the decision records, or `docs/HUB.md`'s known-risks list — say you
  are restating a documented risk rather than discovering one.
- Severity is consequence × reachability on the deployment `README.md` describes, not on a
  hypothetical public hub. State which deployment you assume.
- Do not propose a fix before you have stated the failure. A fix without a failing input is a guess.

## Using a model reviewer

- **One brief per run.** Attach the files in its *Scope* section and nothing else. This is also what
  keeps a small-context model from choking.
- **Ask for the table first.** Each brief names a table (endpoints, bounds, crash points, outcomes).
  A reviewer that cannot fill the table has not read the code.
- **Demand `file:line` and the failing input.** Reject prose findings; ask it to redo the finding with
  a line number or drop it.
- **Say what is already decided.** Briefs 1, 4 and 5 name the deliberate designs and the open issues.
  Without that, a reviewer re-reports them as defects — which is exactly what the first attempt did.
- **Two passes per area if the reviewer is weak.** Pass one: read and fill the table. Pass two: attack
  the table. A single pass over nine files produces a plausible summary; two produce findings.

## What is out of bounds for every brief

Nothing in this repository is deployed publicly. The threat model in `docs/SPEC.md` §11 applies: the
hub is untrusted for confidentiality, trusted for availability; the bridge holds keys; peers are
authenticated but not trusted. A finding that assumes a hostile hub operator, a hostile kernel, or a
compromised host is out of scope — say so and stop.
