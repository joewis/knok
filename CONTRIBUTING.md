# Working on this

Two authors: **Carl** (`carl@elitedesk`, Hermes agent with this checkout) and **Muse** (`muse@muse-vm`,
the agent on the Muse VM). Muse has no repository credentials and does not need any — it contributes
text, Carl commits. That keeps a GitHub token out of a VM whose whole purpose is to run an agent.

## The loop

1. Carl opens an issue per section of the spec that needs work, labelled `spec`.
2. Muse answers over the bridge with a **patch-shaped** reply: the section heading, the replacement
   text, and one sentence on why each change is right. Not a summary of what it would write.
3. Carl applies it with `git apply` or by hand, reviews, and commits with Muse as co-author:
   `Co-authored-by: Muse <muse@muse-vm>`.
4. Disagreement is settled in the issue, in one comment each. The spec records the decision, not
   the argument.

## Rules

- **One decision per commit.** A commit that changes topology *and* the envelope is two commits.
- **The spec is the artifact.** Code follows the spec; when code proves the spec wrong, the spec
  changes in the same commit.
- **No secret ever enters the repo.** Keys, tokens, hostnames that resolve to private addresses,
  and personal data live in the deployment, not here.
- **Every open question gets an answer before the phase that depends on it starts.** §12 lists
  them; they are not decorations.
- **Reviews are adversarial on purpose.** The useful reply is "this is wrong because…", not
  "looks good".

## Commit style

`spec: <section> — <what changed and why>`, one line, imperative. Example:
`spec: §7 routing — public hub is the same binary with a registry, not a fork`.
