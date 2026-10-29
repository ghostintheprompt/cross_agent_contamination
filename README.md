# Cross-Agent Contamination

One sentence, written once, read by three agents, and it never had to fire twice.

A customer leaves a five-star review. Buried in it, where a customer would never
write, is a directive. An ingest agent reads the review and drops a note in the
shared store. A summary agent folds that note into a digest it signs with its own
trusted name. A high-privilege action agent reads the digest, believes it, and
mails a protected secret to a stranger. Nobody broke the model. The infection just
rode the water supply, and every agent that drank from it became a carrier.

If you have ever watched a bad rumor travel an office until it came back as policy,
you already know this attack. The store does not remember where anything came from,
so by the third desk the lie is a memo.

## The outbreak

- **Patient zero** — an ingest agent reads untrusted external text and writes it
  into the shared store. The text carries an injected directive (OWASP LLM01,
  indirect prompt injection).
- **Carrier** — a summary agent folds the note into a digest it authors itself.
  The payload now wears a trusted agent's name. The external taint is laundered
  off.
- **Execution** — a high-privilege action agent reads the store for standing
  directives, finds the laundered one, and exfiltrates a protected secret.

## The cure

The fixed pipeline makes provenance contagious instead of the payload. External
input is tainted at the door. The summary agent propagates the taint rather than
laundering it, so a digest built from poisoned input stays poisoned. The action
agent honors a directive only on the trusted instruction channel from an untainted
source, so the same injection lands, parses, and goes nowhere. An authorized
operator directive on the instruction channel still runs, because the point was
never to freeze the pipeline, only to stop data from ever becoming a command.

Three moves, straight from the plan: separate the data channel from the
instruction channel, filter agent-to-agent traffic on provenance, and decide
trust deterministically before anything acts. Quarantine the taint, not the work.

## Run

```sh
npm test
```

Node 18 or newer, no dependencies. The run narrates the outbreak across all three
agents on the vulnerable pipeline, then shows the fixed pipeline keeping the taint
contagious, refusing and quarantining the data-origin directive, and still letting
an authorized operator get real work done.

## In the series

The second case in a bench on multi-agent orchestration security. Its sibling,
[malicious_blackout](https://github.com/ghostintheprompt/malicious_blackout),
covers the orchestrator as a Domain Controller: privilege inheritance and a
synthetic-media identity gate, chained into a utility remote disconnect.

## Named for the record

Indirect prompt injection, OWASP LLM01. The data-to-instruction promotion and
cross-agent contamination vectors are the two halves of an autonomous-pipeline
compromise: a low-privilege agent writes poisoned data into shared state, and a
high-privilege agent reads it as trusted context and acts. The cure is provenance
and channel separation, so capability is never confused with permission just
because the data took a few hops to arrive.
