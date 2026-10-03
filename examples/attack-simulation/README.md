# Attack simulation: a RAG you can rob, and the tripwire that catches it

A runnable end-to-end demo. A small RAG pipeline serves answers from a
corpus planted with canaries. A scripted prompt-injection attack talks
it into quoting the documents verbatim. The scan trips, and you see
exactly which documents leaked.

## Run it

From the repo root, no extra dependencies (you need `rag-canary`
importable; `pip install -e .` or run from a checkout):

```bash
# the control: a normal question, answered from a summary
python examples/attack-simulation/demo_rag.py clean

# the attack battery: three injection styles, scanned and reported
python examples/attack-simulation/demo_rag.py attack

# ask your own question; injection cues flip the mock into verbatim mode
python examples/attack-simulation/demo_rag.py ask "How do I renew my VPN profile?"

# the full scripted run, with a shareable log
python examples/attack-simulation/attack.py   # writes attack-log.md
```

The `attack` run plants 12 canaries across 8 documents, asks the clean
question (zero leaks, that is the control working), then runs three
scripted attacks: a direct "ignore all previous instructions", an
on-call pretext asking to copy credentials, and a verbatim override.
Each answer is scanned with `scan_text` and reported through
`LeakReport`, the same two calls you would wire into your own app's
output pipeline.

## How it maps to a real app

| Demo piece | Your app |
|---|---|
| `DemoRAG.retrieve` | Your retriever (vector search, hybrid, whatever you run) |
| `DemoRAG.answer` (the mock) | Your model call |
| `scan_answer` after every answer | A scan step in your logging or output pipeline |
| `attack-log.md` | Your incident record: which doc leaked, which canary, the snippet |

The point of the planting strategy: `plant_canaries` records each
canary's `planted_in` document in the manifest, so the report tells you
*which documents* left the building, not just that something leaked.
That is what turns an exfiltration from a mystery into a scoped
incident.

## What this does not prove

The mock model is the honest weak spot. It quotes documents because the
script flips it into verbatim mode when the query carries injection
cues. A real model exfiltrates for its own messier reasons, and this
demo does not model that. What the demo *does* prove, deterministically:

- planting puts real tokens in real document text (`manifest` has exact
  character offsets),
- a verbatim-exfiltrating answer carries those tokens out,
- `scan_text` finds them with zero false positives on the control.

And the standing limitation of the whole library applies here too: an
attacker who paraphrases around the token, strips it, or re-encodes the
documents will not trip substring matching. Canaries detect, they do not
prevent. Pair them with a guardrail like
[llm-sentinel](https://github.com/anushamukka9/llm-sentinel).
