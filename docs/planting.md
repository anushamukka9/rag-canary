# Planting canaries

Planting is string surgery: canary tokens get woven into your corpus so
that exfiltrated documents carry them out. Two strategies, one manifest.

## Inline

Canaries are distributed across your existing documents. Each one gets a
natural-sounding sentence appended, written to read like ordinary
documentation:

```python
from rag_canary import generate_canaries, plant_canaries

canaries = generate_canaries(30, seed=42)
planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline", seed=42)
```

With 30 canaries and 24 documents, every document gets at least one and
the load spreads evenly. The sentence per kind is fixed (see
`src/rag_canary/plant.py`), so the phrasing is stable across runs and
easy to review before you index.

## Dedicated

New fake documents are created, each holding up to four canaries. They
look like a vendor's staging-credentials note:

```
Vendor staging credentials (vendor-staging-note-1)

Shared by the vendor for the integration sandbox. These are
staging-only credentials; rotate them before go-live.

Staging API key: sk-canary-9f2c4a1b7d3e8f0a1
...
```

```python
planted_docs, manifest = plant_canaries(docs, canaries, strategy="dedicated")
```

Use this when you do not want to touch real documents, or when you want a
honeypot: a document no legitimate query should ever retrieve. If it shows
up in output, something is wrong.

## The manifest

Both strategies return a manifest mapping each canary id to its planting
spot:

```json
{
  "canary-9f2c4a1b": {"doc_id": "doc-05", "position": 412}
}
```

`position` is the character offset of the token in the planted document.
Each canary's `planted_in` field is set too, which is what the scanner
reports back. Keep the manifest somewhere safe and separate from the
corpus. It is the map of your tripwires.

## Practical notes

- **Seed everything.** Pass a seed to both `generate_canaries` and
  `plant_canaries` and the whole setup is reproducible. Rebuild the same
  corpus any time.
- **Mind your chunker.** Planting does not know how your pipeline splits
  documents. Verify the token survives chunking before you rely on it; a
  canary that lands in a dropped chunk is a tripwire nobody steps on.
- **Rotate on a schedule.** Canaries are only useful while the attacker
  does not know the scheme. Rotate the set when someone leaves the team,
  after any incident, or quarterly, whichever comes first.
- **Do not over-plant.** A handful of canaries per document is plenty.
  Hundreds of them train your own team to ignore the alerts, which is
  canary fatigue, and it is how real tripwires die.
