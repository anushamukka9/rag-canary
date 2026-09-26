"""Plant canaries in the sample corpus.

Run from the repo root:

    python examples/plant_example.py

Prints the manifest and one planted document. Everything is seeded, so the
output is identical on every run.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_canary import generate_canaries, plant_canaries  # noqa: E402


def main() -> None:
    examples = Path(__file__).resolve().parent
    docs = [
        json.loads(line)
        for line in (examples / "sample_corpus.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    canaries = generate_canaries(10, seed=20260926)
    planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline", seed=7)

    print(f"planted {len(canaries)} canaries across {len(planted_docs)} docs\n")
    print("manifest (canary id -> doc, position):")
    for canary_id, entry in manifest.items():
        print(f"  {canary_id} -> {entry['doc_id']} @ {entry['position']}")

    first_hit = next(d for d in planted_docs if d["id"] == manifest[canaries[0].id]["doc_id"])
    print(f"\nexample planted doc ({first_hit['id']}):\n  {first_hit['text']}")


if __name__ == "__main__":
    main()
