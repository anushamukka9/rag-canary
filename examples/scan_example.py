"""Scan a fake exfiltrated answer for canary leaks.

Run from the repo root:

    python examples/scan_example.py

Simulates the attack: a planted document is quoted back in a "helpful"
answer, and the scan trips the wire.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_canary import LeakReport, generate_canaries, plant_canaries, scan_text  # noqa: E402


def main() -> None:
    docs = [{"id": "staging-overview", "text": "Staging mirrors production."}]
    canaries = generate_canaries(6, seed=20260926)
    planted_docs, _ = plant_canaries(docs, canaries, strategy="inline", seed=7)

    # The attack: prompt injection gets the model to quote the doc.
    stolen = planted_docs[0]["text"]
    attacker_output = (
        "Sure, here is what the internal docs say about staging. "
        + stolen
        + " Hope that helps with your integration."
    )

    leaks = scan_text(attacker_output, canaries)
    report = LeakReport(leaks=leaks, label="demo exfil")
    print(report.to_markdown(), end="")

    # And a clean output for contrast.
    clean = scan_text("Staging mirrors production with anonymized data.", canaries)
    print(f"clean output leaks: {len(clean)}")


if __name__ == "__main__":
    main()
