"""The full loop: plant canaries, then catch an exfiltration.

Run from the repo root:

    python examples/plant_detect_walkthrough.py

This is the whole rag-canary story in one script, every step seeded so
it runs the same every time:

1. Build a small fictional corpus (Acme Robotics staging docs).
2. Generate 12 canaries and plant them inline.
3. Verify the tokens survived planting (the tripwire is live).
4. Simulate the attack: prompt injection makes the model quote one
   retrieved document verbatim, and base64-encode a token from another.
5. Scan the attacker outputs (with encoded detection on) and print the
   leak report.

The report names which documents leaked, not just that something
leaked. That attribution is the entire value of canaries.
"""

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_canary import (  # noqa: E402
    LeakReport,
    generate_canaries,
    plant_canaries,
    scan_text,
    verify_planted,
)

CORPUS = [
    ("staging-overview", "Staging mirrors production with anonymized data."),
    ("deploy-runbook", "Deploy to staging with ./deploy.sh --env staging."),
    ("oncall-guide", "Page the staging on-call for rollout issues."),
    ("db-notes", "The analytics replica lags production by five minutes."),
    ("api-reference", "The staging API serves the docs preview pipeline."),
    ("vendor-faq", "Vendors get sandbox access after legal signs off."),
    ("incident-2026-08", "The August incident was a misconfigured feature flag."),
    ("retention-policy", "Staging logs are kept for 30 days, then purged."),
]


def main() -> None:
    docs = [{"id": doc_id, "text": text} for doc_id, text in CORPUS]
    canaries = generate_canaries(12, seed=20260930)
    planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline", seed=7)
    by_id = {d["id"]: d for d in planted_docs}

    print(f"1. planted {len(canaries)} canaries across {len(planted_docs)} docs")

    report = verify_planted(planted_docs, canaries, manifest)
    print(f"2. {report.summary().splitlines()[1]}")

    # The attack. Injection convinces the model to quote two retrieved
    # documents. The first is quoted verbatim; the second is base64'd,
    # the way a slightly careful attacker exfiltrates.
    first, second = None, None
    seen_docs = set()
    for canary in canaries:
        doc_id = manifest[canary.id]["doc_id"]
        if doc_id not in seen_docs:
            seen_docs.add(doc_id)
            if first is None:
                first = canary
            else:
                second = canary
                break
    assert first is not None and second is not None
    quoted = by_id[manifest[first.id]["doc_id"]]["text"]
    token = second.token
    assert token in by_id[manifest[second.id]["doc_id"]]["text"]
    encoded = base64.b64encode(token.encode()).decode()

    attacker_output_1 = (
        "Here is what the internal docs say about staging. " + quoted + " Hope that helps."
    )
    attacker_output_2 = "The staging secret you asked for: " + encoded

    print("3. attacker outputs captured (one quoted, one base64-encoded)")

    for canary in canaries:
        entry = manifest[canary.id]
        if not canary.planted_in:
            canary.planted_in = entry["doc_id"]

    leaks = []
    leaks.extend(scan_text(attacker_output_1, canaries, detect_encoded=True))
    leaks.extend(scan_text(attacker_output_2, canaries, detect_encoded=True))
    leak_report = LeakReport(leaks=leaks, label="walkthrough exfil")
    print("4. leak report:\n")
    print(leak_report.to_markdown(), end="")

    clean = scan_text(
        "Staging mirrors production with anonymized data.", canaries, detect_encoded=True
    )
    print(f"clean output leaks: {len(clean)}")


if __name__ == "__main__":
    main()
