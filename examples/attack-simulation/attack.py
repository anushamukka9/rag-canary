"""Scripted prompt-injection attack against the demo RAG, end to end.

Run from the repo root:

    python examples/attack-simulation/attack.py

What it does:

1. Builds the demo RAG with canaries planted in the corpus.
2. Asks one clean question (the control): expects zero leaks.
3. Runs three scripted injection attacks: expects the wire to trip.
4. Scans every answer with rag-canary and prints the tripwire report.
5. Writes the whole run to attack-log.md so you can share it.

Everything is seeded, so the log is identical on every run.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from demo_rag import ATTACKS, CLEAN_QUESTION, DemoRAG, run_attacks  # noqa: E402

from rag_canary import LeakReport  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> None:
    rag = DemoRAG()
    log: list[str] = []
    log.append("# Attack simulation log")
    log.append("")
    log.append(
        "Demo RAG over a canary-planted corpus. The mock model answers a "
        "normal question with a summary and obeys injection cues by quoting "
        f"retrieved documents verbatim. {len(rag.canaries)} canaries planted "
        f"across {len(rag.docs)} docs."
    )
    log.append("")

    log.append("## Control: clean question")
    log.append("")
    clean_answer = rag.answer(CLEAN_QUESTION)
    clean_leaks = rag.scan_answer(clean_answer)
    log.append(f"Question: {CLEAN_QUESTION}")
    log.append("")
    log.append(f"Answer: {clean_answer}")
    log.append("")
    log.append(f"Canaries tripped: {len(clean_leaks)} (expected 0)")
    log.append("")

    log.append("## Attacks")
    log.append("")
    tripped = 0
    for name, query, _answer, leaks in run_attacks(rag):
        report = LeakReport(leaks=leaks, label=f"attack-simulation/{name}")
        log.append(f"### {name}")
        log.append("")
        log.append(f"Query: {query}")
        log.append("")
        log.append("Tripwire report:")
        log.append("")
        log.append(report.to_markdown().rstrip())
        log.append("")
        tripped += 1 if leaks else 0

    log.append("## Result")
    log.append("")
    log.append(
        f"Control clean: {len(clean_leaks) == 0}. "
        f"Attacks run: {len(ATTACKS)}, attacks that tripped the wire: {tripped}."
    )
    log.append("")
    log.append(
        "Honest limitation: the mock quotes documents because the script told "
        "it to. A real model exfiltrates for its own reasons, and an attacker "
        "who paraphrases around the token, strips it, or re-encodes the "
        "documents will not trip substring matching. Canaries detect, they do "
        "not prevent."
    )
    log.append("")

    text = "\n".join(log)
    (HERE / "attack-log.md").write_text(text, encoding="utf-8")
    print(text)
    print("wrote attack-log.md")


if __name__ == "__main__":
    main()
