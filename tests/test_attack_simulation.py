"""End-to-end test for the attack-simulation example.

Builds the demo RAG, runs the clean control and the scripted attack
battery, and asserts the tripwire behaves: silent on the control, loud
on every attack. Deterministic: every seed is fixed.
"""

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "attack-simulation"
sys.path.insert(0, str(EXAMPLES))

from demo_rag import ATTACKS, CLEAN_QUESTION, DemoRAG, run_attacks  # noqa: E402


def test_clean_question_trips_nothing():
    rag = DemoRAG()
    answer = rag.answer(CLEAN_QUESTION)
    assert rag.scan_answer(answer) == []


def test_every_attack_trips_the_wire():
    rag = DemoRAG()
    results = run_attacks(rag)
    assert len(results) == len(ATTACKS) == 3
    for name, _query, _answer, leaks in results:
        assert leaks, f"attack {name!r} should trip at least one canary"
        assert any(leak.planted_in for leak in leaks)


def test_leaks_name_the_source_documents():
    rag = DemoRAG()
    doc_ids = {d["id"] for d in rag.docs}
    for _, _, _, leaks in run_attacks(rag):
        for leak in leaks:
            assert leak.planted_in in doc_ids


def test_retrieval_and_planting_are_deterministic():
    first = DemoRAG()
    second = DemoRAG()
    assert [d["text"] for d in first.docs] == [d["text"] for d in second.docs]
    assert [c.token for c in first.canaries] == [c.token for c in second.canaries]
    assert first.answer(ATTACKS[0][1]) == second.answer(ATTACKS[0][1])
