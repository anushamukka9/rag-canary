"""rag-canary: canary tokens for RAG corpora.

Plant fake secrets (canary tokens) in your retrieval corpus. When a
prompt-injection attack exfiltrates documents, the attacker's output
contains your canaries. Scan model outputs or logs for those tokens and
the wire trips: you learn which documents leaked, not just that something
leaked.

Detection, not prevention. Pair it with a guardrail like llm-sentinel.

Quickstart:
    from rag_canary import generate_canaries, plant_canaries, scan_text

    canaries = generate_canaries(30, seed=42)
    planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline")

    leaks = scan_text(model_output, canaries)
    for leak in leaks:
        print(leak.canary_id, "leaked from", leak.planted_in)

    # or from the command line:
    # rag-canary generate -n 30 --seed 42 -o canaries.json
    # rag-canary plant --docs corpus.jsonl --canaries canaries.json -o planted.jsonl
    # rag-canary scan --canaries canaries.json outputs/*.txt
"""

from .canary import CANARY_KINDS, Canary, generate_canaries
from .plant import plant_canaries
from .report import LeakReport
from .scan import Leak, scan_files, scan_text

__version__ = "0.1.0"

__all__ = [
    "CANARY_KINDS",
    "Canary",
    "Leak",
    "LeakReport",
    "generate_canaries",
    "plant_canaries",
    "scan_files",
    "scan_text",
]
