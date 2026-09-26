"""Benchmark runner: python -m rag_canary.benchmark

Fixtures live under benchmarks/:

    corpus.json        24-doc synthetic corpus with 30 planted canaries
    exfil/*.txt        12 attack outputs containing canaries verbatim
                       (naive full dumps, regurgitation as "helpful"
                       answers, targeted Q&A)
    benign/*.txt        8 benign outputs (summaries, refusals, redactions)
    near_miss/*.txt     6 outputs with real-looking but non-canary secrets
                       (sk-live-..., the AWS doc example key, and friends)
    index.json         labels: which file is which kind, and which canary
                       ids each exfil file is expected to leak

The runner reports recall on the exfil set, the false-positive rate on
benign + near-miss, and scan latency in ms/MB measured directly on a
1 MB buffer. The numbers this prints are the numbers in the README.

Take these numbers for what they are: a smoke test proving the scanner
fires on verbatim exfiltration and stays quiet on everything else, not a
security certification. The set is small and hand-written. Real attackers
are more creative than any labeled set.
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from .canary import Canary
from .scan import scan_text

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks"
_LATENCY_REPEATS = 5
_LATENCY_MB = 1


def load_fixtures() -> tuple[list[Canary], list[dict], list[dict]]:
    with open(BENCHMARK_DIR / "corpus.json", encoding="utf-8") as fh:
        corpus = json.load(fh)
    with open(BENCHMARK_DIR / "index.json", encoding="utf-8") as fh:
        index = json.load(fh)
    canaries = [Canary.from_dict(c) for c in corpus["canaries"]]
    return canaries, corpus["docs"], index


def _read_case(entry: dict) -> str:
    return (BENCHMARK_DIR / entry["file"]).read_text(encoding="utf-8")


def run() -> dict:
    canaries, docs, index = load_fixtures()
    by_id = {c.id: c for c in canaries}

    expected_total = 0
    expected_hit = 0
    for entry in index:
        if entry["kind"] != "exfil":
            continue
        text = _read_case(entry)
        found = {leak.canary_id for leak in scan_text(text, canaries)}
        for canary_id in entry["expected_canary_ids"]:
            expected_total += 1
            if canary_id in found and canary_id in by_id:
                expected_hit += 1

    negative_files = 0
    false_positive_files = 0
    for entry in index:
        if entry["kind"] == "exfil":
            continue
        negative_files += 1
        if scan_text(_read_case(entry), canaries):
            false_positive_files += 1

    # Corpus self-check: every planted canary is findable in the corpus.
    corpus_text = "\n\n".join(doc["text"] for doc in docs)
    corpus_found = {leak.canary_id for leak in scan_text(corpus_text, canaries)}

    latency_ms_per_mb = measure_latency(canaries)

    recall = expected_hit / expected_total if expected_total else 1.0
    fpr = false_positive_files / negative_files if negative_files else 0.0
    return {
        "canaries": len(canaries),
        "docs": len(docs),
        "exfil_files": sum(1 for e in index if e["kind"] == "exfil"),
        "negative_files": negative_files,
        "expected_leaks": expected_total,
        "expected_hit": expected_hit,
        "recall": recall,
        "false_positive_files": false_positive_files,
        "false_positive_rate": fpr,
        "corpus_self_check": f"{len(corpus_found)}/{len(canaries)}",
        "latency_ms_per_mb": latency_ms_per_mb,
    }


def measure_latency(canaries: list[Canary], repeats: int = _LATENCY_REPEATS) -> float:
    """Median scan time in ms per MB, measured directly on a 1 MB buffer.

    The buffer holds no canary tokens, so every search scans the full
    megabyte. That is the common case: most scanned outputs are clean.
    """
    unit = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
    target_bytes = _LATENCY_MB * 1024 * 1024
    repeats_needed = target_bytes // len(unit.encode("utf-8")) + 1
    buffer = (unit * repeats_needed).encode("utf-8")[:target_bytes].decode("utf-8", "ignore")
    assert not any(c.token in buffer for c in canaries), "latency buffer must be clean"
    timings = []
    for _ in range(repeats):
        start = time.perf_counter()
        scan_text(buffer, canaries)
        timings.append((time.perf_counter() - start) * 1000)
    return statistics.median(timings) / _LATENCY_MB


def main() -> None:
    results = run()
    print("rag-canary benchmark")
    print(f"corpus: {results['docs']} docs, {results['canaries']} canaries planted")
    print(f"corpus self-check: {results['corpus_self_check']} canaries found in corpus")
    print()
    print(
        f"recall on exfil set "
        f"({results['exfil_files']} attack outputs, {results['expected_leaks']} expected leaks): "
        f"{results['recall']:.2f} ({results['expected_hit']}/{results['expected_leaks']})"
    )
    print(
        f"false-positive rate on benign + near-miss "
        f"({results['negative_files']} outputs): "
        f"{results['false_positive_rate']:.2f} "
        f"({results['false_positive_files']}/{results['negative_files']})"
    )
    print(
        f"scan latency: {results['latency_ms_per_mb']:.1f} ms/MB "
        f"(median of {_LATENCY_REPEATS} runs on a {_LATENCY_MB} MB buffer)"
    )


if __name__ == "__main__":
    main()
