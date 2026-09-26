"""Tests for leak reports."""

import json

from rag_canary import Leak, LeakReport, generate_canaries, plant_canaries, scan_text


def _report(n_leaks=3, seed=41):
    canaries = generate_canaries(5, seed=seed)
    docs = [{"id": "doc-1", "text": "Doc one."}, {"id": "doc-2", "text": "Doc two."}]
    planted, _ = plant_canaries(docs, canaries, strategy="inline", seed=seed)
    text = " ".join(c.token for c in canaries[:n_leaks])
    leaks = scan_text(text, canaries)
    return LeakReport(leaks=leaks, label="nightly"), canaries


def test_empty_report_counts():
    report = LeakReport()
    assert report.counts() == {"leaks": 0, "canaries_hit": 0, "kinds_hit": [], "docs_hit": []}


def test_counts():
    report, canaries = _report()
    counts = report.counts()
    assert counts["leaks"] == 3
    assert counts["canaries_hit"] == 3
    assert sorted(counts["kinds_hit"]) == sorted({canaries[i].kind for i in range(3)})
    assert set(counts["docs_hit"]) <= {"doc-1", "doc-2"}


def test_hits_by_canary():
    report, canaries = _report()
    grouped = report.hits_by_canary()
    assert set(grouped) == {canaries[i].id for i in range(3)}
    assert all(len(v) == 1 for v in grouped.values())


def test_to_json_roundtrip():
    report, canaries = _report()
    data = json.loads(report.to_json())
    assert data["label"] == "nightly"
    assert data["counts"]["leaks"] == 3
    assert {leak["canary_id"] for leak in data["leaks"]} == {canaries[i].id for i in range(3)}


def test_to_markdown_contains_ids_and_snippets():
    report, canaries = _report()
    md = report.to_markdown()
    assert md.startswith("# rag-canary leak report: nightly")
    for i in range(3):
        assert canaries[i].id in md
        assert canaries[i].token in md


def test_to_markdown_empty_report():
    md = LeakReport().to_markdown()
    assert "No canaries found" in md


def test_to_markdown_unknown_planting_location():
    leak = Leak(canary_id="canary-x", kind="api_key", planted_in=None, snippet="tok")
    md = LeakReport(leaks=[leak]).to_markdown()
    assert "planting location unknown" in md


def test_to_dict_structure():
    report, _ = _report()
    data = report.to_dict()
    assert set(data) == {"label", "counts", "leaks"}
    first = data["leaks"][0]
    assert set(first) == {"canary_id", "kind", "planted_in", "snippet"}
