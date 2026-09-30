"""Tests for verify_planted: the planting integrity check."""

from rag_canary import generate_canaries, plant_canaries, verify_planted


def _planted(n_canaries=6, n_docs=3, seed=11):
    canaries = generate_canaries(n_canaries, seed=seed)
    docs = [{"id": f"doc-{i}", "text": f"Doc {i}."} for i in range(n_docs)]
    planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline", seed=seed)
    return planted_docs, canaries, manifest


def test_verify_all_present():
    planted_docs, canaries, manifest = _planted()
    report = verify_planted(planted_docs, canaries, manifest)
    assert report.checked == 6
    assert report.found == 6
    assert report.ok()
    assert report.missing == []


def test_verify_uses_planted_in_without_manifest():
    planted_docs, canaries, _ = _planted()
    report = verify_planted(planted_docs, canaries)
    assert report.ok()


def test_verify_uses_manifest_when_planted_in_missing():
    planted_docs, canaries, manifest = _planted()
    for c in canaries:
        c.planted_in = None
    report = verify_planted(planted_docs, canaries, manifest)
    assert report.ok()


def test_verify_catches_mangled_token():
    planted_docs, canaries, manifest = _planted()
    doc_id = manifest[canaries[0].id]["doc_id"]
    doc = next(d for d in planted_docs if d["id"] == doc_id)
    doc["text"] = doc["text"].replace(canaries[0].token, "[REDACTED]")
    report = verify_planted(planted_docs, canaries, manifest)
    assert not report.ok()
    assert report.found == 5
    assert len(report.missing) == 1
    assert report.missing[0]["canary_id"] == canaries[0].id
    assert "token not found" in report.missing[0]["reason"]


def test_verify_catches_deleted_doc():
    planted_docs, canaries, manifest = _planted()
    doc_id = manifest[canaries[0].id]["doc_id"]
    planted_docs = [d for d in planted_docs if d["id"] != doc_id]
    report = verify_planted(planted_docs, canaries, manifest)
    assert not report.ok()
    missing_ids = {m["canary_id"] for m in report.missing}
    assert canaries[0].id in missing_ids
    assert any("not in corpus" in m["reason"] for m in report.missing)


def test_verify_catches_unplaced_canary():
    planted_docs, canaries, _ = _planted()
    stray = generate_canaries(1, seed=999)[0]
    report = verify_planted(planted_docs, canaries + [stray])
    assert not report.ok()
    assert report.checked == 7
    entry = next(m for m in report.missing if m["canary_id"] == stray.id)
    assert "no planting location" in entry["reason"]


def test_verify_empty_set_ok():
    report = verify_planted([{"id": "d", "text": "x"}], [])
    assert report.ok()
    assert report.checked == 0


def test_verify_summary_and_json():
    import json

    planted_docs, canaries, manifest = _planted()
    report = verify_planted(planted_docs, canaries, manifest)
    assert "6/6" in report.summary()
    payload = json.loads(report.to_json())
    assert payload["checked"] == 6 and payload["found"] == 6
    assert payload["missing"] == []
