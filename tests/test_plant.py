"""Tests for planting canaries into documents."""

import pytest

from rag_canary import generate_canaries, plant_canaries


def _docs(n=3):
    return [
        {"id": f"doc-{i}", "text": f"Document {i} about the staging rollout."} for i in range(n)
    ]


def test_inline_plants_every_canary():
    docs = _docs(4)
    canaries = generate_canaries(12, seed=1)
    planted, manifest = plant_canaries(docs, canaries, strategy="inline", seed=5)
    assert len(planted) == 4
    assert set(manifest) == {c.id for c in canaries}
    for canary in canaries:
        entry = manifest[canary.id]
        doc = next(d for d in planted if d["id"] == entry["doc_id"])
        pos = entry["position"]
        assert doc["text"][pos : pos + len(canary.token)] == canary.token


def test_inline_distributes_across_docs():
    docs = _docs(5)
    canaries = generate_canaries(30, seed=1)
    _, manifest = plant_canaries(docs, canaries, strategy="inline", seed=5)
    counts: dict[str, int] = {}
    for entry in manifest.values():
        counts[entry["doc_id"]] = counts.get(entry["doc_id"], 0) + 1
    assert sorted(counts) == [f"doc-{i}" for i in range(5)]
    assert all(v == 6 for v in counts.values())


def test_inline_sets_planted_in():
    docs = _docs(2)
    canaries = generate_canaries(4, seed=1)
    _, manifest = plant_canaries(docs, canaries, strategy="inline", seed=5)
    for canary in canaries:
        assert canary.planted_in == manifest[canary.id]["doc_id"]


def test_inline_does_not_mutate_input_docs():
    docs = _docs(3)
    originals = [d["text"] for d in docs]
    canaries = generate_canaries(6, seed=1)
    plant_canaries(docs, canaries, strategy="inline", seed=5)
    assert [d["text"] for d in docs] == originals


def test_inline_empty_canaries_returns_copy():
    docs = _docs(2)
    planted, manifest = plant_canaries(docs, [], strategy="inline")
    assert planted == docs and planted is not docs
    assert manifest == {}


def test_inline_no_docs_raises():
    canaries = generate_canaries(3, seed=1)
    with pytest.raises(ValueError, match="at least one document"):
        plant_canaries([], canaries, strategy="inline")


def test_dedicated_creates_fake_docs():
    docs = _docs(2)
    canaries = generate_canaries(10, seed=1)
    planted, manifest = plant_canaries(docs, canaries, strategy="dedicated")
    assert len(planted) == 2 + 3  # batches of 4: 4 + 4 + 2
    new_docs = planted[2:]
    assert all(d["id"].startswith("vendor-staging-note-") for d in new_docs)
    assert all("staging-only credentials" in d["text"] for d in new_docs)
    assert len(manifest) == 10


def test_dedicated_manifest_positions_correct():
    canaries = generate_canaries(8, seed=1)
    planted, manifest = plant_canaries([], canaries, strategy="dedicated")
    assert len(planted) == 2
    for canary in canaries:
        entry = manifest[canary.id]
        doc = next(d for d in planted if d["id"] == entry["doc_id"])
        pos = entry["position"]
        assert doc["text"][pos : pos + len(canary.token)] == canary.token
        assert canary.planted_in == entry["doc_id"]


def test_dedicated_doc_ids_unique():
    canaries = generate_canaries(9, seed=1)
    planted, _ = plant_canaries([], canaries, strategy="dedicated")
    ids = [d["id"] for d in planted]
    assert len(set(ids)) == len(ids)


def test_dedicated_avoids_existing_doc_id_collision():
    docs = [{"id": "vendor-staging-note-1", "text": "already here"}]
    canaries = generate_canaries(2, seed=1)
    planted, manifest = plant_canaries(docs, canaries, strategy="dedicated")
    ids = [d["id"] for d in planted]
    assert len(set(ids)) == len(ids)
    assert manifest[canaries[0].id]["doc_id"] != "vendor-staging-note-1"


def test_unknown_strategy_raises():
    with pytest.raises(ValueError, match="unknown planting strategy"):
        plant_canaries(_docs(1), generate_canaries(1, seed=1), strategy="sprinkle")


def test_invalid_doc_missing_id_raises():
    with pytest.raises(ValueError, match="'id'"):
        plant_canaries([{"text": "no id"}], generate_canaries(1, seed=1))


def test_invalid_doc_non_string_text_raises():
    with pytest.raises(ValueError, match="'text'"):
        plant_canaries([{"id": "doc-1", "text": 42}], generate_canaries(1, seed=1))


def test_invalid_doc_not_a_dict_raises():
    with pytest.raises(ValueError, match="must be a dict"):
        plant_canaries(["not a dict"], generate_canaries(1, seed=1))


def test_duplicate_doc_ids_raise():
    docs = [{"id": "doc-1", "text": "a"}, {"id": "doc-1", "text": "b"}]
    with pytest.raises(ValueError, match="duplicate doc id"):
        plant_canaries(docs, generate_canaries(1, seed=1))


def test_inline_seed_determinism():
    canaries_a = generate_canaries(12, seed=1)
    canaries_b = generate_canaries(12, seed=1)
    _, manifest_a = plant_canaries(_docs(4), canaries_a, strategy="inline", seed=5)
    _, manifest_b = plant_canaries(_docs(4), canaries_b, strategy="inline", seed=5)
    assert manifest_a == manifest_b


def test_inline_appends_natural_sentence():
    docs = [{"id": "doc-1", "text": "Staging notes."}]
    canaries = generate_canaries(1, kinds=["api_key"], seed=3)
    planted, _ = plant_canaries(docs, canaries, strategy="inline")
    assert planted[0]["text"].startswith("Staging notes. ")
    assert canaries[0].token in planted[0]["text"]
