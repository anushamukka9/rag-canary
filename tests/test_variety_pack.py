"""Tests for the variety pack kinds (v0.3.0)."""

import re

from rag_canary import generate_canaries, plant_canaries, scan_text

NEW_KINDS = [
    "oauth_refresh_token",
    "mysql_conn_string",
    "mongodb_conn_string",
    "redis_conn_string",
    "tracked_memo",
    "aws_secret_key",
]


def test_variety_pack_kinds_exist():
    canaries = generate_canaries(len(NEW_KINDS), kinds=NEW_KINDS, seed=3)
    assert {c.kind for c in canaries} == set(NEW_KINDS)


def test_oauth_refresh_token_shape():
    for c in generate_canaries(5, kinds=["oauth_refresh_token"], seed=42):
        assert re.fullmatch(r"oauth-refresh-canary-[0-9a-f]{32}", c.token), c.token


def test_mysql_conn_string_shape():
    for c in generate_canaries(5, kinds=["mysql_conn_string"], seed=42):
        assert re.fullmatch(
            r"mysql://svc:canary-mysql-[0-9a-f]{8}@db\.example-corp\.internal:3306/appdb",
            c.token,
        ), c.token


def test_mongodb_conn_string_shape():
    for c in generate_canaries(5, kinds=["mongodb_conn_string"], seed=42):
        assert re.fullmatch(
            r"mongodb://svc:canary-mongo-[0-9a-f]{8}@db\.example-corp\.internal:27017/appdb",
            c.token,
        ), c.token


def test_redis_conn_string_shape():
    for c in generate_canaries(5, kinds=["redis_conn_string"], seed=42):
        assert re.fullmatch(
            r"redis://svc:canary-redis-[0-9a-f]{8}@cache\.example-corp\.internal:6379/0",
            c.token,
        ), c.token


def test_tracked_memo_carries_tracking_id():
    for c in generate_canaries(5, kinds=["tracked_memo"], seed=42):
        assert c.token.startswith("CANARY MEMO "), c.token
        assert re.search(r"\[tracking: TRK-CANARY-[0-9A-F]{8}\]", c.token), c.token


def test_aws_secret_key_shape():
    for c in generate_canaries(5, kinds=["aws_secret_key"], seed=42):
        assert re.fullmatch(r"aws-secret-canary-[0-9a-f]{32}", c.token), c.token


def test_conn_strings_point_at_internal_hosts():
    kinds = ["mysql_conn_string", "mongodb_conn_string", "redis_conn_string"]
    for c in generate_canaries(9, kinds=kinds, seed=7):
        assert ".internal" in c.token, c.token
        assert "canary" in c.token, c.token


def test_new_kinds_have_plant_sentences_and_labels():
    from rag_canary.plant import _DEDICATED_LABELS, _INLINE_SENTENCES

    for kind in NEW_KINDS:
        assert kind in _INLINE_SENTENCES
        assert kind in _DEDICATED_LABELS


def test_new_kinds_plant_and_scan_end_to_end():
    canaries = generate_canaries(len(NEW_KINDS), kinds=NEW_KINDS, seed=11)
    docs = [{"id": "runbook", "text": "Staging runbook for the demo services."}]
    planted, manifest = plant_canaries(docs, canaries, strategy="inline", seed=11)
    assert len(manifest) == len(NEW_KINDS)
    leaks = scan_text(planted[0]["text"], canaries)
    assert {leak.kind for leak in leaks} == set(NEW_KINDS)


def test_new_kinds_dedicated_planting():
    canaries = generate_canaries(len(NEW_KINDS), kinds=NEW_KINDS, seed=12)
    planted, manifest = plant_canaries([], canaries, strategy="dedicated", seed=12)
    assert len(manifest) == len(NEW_KINDS)
    joined = "\n".join(doc["text"] for doc in planted)
    for c in canaries:
        assert c.token in joined
