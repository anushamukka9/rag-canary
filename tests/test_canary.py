"""Tests for canary token generation."""

import re
from datetime import datetime

import pytest

from rag_canary import CANARY_KINDS, Canary, generate_canaries, rotate_canaries


def test_all_kinds_generated_by_default():
    canaries = generate_canaries(len(CANARY_KINDS))
    assert sorted({c.kind for c in canaries}) == sorted(CANARY_KINDS)


def test_kind_subset():
    canaries = generate_canaries(6, kinds=["api_key", "ssn"])
    assert {c.kind for c in canaries} == {"api_key", "ssn"}
    assert len(canaries) == 6


def test_kind_subset_round_robin():
    canaries = generate_canaries(len(CANARY_KINDS) * 2)
    counts = {kind: 0 for kind in CANARY_KINDS}
    for c in canaries:
        counts[c.kind] += 1
    assert all(v == 2 for v in counts.values())


def test_unknown_kind_raises():
    with pytest.raises(ValueError, match="unknown canary kinds"):
        generate_canaries(5, kinds=["api_key", "nuclear_launch_code"])


def test_n_must_be_positive():
    with pytest.raises(ValueError, match="at least 1"):
        generate_canaries(0)
    with pytest.raises(ValueError, match="at least 1"):
        generate_canaries(-3)


def test_tokens_unique():
    canaries = generate_canaries(200)
    tokens = [c.token for c in canaries]
    assert len(set(tokens)) == 200


def test_ids_unique():
    canaries = generate_canaries(200)
    ids = [c.id for c in canaries]
    assert len(set(ids)) == 200


@pytest.mark.parametrize("kind", list(CANARY_KINDS))
def test_every_token_contains_canary_marker(kind):
    canaries = generate_canaries(5, kinds=[kind])
    for c in canaries:
        assert "canary" in c.token.lower(), f"{kind} token missing marker: {c.token}"


def test_no_xoxb_prefix_anywhere():
    canaries = generate_canaries(50)
    for c in canaries:
        assert "xoxb-" not in c.token.lower()


def test_no_github_token_prefixes():
    canaries = generate_canaries(50, kinds=["github_token"])
    for c in canaries:
        assert not re.search(r"gh[op]_[A-Za-z0-9]", c.token)
        assert "github_pat_" not in c.token


def test_aws_token_breaks_partner_pattern():
    canaries = generate_canaries(50, kinds=["aws_key"])
    for c in canaries:
        assert "canary" in c.token.lower()
        assert re.search(r"AKIA[0-9A-Z]{16}", c.token) is None


def test_ssn_in_never_issued_range():
    canaries = generate_canaries(20, kinds=["ssn"])
    for c in canaries:
        assert re.fullmatch(r"900-\d{2}-\d{4}-canary", c.token), c.token


def test_email_shape():
    canaries = generate_canaries(5, kinds=["email"])
    for c in canaries:
        assert re.fullmatch(r"canary\+[0-9a-f]{6}@example-corp\.internal", c.token), c.token


def test_seed_determinism():
    first = generate_canaries(30, seed=1234)
    second = generate_canaries(30, seed=1234)
    assert [(c.id, c.token, c.kind) for c in first] == [(c.id, c.token, c.kind) for c in second]


def test_different_seeds_differ():
    first = generate_canaries(10, seed=1)
    second = generate_canaries(10, seed=2)
    assert [c.token for c in first] != [c.token for c in second]


def test_unseeded_tokens_still_safe():
    canaries = generate_canaries(20)
    for c in canaries:
        assert "canary" in c.token.lower()
    assert len({c.token for c in canaries}) == 20


def test_canary_defaults():
    c = Canary(id="canary-1", token="sk-canary-abc", kind="api_key")
    assert c.planted_in is None
    assert c.note == ""
    datetime.fromisoformat(c.created_at)


def test_to_dict_from_dict_roundtrip():
    original = generate_canaries(3, seed=9)
    for c in original:
        restored = Canary.from_dict(c.to_dict())
        assert restored == c


def test_from_dict_missing_optional_fields():
    c = Canary.from_dict({"id": "canary-1", "token": "sk-canary-abc", "kind": "api_key"})
    assert c.planted_in is None
    assert c.note == ""
    assert c.created_at


def test_token_shapes_spot_check():
    canaries = {c.kind: c for c in generate_canaries(10, seed=42)}
    assert canaries["api_key"].token.startswith("sk-canary-")
    assert canaries["slack_token"].token.startswith("slack-canary-")
    assert canaries["webhook_url"].token.startswith("https://hooks.example-corp.internal/canary/")
    assert canaries["db_conn_string"].token.startswith("postgresql://")
    assert "CANARY MEMO" in canaries["internal_memo"].token


def test_jwt_token_shape():
    canaries = generate_canaries(5, kinds=["jwt_token"], seed=42)
    for c in canaries:
        parts = c.token.split(".")
        assert len(parts) == 3, c.token
        assert parts[0] == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert parts[2].startswith("canary-sig-")


def test_credit_card_shape():
    canaries = generate_canaries(5, kinds=["credit_card"], seed=42)
    for c in canaries:
        assert re.fullmatch(r"4111-canary-1111-\d{4}", c.token), c.token
        assert not c.token.replace("-", "").isdigit()


def test_private_key_shape():
    canaries = generate_canaries(5, kinds=["private_key"], seed=42)
    for c in canaries:
        lines = c.token.splitlines()
        assert lines[0] == "-----BEGIN CANARY PRIVATE KEY-----"
        assert lines[-1] == "-----END CANARY PRIVATE KEY-----"
        assert len(lines) == 6


def test_new_kinds_have_plant_sentences_and_labels():
    from rag_canary.plant import _DEDICATED_LABELS, _INLINE_SENTENCES

    for kind in ("jwt_token", "credit_card", "private_key"):
        assert kind in _INLINE_SENTENCES
        assert kind in _DEDICATED_LABELS


def test_thirteen_kinds_total():
    assert len(CANARY_KINDS) == 13


def test_rotate_canaries_avoids_old_tokens():
    old = generate_canaries(20, seed=1)
    fresh = rotate_canaries(old, 10, seed=1)
    assert len(fresh) == 10
    old_tokens = {c.token for c in old}
    assert not ({c.token for c in fresh} & old_tokens)
    assert len({c.token for c in fresh}) == 10


def test_rotate_canaries_deterministic():
    old = generate_canaries(10, seed=5)
    first = rotate_canaries(old, 8, seed=9)
    second = rotate_canaries(old, 8, seed=9)
    assert [c.token for c in first] == [c.token for c in second]


def test_rotate_canaries_n_must_be_positive():
    old = generate_canaries(5, seed=1)
    with pytest.raises(ValueError, match="at least 1"):
        rotate_canaries(old, 0)


def test_rotate_canaries_rejects_unknown_kind():
    old = generate_canaries(5, seed=1)
    with pytest.raises(ValueError, match="unknown canary kinds"):
        rotate_canaries(old, 5, kinds=["bogus"])
