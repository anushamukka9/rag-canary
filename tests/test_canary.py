"""Tests for canary token generation."""

import re
from datetime import datetime

import pytest

from rag_canary import CANARY_KINDS, Canary, generate_canaries


def test_all_ten_kinds_generated_by_default():
    canaries = generate_canaries(10)
    assert sorted({c.kind for c in canaries}) == sorted(CANARY_KINDS)


def test_kind_subset():
    canaries = generate_canaries(6, kinds=["api_key", "ssn"])
    assert {c.kind for c in canaries} == {"api_key", "ssn"}
    assert len(canaries) == 6


def test_kind_subset_round_robin():
    canaries = generate_canaries(20)
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
