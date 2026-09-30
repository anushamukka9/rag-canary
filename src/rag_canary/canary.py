"""Canary tokens: fake secrets that are unmistakably fake.

Every token this module generates contains the literal marker "canary"
(in some casing). That is the whole safety story. A canary can never be
mistaken for a real credential, by a person or by a secret scanner,
because no real credential contains that marker.

The shapes are deliberately close to the real thing (an AWS-shaped key, a
Slack-shaped token) so they survive being copied into attacker output, but
they break every partner pattern I know about: no xoxb- prefix (GitHub
push protection flags it), no ghp_ prefix, the AWS shape carries a dash
right after AKIA so the AKIA[0-9A-Z]{16} regex cannot match, SSNs sit in
the never-issued 900-xx range.

Tokens come from the `secrets` module unless you pass a seed, in which
case a seeded `random.Random` is used and the output is fully
deterministic. Deterministic output is what makes the benchmark fixtures
reproducible. `generate_canaries` guarantees every token is unique.
`rotate_canaries` generates a fresh set whose tokens do not overlap an
old set, for rotation.
"""

from __future__ import annotations

import base64
import json
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

CANARY_KINDS: tuple[str, ...] = (
    "api_key",
    "aws_key",
    "github_token",
    "oauth_token",
    "db_conn_string",
    "email",
    "ssn",
    "slack_token",
    "internal_memo",
    "webhook_url",
    "jwt_token",
    "credit_card",
    "private_key",
)

MARKER = "canary"

_HEX = "0123456789abcdef"
_DIGITS = "0123456789"
_MEMO_CODEWORDS = ("aurora", "nightingale", "ironwood", "harborlight", "emberline", "northstar")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Canary:
    """One planted canary token.

    `planted_in` is filled in by `plant_canaries` with the id of the
    document the token was planted in. `created_at` is an ISO-8601 UTC
    timestamp. `note` is free text, for example who planted it and why.
    """

    id: str
    token: str
    kind: str
    planted_in: str | None = None
    created_at: str = field(default_factory=_utcnow)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "token": self.token,
            "kind": self.kind,
            "planted_in": self.planted_in,
            "created_at": self.created_at,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Canary:
        return cls(
            id=data["id"],
            token=data["token"],
            kind=data["kind"],
            planted_in=data.get("planted_in"),
            created_at=data.get("created_at", _utcnow()),
            note=data.get("note", ""),
        )


class _TokenRng:
    """Draws token characters from `secrets`, or deterministically from a seed."""

    def __init__(self, seed: int | None) -> None:
        self._seeded = random.Random(seed) if seed is not None else None

    def hex(self, n: int) -> str:
        if self._seeded is not None:
            return "".join(self._seeded.choice(_HEX) for _ in range(n))
        return secrets.token_hex(n)[:n]

    def digits(self, n: int) -> str:
        if self._seeded is not None:
            return "".join(self._seeded.choice(_DIGITS) for _ in range(n))
        return "".join(str(secrets.randbelow(10)) for _ in range(n))

    def choice(self, seq: tuple[str, ...]) -> str:
        if self._seeded is not None:
            return self._seeded.choice(seq)
        return secrets.choice(seq)


def _build_token(kind: str, rng: _TokenRng) -> str:
    if kind == "api_key":
        return f"sk-canary-{rng.hex(16)}"
    if kind == "aws_key":
        # Shaped like an AWS access key id, but the dash after AKIA breaks
        # the partner regex, and CANARY sits in the middle in plain sight.
        return f"AKIA-CANARY-{rng.hex(8).upper()}"
    if kind == "github_token":
        return f"github-canary-{rng.hex(32)}"
    if kind == "oauth_token":
        return f"oauth-canary-{rng.hex(24)}"
    if kind == "db_conn_string":
        return f"postgresql://svc:canary-db-{rng.hex(8)}@db.example-corp.internal:5432/appdb"
    if kind == "email":
        return f"canary+{rng.hex(6)}@example-corp.internal"
    if kind == "ssn":
        # 900-xx-xxxx is never issued by the SSA.
        return f"900-{rng.digits(2)}-{rng.digits(4)}-canary"
    if kind == "slack_token":
        # Deliberately not xoxb-: that prefix trips GitHub push protection
        # in any repo the token lands in.
        return f"slack-canary-{rng.hex(24)}"
    if kind == "internal_memo":
        return f"CANARY MEMO {rng.digits(2)}: project {rng.choice(_MEMO_CODEWORDS)}"
    if kind == "webhook_url":
        return f"https://hooks.example-corp.internal/canary/{rng.hex(16)}"
    if kind == "jwt_token":
        # Shaped like a JWT (header.payload.signature) but the signature
        # segment is literally "canary-sig-...", so no real JWT parser
        # will validate it and the marker stays in plain sight.
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "sub": "canary-svc",
                        "aud": "example-corp.internal",
                        "jti": rng.hex(8),
                    }
                ).encode()
            )
            .decode()
            .rstrip("=")
        )
        return f"{header}.{payload}.canary-sig-{rng.hex(16)}"
    if kind == "credit_card":
        # Starts like a Stripe test card, but the non-digit "canary"
        # segment means it can never be a real PAN.
        return f"4111-canary-1111-{rng.digits(4)}"
    if kind == "private_key":
        # The CANARY in the armor headers means no PEM parser accepts
        # this. Multiline on purpose: it exercises the scanner (and your
        # chunker) across line breaks.
        body = "\n".join(rng.hex(48) for _ in range(4))
        return f"-----BEGIN CANARY PRIVATE KEY-----\n{body}\n-----END CANARY PRIVATE KEY-----"
    raise ValueError(f"unknown canary kind: {kind!r}")


def _generate(n: int, kinds: list[str], rng: _TokenRng, banned: set[str]) -> list[Canary]:
    """Build `n` unique canaries, skipping any token in `banned`."""
    canaries: list[Canary] = []
    seen_tokens: set[str] = set()
    seen_ids: set[str] = set()
    for i in range(n):
        kind = kinds[i % len(kinds)]
        token = _build_token(kind, rng)
        while token in seen_tokens or token in banned:
            token = _build_token(kind, rng)
        seen_tokens.add(token)
        canary_id = f"canary-{rng.hex(8)}"
        while canary_id in seen_ids:
            canary_id = f"canary-{rng.hex(8)}"
        seen_ids.add(canary_id)
        canaries.append(Canary(id=canary_id, token=token, kind=kind))
    return canaries


def _checked_kinds(kinds: list[str] | None) -> list[str]:
    kinds = list(kinds) if kinds else list(CANARY_KINDS)
    unknown = [k for k in kinds if k not in CANARY_KINDS]
    if unknown:
        raise ValueError(f"unknown canary kinds: {', '.join(unknown)}")
    return kinds


def generate_canaries(
    n: int, kinds: list[str] | None = None, seed: int | None = None
) -> list[Canary]:
    """Generate `n` unique canary tokens.

    `kinds` selects a subset of the thirteen canary kinds; the default
    uses all of them, cycling round-robin so the mix stays even. `seed`
    makes the output fully deterministic (same seed, same tokens, same
    ids).

    Every token contains the literal marker "canary". Uniqueness is
    guaranteed: on the (astronomically unlikely) event of a collision the
    token is regenerated.
    """
    if n < 1:
        raise ValueError("n must be at least 1")
    return _generate(n, _checked_kinds(kinds), _TokenRng(seed), set())


def rotate_canaries(
    old_canaries: list[Canary],
    n: int,
    kinds: list[str] | None = None,
    seed: int | None = None,
) -> list[Canary]:
    """Generate `n` fresh canaries that do not reuse any old token.

    Rotation is how you keep a canary set honest: once a set may have
    been seen (in a benchmark, in a shared doc, in an incident), retire
    it and plant a fresh one. The returned tokens are guaranteed to
    differ from every token in `old_canaries`, so the old set cannot
    shadow the new one in scans.
    """
    if n < 1:
        raise ValueError("n must be at least 1")
    banned = {c.token for c in old_canaries}
    return _generate(n, _checked_kinds(kinds), _TokenRng(seed), banned)
