"""Plant canaries in a document corpus.

Two strategies:

- "inline": distributes canaries across your existing documents, appending
  one natural-sounding sentence per canary. The sentence reads like
  ordinary documentation, so the token survives retrieval and quotation.
- "dedicated": creates new fake documents (a "vendor staging credentials"
  note and friends), each holding several canaries. Good when you do not
  want to touch real documents, or when you want a honeypot doc that no
  legitimate query should ever retrieve.

Returns (planted_docs, manifest). `planted_docs` is a fresh list of
{"id", "text"} dicts; your input docs are never mutated. `manifest` maps
each canary id to {"doc_id", "position"}, where position is the character
offset of the token inside the planted document text. Each canary's
`planted_in` field is also set, which is what `scan_text` reports back.

Limitation, stated plainly: planting is string surgery. It does not
understand your chunker. If your pipeline splits documents into chunks,
plant near the sentences you expect to be retrieved, and verify the token
survives chunking before you rely on it.
"""

from __future__ import annotations

import random

from .canary import Canary

_INLINE_SENTENCES = {
    "api_key": (
        "The temporary integration key for the staging rollout is {token}; "
        "it expires after the demo and gets rotated."
    ),
    "aws_key": ("Staging bucket access uses {token}; keep it out of the production configs."),
    "github_token": (
        "The docs preview pipeline authenticates with {token} until the migration finishes."
    ),
    "oauth_token": (
        "The legacy dashboard still logs in with {token} while SSO is being rolled out."
    ),
    "db_conn_string": ("The analytics replica is reachable at {token}; it is read-only."),
    "email": ("Send the rollout checklist to {token} so it lands in the staging inbox."),
    "ssn": (
        "The synthetic payroll record for the demo employee lists SSN {token}; "
        "it is not a real person."
    ),
    "slack_token": (
        "Deploy notifications post with {token}; the channel gets archived after launch."
    ),
    "internal_memo": "File the quarterly review under {token}.",
    "webhook_url": ("Build notifications go to {token} until the new pipeline is live."),
    "jwt_token": ("The staging service authenticates with {token}; the signature is a dummy."),
    "credit_card": ("The demo checkout uses test card {token}; it cannot be charged."),
    "private_key": (
        "The sandbox signs nightly artifacts with:\n{token}\nRotate it before go-live."
    ),
}

_DEDICATED_LABELS = {
    "api_key": "Staging API key",
    "aws_key": "Staging AWS access key",
    "github_token": "Docs preview token",
    "oauth_token": "Legacy dashboard token",
    "db_conn_string": "Analytics replica",
    "email": "Staging inbox",
    "ssn": "Demo payroll SSN",
    "slack_token": "Deploy notifier token",
    "internal_memo": "Filing reference",
    "webhook_url": "Build webhook",
    "jwt_token": "Staging service JWT",
    "credit_card": "Demo test card",
    "private_key": "Sandbox signing key",
}

_DEDICATED_BATCH_SIZE = 4


def _checked_docs(docs: list[dict]) -> list[dict]:
    """Copy docs and validate the {"id", "text"} shape."""
    checked = []
    seen_ids: set[str] = set()
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            raise ValueError(f"doc at index {i} must be a dict with 'id' and 'text'")
        doc_id = doc.get("id")
        text = doc.get("text")
        if not isinstance(doc_id, str) or not doc_id:
            raise ValueError(f"doc at index {i} needs a non-empty string 'id'")
        if not isinstance(text, str):
            raise ValueError(f"doc {doc_id!r} needs a string 'text'")
        if doc_id in seen_ids:
            raise ValueError(f"duplicate doc id: {doc_id!r}")
        seen_ids.add(doc_id)
        checked.append({"id": doc_id, "text": text})
    return checked


def _plant_inline(
    docs: list[dict], canaries: list[Canary], manifest: dict, rng: random.Random
) -> None:
    if not docs:
        raise ValueError("inline planting needs at least one document")
    order = list(range(len(docs)))
    rng.shuffle(order)
    for i, canary in enumerate(canaries):
        doc = docs[order[i % len(docs)]]
        sentence = _INLINE_SENTENCES[canary.kind].format(token=canary.token)
        prefix = doc["text"] + " " if doc["text"] else ""
        position = len(prefix) + sentence.index(canary.token)
        doc["text"] = prefix + sentence
        canary.planted_in = doc["id"]
        manifest[canary.id] = {"doc_id": doc["id"], "position": position}


def _plant_dedicated(
    docs: list[dict], canaries: list[Canary], manifest: dict, rng: random.Random
) -> None:
    del rng  # dedicated planting is order-stable by design
    existing_ids = {doc["id"] for doc in docs}
    counter = 1
    for start in range(0, len(canaries), _DEDICATED_BATCH_SIZE):
        batch = canaries[start : start + _DEDICATED_BATCH_SIZE]
        doc_id = f"vendor-staging-note-{counter}"
        while doc_id in existing_ids:
            counter += 1
            doc_id = f"vendor-staging-note-{counter}"
        existing_ids.add(doc_id)
        counter += 1
        lines = [
            f"Vendor staging credentials ({doc_id})",
            "",
            "Shared by the vendor for the integration sandbox. These are",
            "staging-only credentials; rotate them before go-live.",
            "",
        ]
        for canary in batch:
            lines.append(f"{_DEDICATED_LABELS[canary.kind]}: {canary.token}")
        text = "\n".join(lines)
        for canary in batch:
            canary.planted_in = doc_id
            manifest[canary.id] = {"doc_id": doc_id, "position": text.index(canary.token)}
        docs.append({"id": doc_id, "text": text})


def plant_canaries(
    docs: list[dict],
    canaries: list[Canary],
    strategy: str = "inline",
    seed: int | None = None,
) -> tuple[list[dict], dict]:
    """Plant canaries in docs. Returns (planted_docs, manifest).

    `docs` is a list of {"id", "text"} dicts. `strategy` is "inline" or
    "dedicated". `seed` makes the inline distribution deterministic.

    The input docs are copied, never mutated. Each canary's `planted_in`
    is set to the document that received it. The manifest maps
    canary id -> {"doc_id": ..., "position": ...} with the exact character
    offset of the token in the planted text.
    """
    if strategy not in ("inline", "dedicated"):
        raise ValueError(f"unknown planting strategy: {strategy!r}")
    planted_docs = _checked_docs(docs)
    manifest: dict[str, dict] = {}
    if not canaries:
        return planted_docs, manifest
    rng = random.Random(seed)
    if strategy == "inline":
        _plant_inline(planted_docs, canaries, manifest, rng)
    else:
        _plant_dedicated(planted_docs, canaries, manifest, rng)
    return planted_docs, manifest
