"""Verify planted canaries survived in the corpus.

Planting is string surgery, and corpora go through chunkers,
normalizers, and re-indexing before they reach retrieval. Any of those
steps can mangle or drop a token: a chunker might split it across
chunks, a normalizer might strip the PEM armor lines, a dedup pass
might delete the honeypot doc. A canary that did not survive is a
tripwire that will never trip.

`verify_planted` checks every canary against the planted documents and
reports which tokens are still findable and which are not. Run it after
planting, and again after any pipeline change that touches document
text. The CLI wraps it:

    rag-canary verify --docs planted.jsonl --canaries canaries.json --manifest manifest.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .canary import Canary


@dataclass
class VerifyReport:
    """The result of checking planted canaries against planted documents."""

    checked: int = 0
    found: int = 0
    missing: list[dict] = field(default_factory=list)

    def ok(self) -> bool:
        """True when every checked canary was found in its document."""
        return not self.missing

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "found": self.found,
            "missing": self.missing,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def summary(self) -> str:
        lines = [f"verify: {self.found}/{self.checked} canaries present"]
        if not self.missing:
            lines.append("All planted canaries survived. The tripwire is live.")
            return "\n".join(lines)
        lines.append("")
        lines.append("MISSING:")
        for entry in self.missing:
            lines.append(f"  {entry['canary_id']} ({entry['kind']}) - {entry['reason']}")
        return "\n".join(lines)


def verify_planted(
    docs: list[dict],
    canaries: list[Canary],
    manifest: dict | None = None,
) -> VerifyReport:
    """Check that every canary token is still present in its planted document.

    `docs` is a list of {"id", "text"} dicts (the planted corpus).
    Each canary's `planted_in` names its document; when that is empty,
    the manifest (from `plant_canaries`) is consulted instead. A canary
    with no recorded planting location is reported missing with that
    reason, not silently skipped.
    """
    manifest = manifest or {}
    by_id = {doc.get("id"): doc for doc in docs if isinstance(doc, dict)}
    report = VerifyReport()
    for canary in canaries:
        report.checked += 1
        doc_id = canary.planted_in
        if not doc_id:
            entry = manifest.get(canary.id, {})
            doc_id = entry.get("doc_id")
        if not doc_id:
            report.missing.append(
                {
                    "canary_id": canary.id,
                    "kind": canary.kind,
                    "doc_id": None,
                    "reason": "no planting location recorded",
                }
            )
            continue
        doc = by_id.get(doc_id)
        if doc is None:
            report.missing.append(
                {
                    "canary_id": canary.id,
                    "kind": canary.kind,
                    "doc_id": doc_id,
                    "reason": f"document {doc_id!r} not in corpus",
                }
            )
            continue
        text = doc.get("text", "")
        if canary.token and canary.token in text:
            report.found += 1
        else:
            report.missing.append(
                {
                    "canary_id": canary.id,
                    "kind": canary.kind,
                    "doc_id": doc_id,
                    "reason": "token not found in document text",
                }
            )
    return report
