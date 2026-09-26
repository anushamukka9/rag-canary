"""Scan text for canary tokens.

Matching is exact substring search. That is deliberate: a canary that an
attacker copied verbatim is found with zero false positives, and the scan
runs in milliseconds with no model calls. It is also the honest
limitation to keep in mind. An attacker who paraphrases around the token,
strips it, or base64-encodes the exfiltrated documents will not trip
substring matching. See the README's honest limitations; canaries detect,
they do not prevent.

`scan_text` returns one `Leak` per canary found (first occurrence), with a
context window around the hit so you can see how it leaked. `scan_files`
reads files (UTF-8 with replacement for undecodable bytes, so messy logs
do not crash the scan) and scans each one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .canary import Canary

SNIPPET_RADIUS = 60


@dataclass
class Leak:
    """One canary token found in scanned text."""

    canary_id: str
    kind: str
    planted_in: str | None
    snippet: str


def _snippet(text: str, start: int, token_len: int) -> str:
    lo = max(0, start - SNIPPET_RADIUS)
    hi = start + token_len + SNIPPET_RADIUS
    return text[lo:hi].strip()


def scan_text(text: str, canaries: list[Canary]) -> list[Leak]:
    """Scan one string for canary tokens. Returns a list of Leak."""
    leaks = []
    for canary in canaries:
        if not canary.token:
            continue
        idx = text.find(canary.token)
        if idx < 0:
            continue
        leaks.append(
            Leak(
                canary_id=canary.id,
                kind=canary.kind,
                planted_in=canary.planted_in,
                snippet=_snippet(text, idx, len(canary.token)),
            )
        )
    return leaks


def scan_files(paths: list, canaries: list[Canary]) -> list[Leak]:
    """Scan files for canary tokens. Returns a flat list of Leak."""
    leaks: list[Leak] = []
    for path in paths:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        leaks.extend(scan_text(text, canaries))
    return leaks
