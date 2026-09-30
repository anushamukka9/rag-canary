"""Scan text for canary tokens.

Matching is exact substring search. That is deliberate: a canary that an
attacker copied verbatim is found with zero false positives, and the scan
runs in milliseconds with no model calls. It is also the honest
limitation to keep in mind. An attacker who paraphrases around the token,
strips it, or base64-encodes the exfiltrated documents will not trip
plain substring matching; pass detect_encoded=True to also catch tokens
hidden behind base64 or hex encoding. See the README's honest
limitations; canaries detect, they do not prevent.

`scan_text` returns one `Leak` per canary found (first occurrence), with a
context window around the hit so you can see how it leaked. `scan_files`
reads files (UTF-8 with replacement for undecodable bytes, so messy logs
do not crash the scan) and scans each one.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from .canary import Canary

SNIPPET_RADIUS = 60


@dataclass
class Leak:
    """One canary token found in scanned text.

    `encoding` is "verbatim" when the token appeared as-is, or "base64"
    / "hex" when it was found in encoded form (only when scanning with
    detect_encoded=True).
    """

    canary_id: str
    kind: str
    planted_in: str | None
    snippet: str
    encoding: str = "verbatim"


def _snippet(text: str, start: int, token_len: int) -> str:
    lo = max(0, start - SNIPPET_RADIUS)
    hi = start + token_len + SNIPPET_RADIUS
    return text[lo:hi].strip()


def _encodings(token: str) -> list[tuple[str, str]]:
    """(encoding name, encoded form) pairs to search for.

    Attackers sometimes base64- or hex-encode exfiltrated text. The
    encoded forms are long and random-looking, so searching for them is
    as safe as searching for the token itself. Base64 padding is
    optional: both the padded and unpadded forms are searched.
    """
    raw = token.encode("utf-8")
    forms: list[tuple[str, str]] = []
    padded = base64.b64encode(raw).decode("ascii")
    forms.append(("base64", padded))
    unpadded = padded.rstrip("=")
    if unpadded != padded:
        forms.append(("base64", unpadded))
    hexed = raw.hex()
    forms.append(("hex", hexed))
    upper = hexed.upper()
    if upper != hexed:
        forms.append(("hex", upper))
    return forms


def scan_text(text: str, canaries: list[Canary], detect_encoded: bool = False) -> list[Leak]:
    """Scan one string for canary tokens. Returns a list of Leak.

    With detect_encoded=True, tokens hidden behind base64 or hex
    encoding are also reported (Leak.encoding says which). Verbatim
    matches take precedence: a token found as-is is reported once, as
    verbatim.
    """
    leaks = []
    for canary in canaries:
        if not canary.token:
            continue
        idx = text.find(canary.token)
        if idx >= 0:
            leaks.append(
                Leak(
                    canary_id=canary.id,
                    kind=canary.kind,
                    planted_in=canary.planted_in,
                    snippet=_snippet(text, idx, len(canary.token)),
                    encoding="verbatim",
                )
            )
            continue
        if detect_encoded:
            for encoding, form in _encodings(canary.token):
                pos = text.find(form)
                if pos >= 0:
                    leaks.append(
                        Leak(
                            canary_id=canary.id,
                            kind=canary.kind,
                            planted_in=canary.planted_in,
                            snippet=_snippet(text, pos, len(form)),
                            encoding=encoding,
                        )
                    )
                    break
    return leaks


def scan_files(paths: list, canaries: list[Canary], detect_encoded: bool = False) -> list[Leak]:
    """Scan files for canary tokens. Returns a flat list of Leak."""
    leaks: list[Leak] = []
    for path in paths:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        leaks.extend(scan_text(text, canaries, detect_encoded=detect_encoded))
    return leaks
