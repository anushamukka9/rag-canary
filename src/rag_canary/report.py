"""Leak reports: counts and per-canary hits, as JSON or Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .scan import Leak


@dataclass
class LeakReport:
    """A scan result. `label` names the scan (a filename, a date, a run id)."""

    leaks: list[Leak] = field(default_factory=list)
    label: str = ""

    def counts(self) -> dict:
        canary_ids = sorted({leak.canary_id for leak in self.leaks})
        kinds = sorted({leak.kind for leak in self.leaks})
        docs = sorted({leak.planted_in for leak in self.leaks if leak.planted_in})
        return {
            "leaks": len(self.leaks),
            "canaries_hit": len(canary_ids),
            "kinds_hit": kinds,
            "docs_hit": docs,
        }

    def hits_by_canary(self) -> dict[str, list[Leak]]:
        grouped: dict[str, list[Leak]] = {}
        for leak in self.leaks:
            grouped.setdefault(leak.canary_id, []).append(leak)
        return grouped

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "counts": self.counts(),
            "leaks": [
                {
                    "canary_id": leak.canary_id,
                    "kind": leak.kind,
                    "planted_in": leak.planted_in,
                    "encoding": leak.encoding,
                    "snippet": leak.snippet,
                }
                for leak in self.leaks
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        counts = self.counts()
        title = "# rag-canary leak report"
        if self.label:
            title += f": {self.label}"
        lines = [title, ""]
        lines.append(f"{counts['leaks']} leak(s) across {counts['canaries_hit']} canary(ies).")
        if not self.leaks:
            lines.append("")
            lines.append("No canaries found. Nothing leaked, or nothing was scanned.")
            return "\n".join(lines) + "\n"
        lines.append("")
        for canary_id, hits in self.hits_by_canary().items():
            first = hits[0]
            if first.planted_in:
                where = f"planted in `{first.planted_in}`"
            else:
                where = "planting location unknown"
            encodings = sorted({hit.encoding for hit in hits if hit.encoding != "verbatim"})
            suffix = f" ({', '.join(encodings)}-encoded)" if encodings else ""
            lines.append(f"## {canary_id} ({first.kind}){suffix}")
            lines.append(f"{where} - {len(hits)} hit(s)")
            lines.append("")
            for hit in hits:
                for snippet_line in hit.snippet.splitlines():
                    lines.append(f"> {snippet_line}".rstrip())
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"
