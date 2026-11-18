"""HTML detection reports: single static file, no dependencies.

The Markdown and JSON reports are good for tickets and pipelines. The
HTML report is the one you send to a person: open it in any browser,
no server, no build step, no external assets. All CSS is inline in
the file and every dynamic value is escaped, so a snippet that
contains markup cannot break out of the report or inject into it.

Severity is a triage aid, not a verdict. It is assigned per canary
kind by what a real version of that credential would give an
attacker:

- critical: private keys, database connection strings, and cloud
  secret keys. Direct access, no further steps.
- high: API keys and OAuth or platform tokens. Usable as-is against
  an API, usually scoped but real.
- medium: card numbers, SSNs, and webhook URLs. Sensitive data or a
  narrower channel, not a login by itself.
- low: email addresses and internal memos. Identifiers and internal
  context, no credential attached.

A report's overall severity is the highest severity among its hits,
or "none" when nothing tripped. Counts are reported per severity so
a reader can see the shape at a glance instead of reading every hit.
"""

from __future__ import annotations

import html

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

SEVERITY_BY_KIND: dict[str, str] = {
    "private_key": "critical",
    "db_conn_string": "critical",
    "mysql_conn_string": "critical",
    "mongodb_conn_string": "critical",
    "redis_conn_string": "critical",
    "aws_secret_key": "critical",
    "aws_key": "critical",
    "api_key": "high",
    "github_token": "high",
    "oauth_token": "high",
    "oauth_refresh_token": "high",
    "jwt_token": "high",
    "slack_token": "high",
    "credit_card": "medium",
    "ssn": "medium",
    "webhook_url": "medium",
    "email": "low",
    "internal_memo": "low",
    "tracked_memo": "low",
}

DEFAULT_SEVERITY = "medium"

_CSS = """
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 880px;
  padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.15rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left;
  vertical-align: top; }
th { background: #f2f2f2; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.5rem;
  font-size: 0.8rem; font-weight: 600; color: #fff; }
.sev-critical { background: #b00020; } .sev-high { background: #d35400; }
.sev-medium { background: #9a7b00; } .sev-low { background: #555; }
.sev-none { background: #2e7d32; }
.prompt, .snippet { background: #f7f7f7; border: 1px solid #ddd;
  padding: 0.6rem 0.8rem; white-space: pre-wrap; word-break: break-word; }
.meta { color: #555; }
""".strip()


def severity_for_kind(kind: str) -> str:
    """Severity for one canary kind. Unknown kinds default to medium."""
    return SEVERITY_BY_KIND.get(kind, DEFAULT_SEVERITY)


def severity_summary(leaks: list) -> dict[str, int]:
    """Count hits per severity, in severity order, plus a total."""
    summary = {name: 0 for name in SEVERITIES}
    for leak in leaks:
        summary[severity_for_kind(leak.kind)] += 1
    summary["total"] = len(leaks)
    return summary


def overall_severity(leaks: list) -> str:
    """Highest severity present, or "none" for a clean scan."""
    for name in SEVERITIES:
        if any(severity_for_kind(leak.kind) == name for leak in leaks):
            return name
    return "none"


def _badge(severity: str) -> str:
    return f'<span class="badge sev-{severity}">{severity}</span>'


def _summary_table(leaks: list) -> str:
    summary = severity_summary(leaks)
    rows = "".join(
        f"<tr><td>{_badge(name)}</td><td>{summary[name]}</td></tr>" for name in SEVERITIES
    )
    return (
        "<h2>Severity summary</h2><table><tr><th>Severity</th><th>Hits</th></tr>"
        f"{rows}<tr><td>Total</td><td>{summary['total']}</td></tr></table>"
    )


def _hits_table(leaks: list) -> str:
    if not leaks:
        return "<p>No canaries found. Nothing leaked, or nothing was scanned.</p>"
    rows = []
    for leak in sorted(leaks, key=lambda item: (item.canary_id, item.kind)):
        severity = severity_for_kind(leak.kind)
        where = html.escape(leak.planted_in) if leak.planted_in else "unknown"
        encoding = html.escape(leak.encoding)
        rows.append(
            "<tr>"
            f"<td>{_badge(severity)}</td>"
            f"<td>{html.escape(leak.canary_id)}</td>"
            f"<td>{html.escape(leak.kind)}</td>"
            f"<td>{where}</td>"
            f"<td>{encoding}</td>"
            f"<td><div class='snippet'>{html.escape(leak.snippet)}</div></td>"
            "</tr>"
        )
    head = (
        "<tr><th>Severity</th><th>Canary</th><th>Kind</th>"
        "<th>Planted in</th><th>Encoding</th><th>Snippet</th></tr>"
    )
    return f"<table>{head}{''.join(rows)}</table>"


def _page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n<html lang='en'><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body>{body}</body></html>\n"
    )


def render_leak_report_html(report, prompt: str | None = None) -> str:
    """Render one LeakReport as a standalone HTML page.

    `prompt`, when given, is shown as the prompt that carried the
    canaries out. That is the attack-simulation case: the report
    answers which canaries fired and which prompt did it.
    """
    title = "rag-canary detection report"
    if report.label:
        title += f": {report.label}"
    counts = report.counts()
    overall = overall_severity(report.leaks)
    parts = [f"<h1>{html.escape(title)}</h1>"]
    parts.append(
        f"<p class='meta'>{counts['leaks']} leak(s) across "
        f"{counts['canaries_hit']} canary(ies). Overall severity: "
        f"{_badge(overall)}</p>"
    )
    if prompt is not None:
        parts.append("<h2>Prompt that carried them out</h2>")
        parts.append(f"<div class='prompt'>{html.escape(prompt)}</div>")
    parts.append(_summary_table(report.leaks))
    parts.append("<h2>Canaries that fired</h2>")
    parts.append(_hits_table(report.leaks))
    parts.append(
        "<p class='meta'>Severity is assigned per canary kind by what a "
        "real version of that credential would give an attacker. It is a "
        "triage aid, not a verdict. Canaries detect, they do not "
        "prevent.</p>"
    )
    return _page(title, "".join(parts))


def render_attack_report_html(
    control_query: str,
    control_leaks: list,
    attacks: list,
    total_canaries: int,
    total_docs: int,
) -> str:
    """Render the attack-simulation battery as one HTML page.

    `attacks` is a list of (name, query, leaks) triples, in run order.
    Each attack gets its own section: the prompt verbatim, the
    severity summary for that attack, and the table of canaries it
    carried out. The control comes first so a clean control is
    visible before any attack result.
    """
    title = "rag-canary attack simulation: detection report"
    all_leaks = list(control_leaks) + [leak for _, _, leaks in attacks for leak in leaks]
    tripped = sum(1 for _, _, leaks in attacks if leaks)
    parts = [f"<h1>{html.escape(title)}</h1>"]
    parts.append(
        f"<p class='meta'>{total_canaries} canaries planted across "
        f"{total_docs} docs. Attacks run: {len(attacks)}, attacks that "
        f"tripped the wire: {tripped}. Overall severity: "
        f"{_badge(overall_severity(all_leaks))}</p>"
    )
    parts.append(_summary_table(all_leaks))
    parts.append("<h2>Control: clean question</h2>")
    parts.append(f"<div class='prompt'>{html.escape(control_query)}</div>")
    parts.append(f"<p>Canaries tripped: {len(control_leaks)} (expected 0)</p>")
    if control_leaks:
        parts.append(_hits_table(list(control_leaks)))
    for name, query, leaks in attacks:
        parts.append(f"<h2>Attack: {html.escape(name)}</h2>")
        parts.append("<h3>Prompt that carried them out</h3>")
        parts.append(f"<div class='prompt'>{html.escape(query)}</div>")
        parts.append(
            f"<p>{len(leaks)} canary(ies) fired. Overall severity for "
            f"this attack: {_badge(overall_severity(list(leaks)))}</p>"
        )
        parts.append(_summary_table(list(leaks)))
        parts.append("<h3>Canaries that fired</h3>")
        parts.append(_hits_table(list(leaks)))
    parts.append(
        "<p class='meta'>Honest limitation: the mock model in this demo "
        "quotes documents because the script told it to. A real model "
        "exfiltrates for its own reasons, and an attacker who "
        "paraphrases around the token, strips it, or re-encodes the "
        "documents will not trip substring matching. Canaries detect, "
        "they do not prevent.</p>"
    )
    return _page(title, "".join(parts))
