# HTML detection reports

The Markdown report is for tickets. The JSON report is for pipelines.
The HTML report is for people: one static file you can attach to an
incident, email to a teammate, or open from a shared drive. No server,
no build step, no dependencies. All styling is inline in the file and
there are no external assets, so the file you save today opens the
same way next year.

## From a scan

```bash
rag-canary scan --canaries canaries.json --format html outputs/*.log > detection-report.html
```

Or from Python:

```python
from rag_canary import LeakReport

report = LeakReport(leaks=leaks, label="2026-11-18 nightly")
html_text = report.to_html(prompt=prompt_that_produced_the_output)
open("detection-report.html", "w", encoding="utf-8").write(html_text)
```

The `prompt` argument is optional. When you have it, pass it: the
report shows it in a section titled "Prompt that carried them out",
which is usually the first question an incident review asks.

## What is in the report

- A header with the label, the leak count, the number of distinct
  canaries hit, and the overall severity.
- A severity summary table: hits counted per severity, plus a total.
- A table of every canary that fired: severity, canary id, kind,
  the document it was planted in, the encoding it was found in
  (verbatim, base64, or hex), and the snippet around the hit.
- When a prompt is supplied, that prompt verbatim, escaped so it
  cannot break the page.

Every dynamic value is HTML-escaped before it goes into the page. A
snippet that contains markup shows up as text, never as live HTML.

## Severity

Severity is assigned per canary kind by what a real version of that
credential would give an attacker:

| Severity | Kinds |
|---|---|
| critical | private_key, db_conn_string, mysql_conn_string, mongodb_conn_string, redis_conn_string, aws_key, aws_secret_key |
| high | api_key, github_token, oauth_token, oauth_refresh_token, jwt_token, slack_token |
| medium | credit_card, ssn, webhook_url |
| low | email, internal_memo, tracked_memo |

An unknown kind defaults to medium. A report's overall severity is
the highest severity among its hits, or "none" when nothing tripped.

Read this as a triage aid, not a verdict. A low-severity canary in
output still means a document left the building. Severity only tells
you which fire to run to first.

## The attack-simulation report

The bundled attack simulation writes this report for the whole
battery:

```bash
python examples/attack-simulation/attack.py
# writes attack-log.md and detection-report.html
```

That page leads with the control (a clean question, zero trips),
then gives each attack its own section: the prompt verbatim, a
severity summary for that attack, and the table of canaries that
attack carried out. A checked-in copy sits at
`examples/attack-simulation/detection-report.html` so you can see
the shape without running anything.

## Honest limitations

- The report shows what the scanner found. It inherits every scanner
  limitation: verbatim copies, plus base64 and hex forms when encoded
  detection is on. Paraphrased or stripped tokens do not appear,
  because they were not found.
- Severity is a fixed per-kind table. It does not know your data.
  A memo canary in a harmless doc and a memo canary in a sensitive
  doc get the same low rating. Adjust your reading, not just the
  table.
- The file contains the snippets around each hit, which can include
  document text. Treat the report itself as sensitive and share it
  the way you would share an incident record.
