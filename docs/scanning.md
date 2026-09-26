# Scanning for leaks

Scanning is the other half of the tripwire. You planted the canaries;
now you watch the places exfiltrated text would surface.

## What to scan

- **Model outputs.** The direct case: scan every response your RAG system
  produces, or a sampled stream of them, before they reach the user.
- **Logs.** Application logs, chat transcripts, and audit trails. An
  attacker who exfiltrates documents often leaves the tokens in logs on
  the way out.
- **Egress captures.** If you mirror outbound traffic, scan the mirror.

The uncomfortable truth is that you only catch what you scan. Output and
log coverage is the real work; the scanner itself is the easy part.

## How it works

```python
from rag_canary import LeakReport, scan_files, scan_text

leaks = scan_text(model_output, canaries)
report = LeakReport(leaks=leaks, label="2026-09-26 nightly")
print(report.to_markdown())
```

Matching is exact substring search over the canary tokens. A token copied
verbatim is found with zero false positives, and the scan costs
milliseconds per megabyte with no model calls and no network. Each `Leak`
carries the canary id, its kind, where it was planted, and a snippet of
surrounding text so you can see how it leaked.

`scan_files` reads files as UTF-8 with replacement for undecodable bytes,
so messy logs do not crash the scan.

## Reports

`LeakReport` gives you counts (leaks, distinct canaries hit, kinds hit,
documents hit) and per-canary hits, as JSON or Markdown:

```python
report.to_json()      # machine-readable, for artifacts and dashboards
report.to_markdown()  # paste into an incident ticket or PR
```

## In a pipeline

Scan in the request path when latency allows (it is ~10 ms/MB), or scan
asynchronously off a log stream when it does not. Either way, alert on
the first hit: a single canary in output means a document left the
building. See [ci-usage](ci-usage.md) for the CI pattern.

## What scanning cannot do

Substring matching finds verbatim copies. It does not find a token the
attacker paraphrased around, stripped out, or base64-encoded. If your
threat model includes an attacker who knows the canary scheme, pair this
with output inspection that does not depend on exact tokens. Read the
honest limitations in the README before you trust a clean scan.
