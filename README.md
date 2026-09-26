# rag-canary

Canary tokens for RAG corpora. Plant fake secrets in your documents. When
a prompt-injection attack exfiltrates those documents, the attacker's
output contains your canaries. Scan model outputs or logs for the tokens
and the wire trips: you learn which documents leaked, not just that
something leaked.

Detection, not prevention. Pair it with a guardrail like
[llm-sentinel](https://github.com/anushamukka9/llm-sentinel).

## Why this exists

RAG systems hand the model your documents, and every retrieved document
is exfiltration surface. Prompt injection keeps getting better at talking
models into quoting those documents back. Prevention is a guardrail's
job. But I wanted the tripwire too: something that tells me after the
fact that a specific document left the building, so I can scope the
incident instead of guessing.

The idea is old. Banknote stacks have dye packs; databases have honey
tokens. This is the same trick for retrieval corpora: plant credentials
that are unmistakably fake, then watch for them where they should never
appear. Every token contains the literal marker `canary`, so it can never
be confused with a real secret, by a person or by a scanner. Read the
honest limitations before you trust it with anything important.

## Quickstart

```bash
pip install rag-canary
```

```bash
$ rag-canary generate -n 10 --seed 42 -o canaries.json
wrote 10 canaries to canaries.json

$ rag-canary plant --docs corpus.jsonl --canaries canaries.json --seed 42 \
    -o planted.jsonl --manifest manifest.json
wrote 24 planted docs to planted.jsonl
wrote manifest (10 canaries) to manifest.json

$ rag-canary scan --canaries canaries.json --manifest manifest.json model-output.txt

rag-canary scan: 1 file(s), 2 leak(s)

model-output.txt: 2 leak(s)
  [api_key] canary-9f2c4a1b (planted in doc-05)
    > The temporary integration key for the staging rollout is sk-canary-9f2c4a1b7d3e8f0a1; it expires...
  [email] canary-71bd00e3 (planted in doc-11)
    > Send the rollout checklist to canary+71bd00@example-corp.internal so it lands in the staging inbox...
```

A clean scan exits 0. A tripped canary exits 1, which is what you want in
CI: loud. Machine-readable output for pipelines:

```bash
rag-canary scan --canaries canaries.json --format json outputs/*.log > leak-report.json
rag-canary scan --canaries canaries.json --format markdown outputs/*.log  # paste into a ticket
```

Or from Python:

```python
from rag_canary import LeakReport, generate_canaries, plant_canaries, scan_text

canaries = generate_canaries(30, seed=42)
planted_docs, manifest = plant_canaries(docs, canaries, strategy="inline", seed=42)

leaks = scan_text(model_output, canaries)
report = LeakReport(leaks=leaks, label="2026-09-26 nightly")
print(report.to_markdown())
```

Try the bundled examples: `examples/sample_corpus.jsonl` (a small demo
corpus), `examples/plant_example.py` (plant and inspect), and
`examples/scan_example.py` (a simulated exfiltration and the scan that
catches it).

## Canary kinds

Ten kinds, one rule: every token contains the literal marker `canary`.
Shapes are close to the real thing so they survive being copied into
attacker output, but they break every partner pattern I know about.

| Kind | Shape |
|---|---|
| `api_key` | `sk-canary-<hex>` |
| `aws_key` | `AKIA-CANARY-<hex>` (the dash breaks the partner regex) |
| `github_token` | `github-canary-<hex>` (no `ghp_` prefix) |
| `oauth_token` | `oauth-canary-<hex>` |
| `db_conn_string` | `postgresql://svc:canary-db-<hex>@db.example-corp.internal:5432/appdb` |
| `email` | `canary+<hex>@example-corp.internal` |
| `ssn` | `900-<digits>-canary` (900-xx is never issued) |
| `slack_token` | `slack-canary-<hex>` (never `xoxb-`; that trips push protection) |
| `internal_memo` | `CANARY MEMO <n>: project <codeword>` |
| `webhook_url` | `https://hooks.example-corp.internal/canary/<hex>` |

See [docs/canary-kinds.md](docs/canary-kinds.md) for the full safety notes.
Planting strategies and the manifest are documented in
[docs/planting.md](docs/planting.md); scanning in
[docs/scanning.md](docs/scanning.md).

## Benchmarks

Fixtures under `benchmarks/`: a 24-doc synthetic corpus with 30 planted
canaries, 12 exfiltration outputs containing canaries verbatim (naive full
dumps, regurgitation as "helpful" answers, targeted Q&A), 8 benign
outputs, and 6 near-miss outputs with real-looking but non-canary secrets
(`sk-live-...`, the AWS documentation example key, and friends). Run them
yourself:

```bash
python -m rag_canary.benchmark
```

Results on the bundled set:

| Metric | Result |
|---|---|
| Recall on exfil set (12 attack outputs, 19 expected leaks) | 1.00 (19/19) |
| False-positive rate on benign + near-miss (14 outputs) | 0.00 (0/14) |
| Corpus self-check (planted canaries findable in corpus) | 30/30 |
| Scan latency | ~10 ms/MB (median of 5 runs on a 1 MB buffer; varies a little by machine) |

Take these numbers for what they are: a smoke test proving the scanner
fires on verbatim exfiltration and stays quiet on everything else, not a
security certification. The set is small and hand-written. Real attackers
are more creative than any labeled set. If you evaluate against your own
attack simulations, please contribute the cases back.

## CI usage

Scan yesterday's outputs on a schedule and fail loudly on a hit. See
[docs/ci-usage.md](docs/ci-usage.md) for copy-paste workflow snippets,
including a manifest-stability gate for corpus PRs.

## Honest limitations

- Canaries detect; they never prevent. The document still left. The
  canary just tells you which one.
- An attacker who knows the scheme can strip the markers or paraphrase
  around them. Secrecy of the canary set is load-bearing; rotate it.
- Base64 or otherwise encoded exfiltration evades substring matching.
  This scanner finds verbatim copies, nothing cleverer.
- You only catch what you scan. Output and log coverage is the real
  work; the scanner is the easy part.
- Planting is string surgery and does not know your chunker. Verify the
  token survives chunking before you rely on it.
- Do not over-plant. Hundreds of canaries train your own team to ignore
  the alerts, and that is how tripwires die.

## Roadmap

- Encoded-exfil detection (base64 and hex variants of planted tokens)
- Chunk-aware planting that verifies token survival through a chunker
- A hosted canary-set vault with rotation reminders
- Larger, community-sourced attack fixture sets

## License

MIT. See LICENSE.
