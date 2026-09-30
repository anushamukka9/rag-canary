# Canary kinds

Thirteen kinds, one rule: every token contains the literal marker `canary`
(case-insensitive). That marker is the entire safety story. No real
credential contains it, so a canary can never be confused with one, by a
person or by a scanner.

| Kind | Token shape | Why it is safe |
|---|---|---|
| `api_key` | `sk-canary-<16 hex>` | Marked; not a Stripe live key |
| `aws_key` | `AKIA-CANARY-<8 hex>` | The dash after `AKIA` breaks the partner regex `AKIA[0-9A-Z]{16}` |
| `github_token` | `github-canary-<32 hex>` | No `ghp_`/`gho_`/`github_pat_` prefix |
| `oauth_token` | `oauth-canary-<24 hex>` | Marked; vendor-neutral shape |
| `db_conn_string` | `postgresql://svc:canary-db-<8 hex>@db.example-corp.internal:5432/appdb` | Points at a reserved `.internal` host that does not exist |
| `email` | `canary+<6 hex>@example-corp.internal` | Reserved domain; plus-addressed marker |
| `ssn` | `900-<2 digits>-<4 digits>-canary` | 900-xx-xxxx is never issued by the SSA |
| `slack_token` | `slack-canary-<24 hex>` | Deliberately not `xoxb-`; that prefix trips GitHub push protection |
| `internal_memo` | `CANARY MEMO <2 digits>: project <codeword>` | Plainly labeled; reads like a filing reference |
| `webhook_url` | `https://hooks.example-corp.internal/canary/<16 hex>` | Reserved host; marker in the path |
| `jwt_token` | `<jwt header>.<base64url payload>.canary-sig-<16 hex>` | The signature segment is literally `canary-sig-...`; no JWT parser validates it |
| `credit_card` | `4111-canary-1111-<4 digits>` | Non-digit `canary` segment; can never be a real PAN |
| `private_key` | `-----BEGIN CANARY PRIVATE KEY-----` multiline block | `CANARY` in the armor headers; no PEM parser accepts it |

A few design notes:

- **Close to real, never real.** The shapes are close enough to the real
  thing that they survive being copied into attacker output, which is the
  whole point. The marker keeps them fake.
- **The `xoxb-` ban is load-bearing.** GitHub push protection flags the
  Slack `xoxb-` prefix in any repo it lands in, including benchmark
  fixtures and docs. `slack-canary-` scans clean.
- **SSNs stay in the 900 range.** The Social Security Administration never
  issues numbers starting with 9, so a `900-xx-xxxx` token cannot collide
  with a real person's number.
- **Hosts stay in `.internal`.** Connection strings and webhook URLs point
  at `example-corp.internal`, a reserved-style domain that does not resolve.
  A leaked canary URL is a dead end.
- **The private key is multiline on purpose.** The 4-line hex body
  exercises your chunker across line breaks: if your pipeline splits on
  newlines, the token still has to survive. Run `rag-canary verify`
  after any chunking change; a split token is a dead tripwire.

## Adding a kind

1. Pick a shape that is close to the real credential format.
2. Check it against the partner patterns your scanners match (AWS,
   GitHub, Slack, Stripe). If a pattern can match your shape, reshape it
   until it cannot.
3. Make sure the literal `canary` marker survives in the token.
4. Add the builder in `src/rag_canary/canary.py`, a shape test in
   `tests/test_canary.py`, and a row in this table.
