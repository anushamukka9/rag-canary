# Canary design guide

A canary is only as good as its tripwire. This is the playbook for
choosing kinds, placing tokens, and keeping the set honest over time.

## Marker discipline

Every token contains the literal marker `canary` (case-insensitive).
That is the entire safety story, and it is non-negotiable:

- A canary must never be matchable by a real secret scanner. Break the
  partner patterns on purpose: no `ghp_`, no `xoxb-`, a dash after
  `AKIA`, `CANARY` in PEM armor headers, `900-xx-xxxx` SSNs that the SSA
  never issues.
- A canary must never be a real credential. `4111-canary-1111-...` has a
  non-digit segment, so it can never be a real PAN. `db_conn_string` and
  `webhook_url` point at `.internal` hosts that do not resolve.
- A canary must be close enough to the real thing to survive being
  copied into attacker output. A token that looks fake gets stripped;
  a token that looks plausible gets pasted.

The marker keeps it fake; the shape keeps it alive. See
[canary kinds](canary-kinds.md) for the full table.

## Kind selection

Pick kinds that fit the documents you are protecting:

- **Docs about auth and services:** `jwt_token`, `oauth_token`,
  `api_key`, `github_token`. A service account JWT planted in an
  on-call runbook is exactly the kind of thing an attacker pastes.
- **Docs about payments or demos:** `credit_card` (demo test card),
  `db_conn_string`.
- **Docs about people or HR:** `email`, `ssn` (900-range, never issued).
- **Ops docs:** `slack_token`, `webhook_url`, `internal_memo`.
- **Docs your chunker splits on newlines:** `private_key`. Its
  multiline body is the canary for your chunking pipeline: if the token
  stops surviving, `rag-canary verify` tells you.

A mixed set is better than a pure one. `generate` cycles kinds
round-robin so the mix stays even; `--kinds` narrows it when a corpus
only fits a few.

## Density and placement

- One canary per document is a reasonable default. Ten documents with
  one canary each beats one document with ten: a single exfiltrated
  document identifies itself.
- Plant inline (`strategy="inline"`) for documents a model would quote;
  dedicated honeypot documents (`strategy="dedicated"`) for broad
  sweeps.
- Plant near the facts an attacker wants, not in a boilerplate footer.
  A token next to the staging credentials is retrieved and quoted; a
  token in the copyright notice is not.

## Rotation

Rotate the set whenever it may have been seen: after a benchmark run
against a shared fixture, after an incident, or on a schedule.

    rag-canary rotate --old canaries.json -n 20 --seed 77 -o canaries-v2.json

`rotate` guarantees the fresh tokens do not overlap the old set, so the
old set cannot shadow the new one in scans. Keep the old tokens in your
scan set for a grace period (an attacker might exfiltrate a stale
document), then retire them.

## Secrecy

The tokens themselves are not sensitive (they are fake), but the
*mapping* of canary to document is. If an attacker knows which
documents hold canaries, they can strip them. Keep the manifest and the
planted corpus on the same access tier as the documents they protect.

## Testing the tripwire

A canary that did not survive planting is a tripwire that will never
trip. Run verify after planting and after any pipeline change that
touches document text:

    rag-canary plant --docs corpus.jsonl --canaries canaries.json \
      --manifest manifest.json -o planted.jsonl
    rag-canary verify --docs planted.jsonl --canaries canaries.json \
      --manifest manifest.json

Exit 0 means every token survived. Exit 1 names the missing ones with a
reason: mangled token, deleted document, or no planting location
recorded. The same check gates CI; see [ci-usage.md](ci-usage.md).
