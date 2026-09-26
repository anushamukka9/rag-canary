# Contributing

Bug reports and pull requests are welcome. A few ground rules so the
project stays small and honest.

## What belongs here

- New canary kinds for real credential formats, with tests and a safety
  review of the token shape against partner secret patterns.
- Better planting strategies, as long as the manifest stays exact.
- Docs fixes and clearer guidance.

## What does not

- Anything that calls a model or the network at scan time. Deterministic
  is the whole point.
- "Detection" that depends on exact tokens surviving paraphrase. Substring
  matching is the documented contract; do not pretend it is more.

## How to contribute

1. Fork, branch off `develop`, and keep the change focused.
2. Add tests in `tests/` and a labeled case in `benchmarks/` if you touch
   scanning. Run `pytest -q` and `python -m rag_canary.benchmark`; both
   must be green, and the README benchmark table must match the new
   numbers.
3. Run `ruff check src tests` and `ruff format --check src tests`.
4. Every new canary kind must contain the literal `canary` marker and must
   not match a partner secret pattern (AWS, GitHub, Slack, Stripe).
   Document the shape in `docs/canary-kinds.md`.
5. Open a PR against `develop` with a plain description of what changed
   and why.

## Style

- No em-dashes anywhere. Not in code, not in docs, not in commit messages.
- Line length 100, enforced by ruff.
- Findings explain the problem in plain language. A leak report is read
  during an incident; write it like one.
