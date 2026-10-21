# Rotation scheduling

A canary set is only trustworthy while it is fresh. Once a set may have
been seen (in a benchmark, a shared doc, an incident thread), its tokens
stop being a secret, and an attacker who knows them can strip them.
`rotate` makes a fresh set. This page is about knowing when to run it.

## The schedule

A set ages from its oldest token. `rotation-status` reads the
`created_at` stamp on every canary in the set, takes the oldest one as
the anchor, and adds your interval:

```bash
$ rag-canary rotation-status --canaries canaries.json --interval-days 30
rotation: 19 canaries, oldest created 2026-10-01T12:00:00+00:00
schedule: every 30 days, warning 7 days ahead
next rotation due: 2026-10-31T12:00:00+00:00
state: current, 28 day(s) left.
```

Three states:

| State | Meaning | Exit code |
|---|---|---|
| `current` | Outside the warning window. Nothing to do. | 0 |
| `due_soon` | Inside the warning window (default: last 7 days). Plan the rotation. | 0 |
| `overdue` | Past the due date. Rotate now. | 1 |

The exit code is the point. A scheduled job that runs this check fails
loudly when a set goes overdue, the same way a tripped scan fails a
pipeline. From Python:

```python
from rag_canary import generate_canaries, rotation_status

status = rotation_status(canaries, interval_days=30, warning_days=7)
print(status.state, status.due_at, status.days_until_due)
if status.should_rotate:
    print("rotate this set")
```

## Putting it on a schedule

The library does not run a daemon and does not send reminders. Bring
your own scheduler. A weekly GitHub Actions check:

```yaml
name: canary-rotation
on:
  schedule:
    - cron: "0 9 * * 1"
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: pip install rag-canary
      - run: rag-canary rotation-status --canaries canaries.json --interval-days 30
```

When it fires: run `rag-canary rotate`, replant the corpus with the
fresh set, run `rag-canary verify`, and keep scanning for the old
tokens for a grace period. An attacker holding a stale document can
still leak it, and the old canary is how you would know.

## Picking an interval

Thirty days is a sane default for a set that lives in internal docs.
Shorten it when the set travels: a set pasted into a shared benchmark
or a vendor ticket should rotate the same week, not on the calendar.
Lengthen it only when the set is well contained and replanting is
expensive. The interval is a risk call, not a magic number.

## Honest limits

- This is a clock check. It reads timestamps and compares them to now.
  A set built with backdated stamps gets the schedule those stamps
  imply.
- `due_soon` never fails a job on its own. If you want the warning to
  page someone, wire the JSON output (`--format json`) into your own
  alerting.
- Rotating the tokens does not rotate the documents. Replanting and
  verifying are separate steps, and skipping them leaves the new set
  in a file while the corpus still carries the old one.
