"""Rotation scheduling for canary sets.

`rotate_canaries` makes a fresh set. This module answers the prior
question: when should you rotate? A canary set ages from the moment its
oldest token was created, because that is the token that has had the
most time to be seen, copied into a benchmark, or pasted into a ticket.

`rotation_status` reads the `created_at` stamps on a set and reports
where it sits against a simple schedule: rotate every `interval_days`,
start warning `warning_days` before the deadline. The result is one of
three states: "current", "due_soon", or "overdue". The CLI wraps it as
`rag-canary rotation-status`, which exits 1 when a set is overdue so a
scheduled CI job can fail loudly, the same way a tripped scan does.

Honest limits, stated plainly: this is a clock check, not a daemon.
Nothing here runs in the background, sends reminders, or rotates a set
on its own. You still need a scheduler (cron, a CI schedule, a calendar)
to call the check, and a person or a script to run `rotate` and replant
when it fires. Timestamps are taken at face value; a set built with
backdated or future stamps will get the schedule those stamps imply.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .canary import Canary

DEFAULT_INTERVAL_DAYS = 30
DEFAULT_WARNING_DAYS = 7


def _parse_timestamp(value: str, canary_id: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"canary {canary_id!r} has an unreadable created_at: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_now(value: str | None) -> datetime:
    """Parse an ISO-8601 `now` override, or return the current UTC time."""
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class RotationStatus:
    """Where a canary set sits against its rotation schedule."""

    canary_count: int
    oldest_created_at: str
    due_at: str
    interval_days: int
    warning_days: int
    days_until_due: int
    state: str

    @property
    def should_rotate(self) -> bool:
        """True only when the set is overdue. Due soon is a warning."""
        return self.state == "overdue"

    def to_dict(self) -> dict:
        return {
            "canary_count": self.canary_count,
            "oldest_created_at": self.oldest_created_at,
            "due_at": self.due_at,
            "interval_days": self.interval_days,
            "warning_days": self.warning_days,
            "days_until_due": self.days_until_due,
            "state": self.state,
            "should_rotate": self.should_rotate,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def summary(self) -> str:
        lines = [
            f"rotation: {self.canary_count} canaries, oldest created {self.oldest_created_at}",
            f"schedule: every {self.interval_days} days, warning {self.warning_days} days ahead",
            f"next rotation due: {self.due_at}",
        ]
        if self.state == "overdue":
            lines.append(f"state: OVERDUE by {-self.days_until_due} day(s). Rotate now.")
        elif self.state == "due_soon":
            lines.append(f"state: due soon, {self.days_until_due} day(s) left.")
        else:
            lines.append(f"state: current, {self.days_until_due} day(s) left.")
        return "\n".join(lines)


def rotation_status(
    canaries: list[Canary],
    interval_days: int = DEFAULT_INTERVAL_DAYS,
    warning_days: int = DEFAULT_WARNING_DAYS,
    now: datetime | None = None,
) -> RotationStatus:
    """Report the rotation state of a canary set.

    The anchor is the oldest `created_at` in the set. The due date is
    the anchor plus `interval_days`. `now` defaults to the current UTC
    time; pass it in tests or for reproducible reports.
    """
    if not canaries:
        raise ValueError("rotation status needs at least one canary")
    if interval_days < 1:
        raise ValueError("interval_days must be at least 1")
    if warning_days < 0 or warning_days >= interval_days:
        raise ValueError("warning_days must be at least 0 and below interval_days")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    stamps = [_parse_timestamp(c.created_at, c.id) for c in canaries]
    oldest = min(stamps)
    due = oldest + timedelta(days=interval_days)
    seconds_left = (due - moment).total_seconds()
    if seconds_left >= 0:
        days_until_due = math.floor(seconds_left / 86400)
    else:
        days_until_due = -math.ceil(-seconds_left / 86400)
    if moment >= due:
        state = "overdue"
    elif due - moment <= timedelta(days=warning_days):
        state = "due_soon"
    else:
        state = "current"
    return RotationStatus(
        canary_count=len(canaries),
        oldest_created_at=oldest.isoformat(),
        due_at=due.isoformat(),
        interval_days=interval_days,
        warning_days=warning_days,
        days_until_due=days_until_due,
        state=state,
    )
