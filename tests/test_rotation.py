"""Tests for rotation scheduling (v0.3.0)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from rag_canary import generate_canaries, rotation_status
from rag_canary.cli import main

BASE = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _set_at(moment, n=3, seed=5):
    canaries = generate_canaries(n, seed=seed)
    for c in canaries:
        c.created_at = moment.isoformat()
    return canaries


def test_fresh_set_is_current():
    status = rotation_status(_set_at(BASE), now=BASE + timedelta(days=2))
    assert status.state == "current"
    assert status.should_rotate is False
    assert status.days_until_due == 28
    assert status.canary_count == 3


def test_anchor_is_oldest_canary():
    canaries = _set_at(BASE + timedelta(days=10))
    canaries[0].created_at = BASE.isoformat()
    status = rotation_status(canaries, now=BASE + timedelta(days=29))
    assert status.oldest_created_at == BASE.isoformat()
    assert status.state == "due_soon"


def test_due_soon_inside_warning_window():
    status = rotation_status(
        _set_at(BASE), interval_days=30, warning_days=7, now=BASE + timedelta(days=25)
    )
    assert status.state == "due_soon"
    assert status.should_rotate is False
    assert status.days_until_due == 5


def test_overdue_at_and_past_due_date():
    at_due = rotation_status(_set_at(BASE), now=BASE + timedelta(days=30))
    assert at_due.state == "overdue"
    assert at_due.should_rotate is True
    past = rotation_status(_set_at(BASE), now=BASE + timedelta(days=33))
    assert past.state == "overdue"
    assert past.days_until_due == -3


def test_due_at_is_anchor_plus_interval():
    status = rotation_status(_set_at(BASE), interval_days=14, now=BASE)
    assert status.due_at == (BASE + timedelta(days=14)).isoformat()


def test_empty_set_raises():
    with pytest.raises(ValueError, match="at least one"):
        rotation_status([], now=BASE)


def test_bad_interval_raises():
    with pytest.raises(ValueError, match="interval_days"):
        rotation_status(_set_at(BASE), interval_days=0, now=BASE)


def test_bad_warning_window_raises():
    with pytest.raises(ValueError, match="warning_days"):
        rotation_status(_set_at(BASE), interval_days=30, warning_days=30, now=BASE)


def test_unreadable_created_at_raises():
    canaries = _set_at(BASE)
    canaries[1].created_at = "not a date"
    with pytest.raises(ValueError, match="unreadable created_at"):
        rotation_status(canaries, now=BASE)


def test_status_json_round_trip():
    status = rotation_status(_set_at(BASE), now=BASE + timedelta(days=1))
    payload = json.loads(status.to_json())
    assert payload["state"] == "current"
    assert payload["should_rotate"] is False
    assert payload["interval_days"] == 30


def _write_set(tmp_path, moment, seed=5):
    path = tmp_path / "canaries.json"
    canaries = _set_at(moment, seed=seed)
    path.write_text(json.dumps([c.to_dict() for c in canaries]) + "\n", encoding="utf-8")
    return path


def test_cli_rotation_status_current_exit_0(tmp_path, capsys):
    path = _write_set(tmp_path, BASE)
    rc = main(
        [
            "rotation-status",
            "--canaries",
            str(path),
            "--now",
            (BASE + timedelta(days=3)).isoformat(),
        ]
    )
    assert rc == 0
    assert "current" in capsys.readouterr().out


def test_cli_rotation_status_overdue_exit_1(tmp_path, capsys):
    path = _write_set(tmp_path, BASE)
    rc = main(
        [
            "rotation-status",
            "--canaries",
            str(path),
            "--now",
            (BASE + timedelta(days=40)).isoformat(),
            "--format",
            "json",
        ]
    )
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "overdue"
    assert payload["should_rotate"] is True


def test_cli_rotation_status_missing_file_exit_2(tmp_path):
    rc = main(["rotation-status", "--canaries", str(tmp_path / "nope.json")])
    assert rc == 2
