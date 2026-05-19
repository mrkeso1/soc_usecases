"""Lifecycle review period helpers."""

import calendar
from datetime import date, timedelta

# Current business cadence: three checkpoints per year.
LIFECYCLE_CHECKPOINTS = [(4, 30), (8, 31), (12, 31)]


def _safe_checkpoint_date(year: int, month: int, day: int) -> date:
    """Return a valid date clamping ``day`` to the last day of the month.

    Prevents ValueError for checkpoints like Feb 29 in non-leap years.
    """
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(day, last_day))


def current_lifecycle_window(today: date):
    """Return the active lifecycle review window for a given date."""
    checkpoints = [_safe_checkpoint_date(today.year, month, day) for month, day in LIFECYCLE_CHECKPOINTS]
    for index, checkpoint in enumerate(checkpoints):
        if today <= checkpoint:
            start = date(today.year, 1, 1) if index == 0 else checkpoints[index - 1] + timedelta(days=1)
            return start, checkpoint
    start = checkpoints[-1] + timedelta(days=1)
    end = _safe_checkpoint_date(today.year + 1, *LIFECYCLE_CHECKPOINTS[0])
    return start, end
