"""Lifecycle review period helpers."""

from datetime import date, timedelta

# Current business cadence: three checkpoints per year.
LIFECYCLE_CHECKPOINTS = [(4, 30), (8, 31), (12, 31)]


def current_lifecycle_window(today: date):
    """Return the active lifecycle review window for a given date."""
    checkpoints = [date(today.year, month, day) for month, day in LIFECYCLE_CHECKPOINTS]
    for index, checkpoint in enumerate(checkpoints):
        if today <= checkpoint:
            start = date(today.year, 1, 1) if index == 0 else checkpoints[index - 1] + timedelta(days=1)
            return start, checkpoint
    start = checkpoints[-1] + timedelta(days=1)
    end = date(today.year + 1, 4, 30)
    return start, end
