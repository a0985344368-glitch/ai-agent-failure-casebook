"""Small, standalone ISO-8601 timestamp parser."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone


ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ]"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?"
    r"(Z|[+-]\d{2}:\d{2})?$"
)


def parse_iso8601_to_epoch(value: object) -> float | None:
    """Return UTC POSIX seconds, or ``None`` for any invalid input.

    A missing timezone is interpreted as UTC. Numeric offsets are validated
    before ``timedelta`` construction: hours must be 00..23 and minutes must
    be 00..59. Fractional seconds are truncated to microsecond precision.
    """
    if not isinstance(value, str):
        return None

    match = ISO_RE.fullmatch(value.strip())
    if match is None:
        return None

    (
        year_text,
        month_text,
        day_text,
        hour_text,
        minute_text,
        second_text,
        fraction_text,
        offset_text,
    ) = match.groups()

    try:
        if offset_text is None or offset_text == "Z":
            tzinfo = timezone.utc
        else:
            offset_hours = int(offset_text[1:3])
            offset_minutes = int(offset_text[4:6])
            if not 0 <= offset_hours <= 23:
                return None
            if not 0 <= offset_minutes <= 59:
                return None
            sign = 1 if offset_text[0] == "+" else -1
            offset = timedelta(
                hours=sign * offset_hours,
                minutes=sign * offset_minutes,
            )
            tzinfo = timezone(offset)

        microsecond = (
            int(fraction_text[:6].ljust(6, "0")) if fraction_text else 0
        )
        parsed = datetime(
            int(year_text),
            int(month_text),
            int(day_text),
            int(hour_text),
            int(minute_text),
            int(second_text),
            microsecond,
            tzinfo=tzinfo,
        )
    except (OverflowError, ValueError):
        return None

    try:
        return parsed.timestamp()
    except (OSError, OverflowError, ValueError):
        return None
