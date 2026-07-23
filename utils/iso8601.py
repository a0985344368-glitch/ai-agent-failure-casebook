"""
ISO-8601 timestamp parser utility.
Provides `parse_iso8601_to_epoch(ts)`.
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional

# Match: YYYY-MM-DD[T ]HH:MM:SS followed optionally by .ffffff and Z or [+-]HH:MM offset
ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)

def parse_iso8601_to_epoch(ts) -> Optional[float]:
    """
    Parses an ISO-8601 timestamp string and returns POSIX epoch seconds in UTC,
    or None when the value cannot be parsed or is invalid.
    """
    if not isinstance(ts, str):
        return None

    s = ts.strip()
    match = ISO_RE.match(s)
    if not match:
        return None

    try:
        year_str, month_str, day_str, hour_str, minute_str, second_str, us_str, offset_str = match.groups()

        year = int(year_str)
        month = int(month_str)
        day = int(day_str)
        hour = int(hour_str)
        minute = int(minute_str)
        second = int(second_str)

        if us_str:
            # Handle microsecond padding or truncation (to standard 6 digits)
            us = int(us_str[:6].ljust(6, '0'))
        else:
            us = 0

        if offset_str is None:
            # Naive timestamp with no offset must be interpreted as UTC
            tz = timezone.utc
        elif offset_str == 'Z':
            tz = timezone.utc
        else:
            # Offset is in the form [+-]HH:MM
            sign = 1 if offset_str[0] == '+' else -1
            hours = int(offset_str[1:3])
            minutes = int(offset_str[4:6])
            tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))

        dt = datetime(year, month, day, hour, minute, second, us, tzinfo=tz)
        return dt.timestamp()
    except Exception:
        return None
