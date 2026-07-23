import pytest
from utils.iso8601 import parse_iso8601_to_epoch

def test_accepted_formats():
    # 1. "2026-07-23T10:21:30" (naive -> UTC)
    t1 = parse_iso8601_to_epoch("2026-07-23T10:21:30")
    assert t1 == 1784802090.0

    # 2. "2026-07-23T10:21:30Z"
    t2 = parse_iso8601_to_epoch("2026-07-23T10:21:30Z")
    assert t2 == 1784802090.0

    # 3. "2026-07-23T10:21:30.123456"
    t3 = parse_iso8601_to_epoch("2026-07-23T10:21:30.123456")
    assert t3 == 1784802090.123456

    # 4. "2026-07-23T10:21:30.123456+00:00"
    t4 = parse_iso8601_to_epoch("2026-07-23T10:21:30.123456+00:00")
    assert t4 == 1784802090.123456

    # 5. "2026-07-23T10:21:30+08:00"
    # Offset +08:00 is 8 hours ahead, so UTC is 02:21:30
    t5 = parse_iso8601_to_epoch("2026-07-23T10:21:30+08:00")
    assert t5 == 1784802090.0 - 8 * 3600

    # 6. "2026-07-23 10:21:30"
    t6 = parse_iso8601_to_epoch("2026-07-23 10:21:30")
    assert t6 == 1784802090.0

    # 7. Surrounding whitespace with all forms
    assert parse_iso8601_to_epoch("   2026-07-23T10:21:30   ") == 1784802090.0
    assert parse_iso8601_to_epoch("\n 2026-07-23T10:21:30Z\t") == 1784802090.0
    assert parse_iso8601_to_epoch(" 2026-07-23T10:21:30.123456 ") == 1784802090.123456
    assert parse_iso8601_to_epoch("\r\n2026-07-23T10:21:30.123456+00:00 ") == 1784802090.123456
    assert parse_iso8601_to_epoch(" 2026-07-23T10:21:30+08:00 \n") == 1784802090.0 - 8 * 3600
    assert parse_iso8601_to_epoch("  2026-07-23 10:21:30  ") == 1784802090.0


def test_garbage_inputs():
    # ""
    assert parse_iso8601_to_epoch("") is None
    # None
    assert parse_iso8601_to_epoch(None) is None
    # "not-a-date"
    assert parse_iso8601_to_epoch("not-a-date") is None
    # 12345
    assert parse_iso8601_to_epoch(12345) is None
    # other garbage
    assert parse_iso8601_to_epoch("2026-07-23") is None  # missing time
    assert parse_iso8601_to_epoch("2026-02-30T10:21:30") is None  # invalid day (Feb 30)
    assert parse_iso8601_to_epoch("2026-07-23T25:21:30") is None  # invalid hour (25)
    assert parse_iso8601_to_epoch("2026-07-23T10:61:30") is None  # invalid minute (61)
    assert parse_iso8601_to_epoch("2026-07-23T10:21:30+25:00") is None  # invalid offset hour


def test_behavioral_offset_aware_vs_naive_utc():
    # An offset-aware timestamp and the equivalent naive-UTC timestamp must produce the identical epoch value.
    t_aware = parse_iso8601_to_epoch("2026-07-23T10:21:30+00:00")
    t_naive = parse_iso8601_to_epoch("2026-07-23T10:21:30")
    assert t_aware == t_naive
    assert t_aware == 1784802090.0


def test_behavioral_microsecond_precision():
    # Microsecond precision must be preserved in the returned float.
    t_ms = parse_iso8601_to_epoch("2026-07-23T10:21:30.123456")
    # Expected: 1784802090.123456
    # Floating-point representation might have small imprecision, but the exact microsecond
    # must be preserved in terms of the closest float representation.
    assert t_ms == 1784802090.123456

    # Sub-microsecond (e.g. nanoseconds or extra digits) should be parsed cleanly without crashing
    t_sub_ms = parse_iso8601_to_epoch("2026-07-23T10:21:30.123456789")
    assert t_sub_ms == 1784802090.123456

    # Shorter digits should be padded correctly with zeros
    t_short = parse_iso8601_to_epoch("2026-07-23T10:21:30.12")
    assert t_short == 1784802090.120000
