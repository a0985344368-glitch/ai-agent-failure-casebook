from datetime import datetime, timedelta, timezone

import pytest

from utils.iso8601 import parse_iso8601_to_epoch


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-07-23T10:21:30", 1784802090.0),
        ("2026-07-23T10:21:30Z", 1784802090.0),
        ("2026-07-23T10:21:30.123456", 1784802090.123456),
        ("2026-07-23T10:21:30.123456+00:00", 1784802090.123456),
        ("2026-07-23T10:21:30+08:00", 1784802090.0 - 8 * 3600),
        ("2026-07-23 10:21:30", 1784802090.0),
        ("   2026-07-23T10:21:30   ", 1784802090.0),
        ("\n 2026-07-23T10:21:30Z\t", 1784802090.0),
        (" 2026-07-23T10:21:30.12 ", 1784802090.12),
        ("2026-07-23T10:21:30.123456789", 1784802090.123456),
    ],
)
def test_existing_accepted_formats(value, expected):
    assert parse_iso8601_to_epoch(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "not-a-date",
        12345,
        "2026-07-23",
        "2026-02-30T10:21:30",
        "2026-07-23T25:21:30",
        "2026-07-23T10:61:30",
        "2026-07-23T10:21:30+25:00",
    ],
)
def test_existing_invalid_inputs(value):
    assert parse_iso8601_to_epoch(value) is None


def test_offset_positive_00_60_is_rejected_before_normalization():
    assert parse_iso8601_to_epoch("2026-07-23T10:21:30+00:60") is None


def test_offset_negative_00_60_is_rejected_before_normalization():
    assert parse_iso8601_to_epoch("2026-07-23T10:21:30-00:60") is None


def test_offset_positive_23_59_is_accepted():
    value = "2026-07-23T10:21:30+23:59"
    expected = datetime(
        2026,
        7,
        23,
        10,
        21,
        30,
        tzinfo=timezone(timedelta(hours=23, minutes=59)),
    ).timestamp()

    assert parse_iso8601_to_epoch(value) == expected


def test_offset_positive_24_00_is_rejected():
    assert parse_iso8601_to_epoch("2026-07-23T10:21:30+24:00") is None


def test_offset_aware_and_naive_utc_are_equivalent():
    aware = parse_iso8601_to_epoch("2026-07-23T10:21:30+00:00")
    naive = parse_iso8601_to_epoch("2026-07-23T10:21:30")

    assert aware == naive == 1784802090.0

